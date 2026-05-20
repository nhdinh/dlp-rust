# Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine - Research

**Researched:** 2026-05-20
**Domain:** Windows shared-memory IPC, lock-free cache design, FNV-1a hashing, longest-prefix matching, state machines in Rust DLLs, Windows named-pipe failure modes
**Confidence:** HIGH (existing codebase provides solid foundation; Windows APIs well-documented; design decisions locked in CONTEXT.md)

## Summary

Phase 50 gives the hook DLL a survivable sub-50us hot path and a tier-gated asymmetric fail policy. The core challenge is building a lock-free, double-buffered shared-memory classification cache that the agent owns (read-write) and every hooked process maps read-only, combined with a deterministic fail-mode state machine that gracefully degrades from HEALTHY through DEGRADED and ISOLATED to RESYNC.

The existing codebase provides excellent foundation: the `dlp-hook-dll` crate already has 12 trampolines with `catch_unwind` + SEH hardening, a thread-local 4KiB pipe buffer, `fail_closed!` macro for three return-value families, and `HookDescriptor` metadata table. The `dlp-agent` has `HookIpcServer` with bincode framing, `AllowlistMatcher` with signer caching, and a `Cache` module with FNV-1a hashing and TTL eviction. The `dlp-common` crate has `Classification` enum with `is_sensitive()` and `Decision` enum with `is_denied()`.

**Primary recommendation:** Build incrementally -- (1) shared-memory layout + agent writer, (2) DLL reader + cache lookup integration into trampolines, (3) fail-mode state machine, (4) background thread for ISOLATED-state RESYNC detection, (5) allowlist + performance telemetry. Each layer is independently testable.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Shared-memory cache creation | API / Backend (agent) | -- | Agent runs as SYSTEM, owns the `Global\` namespace mapping |
| Shared-memory cache read | Browser / Client (hook DLL) | -- | DLL maps read-only; no synchronization needed |
| Cache content population | API / Backend (agent) | -- | Agent rebuilds from policy_store + server deltas |
| Cache lookup (per-file) | Browser / Client (hook DLL) | -- | Must complete in <50us without crossing process boundary |
| Fail-mode state machine | Browser / Client (hook DLL) | -- | DLL makes autonomous decisions when pipe is unreachable |
| Pipe failure detection | Browser / Client (hook DLL) | API / Backend | DLL detects; agent may push recovery signals |
| RESYNC background thread | Browser / Client (hook DLL) | -- | DLL-owned thread polls atomic version in ISOLATED state |
| Performance telemetry | Browser / Client (hook DLL) | API / Backend | DLL measures QPC; agent aggregates |
| Allowlist checking | Browser / Client (hook DLL) | -- | Hardcoded + shared-memory operator extensions |

## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Two-tier structure: root-prefix table (first tier) + per-file hash table (second tier). Root-prefix for directory-level classification; per-file for explicit overrides.
- **D-02:** Root-prefix matching uses longest-prefix wins. Prefixes sorted by length (longest first).
- **D-03:** Per-file hash table uses FNV-1a 64-bit with open addressing and 8-byte hash verification.
- **D-04:** Double-buffered version flip uses atomic u64: high 63 bits = monotonic version, low bit = active buffer (0 or 1).
- **D-05:** HEALTHY -> DEGRADED: 3 consecutive named-pipe round-trip failures (ConnectionRefused, Timeout, or Malformed).
- **D-06:** DEGRADED -> ISOLATED: 10 consecutive pipe failures OR cache version older than max tier TTL (T4=30s).
- **D-07:** ISOLATED -> RESYNC: successful pipe round-trip AND cache version in shared memory > DLL last seen.
- **D-08:** DEGRADED uses cache + retries pipe every 10th call. ISOLATED uses cache-only, no pipe attempts.
- **D-09:** Hybrid allowlist: hardcoded common paths in DLL static arrays; operator extensions in separate 64 KiB shared-memory region.
- **D-10:** Operator-extended allowlist in dedicated 64 KiB shared-memory region as flat array of path prefixes.
- **D-11:** Cache warmup: agent pre-populates T3/T4 Protected Path roots at startup; everything else lazy on first pipe request.
- **D-12:** TTL enforcement: DLL checks entry's `ttl_bits` against `cache_version_seen_at` on every lookup.
- **D-13:** RESYNC detection (HEALTHY/DEGRADED): agent sends `HookMessage::CacheDelta` through pipe.
- **D-14:** ISOLATED-state RESYNC: lightweight background thread polls atomic version every 100ms via `WaitForSingleObject`.
- **D-15:** In-flight decisions during RESYNC: allowed to complete using old cache; new decisions use new cache.
- **D-16:** CacheDelta push: agent only updates shared-memory version word (atomic flip); no pipe broadcast.

### Claude's Discretion
- FNV-1a 64-bit chosen over Wyhash for simplicity and proven correctness.
- Atomic u64 version word chosen for single-read simplicity and no torn-read risk.
- DEGRADED uses cache + periodic pipe retry (vs still using pipe primarily) to reduce load on struggling agent.
- Separate allowlist array for cleaner separation of concerns.
- DLL checks TTL on every lookup for correctness over micro-optimization.
- Background thread for ISOLATED-state detection (vs periodic pipe probe) to respect isolation semantics.
- Allow in-flight decisions during RESYNC for zero-latency-spike transitions.
- Shared memory atomic flip only for cache updates -- no pipe broadcast.

### Deferred Ideas (OUT OF SCOPE)
- ntdll syscall-stub patching (Phase 51 -- BLOCK-08, BLOCK-09)
- DACL tripwire (Phase 52 -- DACL-01..05)
- ETW bypass detection (Phase 53 -- ETW-01..05)
- Admin TUI screens (Phase 54 -- UX-01, UX-02)
- Monitor-only / audit-only per-policy mode (Phase 55 -- MODE-01)
- SD/optical/virtual drive enumeration (Phase 56 -- DRIVE-01..04)
- Deployment guide (Phase 57 -- OPS-01..04)

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CACHE-01 | Shared-memory `Global\DlpClassificationCache` (2 MiB, double-buffered, atomic version flip) created/owned by agent; populated from server-pushed `ClassificationDelta`s and policy_store changes | Windows `CreateFileMappingW` + `MapViewOfFile` APIs well-documented; double-buffer pattern from game engines; atomic u64 flip is standard lock-free technique |
| CACHE-02 | Hook DLL maps cache read-only via `OpenFileMappingW` at DllMain; thread-local LRU of last 128 path lookups | `OpenFileMappingW` with `FILE_MAP_READ` is standard; thread-local LRU avoids cross-thread synchronization |
| CACHE-03 | Extended `HookRequest`/`HookResponse` protocol: requests carry `pid`, `tid`, `file_object`, `journal_seq`, `op: HookOp`; responses carry `cache_hint: Option<(PathBuf, Tier, ttl_secs)>` and `cache_version` | Existing bincode framing supports additive fields; `dlp-common/src/hook_ipc.rs` is the extension point |
| CACHE-04 | Server pushes `HookMessage::CacheDelta { added, removed, version }` to agent on policy change; agent rebuilds shared mapping and atomically flips global version word | Agent's `policy_sync.rs` already polls for config changes; extend to trigger cache rebuild |
| CACHE-05 | In-DLL trusted-path allowlist (System32, WinSxS, WindowsApps, Program Files\Common Files) bypasses both cache lookup and pipe | Hardcoded static arrays in DLL; no IPC needed |
| CACHE-06 | Per-process host allowlist (devenv.exe, cargo.exe, msbuild.exe, rustc.exe, link.exe, gcc.exe) bypasses pipe entirely; operator-extendable | `GetModuleFileNameW(NULL)` for self-identification; shared-memory region for operator extensions |
| FAIL-01 | Hook DLL fail-mode state machine: HEALTHY -> DEGRADED (3 consecutive pipe failures) -> ISOLATED (10 consecutive failures OR cache stale) -> RESYNC (pipe recovered + new CacheDelta with greater version) | Deterministic counting with atomic counters; state transitions are idempotent |
| FAIL-02 | Asymmetric tier-gated fail semantics: T3/T4 fail-closed (`ERROR_ACCESS_DENIED`/`STATUS_ACCESS_DENIED`) when ISOLATED; T1/T2 fail-open. Cached classification authoritative for fail decisions; root-prefix table consulted on cache miss | `Classification::is_sensitive()` already distinguishes T3/T4; `fail_closed!` macro already generates correct returns |
| FAIL-03 | Per-tier staleness budgets: T4=30s, T3=60s, T2=5min, T1=30min; per-entry `ttl_bits` field in shared mapping; DLL stamps `cache_version_seen_at` on each successful round-trip | TTL bits stored per entry; comparison against cached `cache_version_seen_at` timestamp |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows` | 0.62.2 [VERIFIED: cargo registry] | Win32 API bindings (`CreateFileMappingW`, `OpenFileMappingW`, `MapViewOfFile`, `WaitForSingleObject`, `CreateThread`, `QueryPerformanceCounter`) | Official Microsoft crate; already in use across project |
| `bincode` | 1.3.3 [VERIFIED: cargo registry] | Length-prefixed IPC serialization | Already used in pipe_client.rs; zero-copy compatible |
| `serde` | workspace | Derive macros for `HookRequest`/`HookResponse` extensions | Project standard |
| `std::sync::atomic` | Rust 1.94.1 [VERIFIED: rustc --version] | AtomicU64 for version word, AtomicU32 for failure counters | Standard library; no external dep |
| `parking_lot` | 0.12.5 [VERIFIED: cargo registry] | RwLock for agent-side cache rebuild (not hot path) | Already used in `dlp-agent/src/cache.rs` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `crossbeam-channel` | 0.5 [VERIFIED: cargo registry] | Agent-side channel for cache delta notifications | Already in `dlp-agent/Cargo.toml` from Phase 49 |
| `dashmap` | 6 [VERIFIED: cargo registry] | Agent-side process registry (PID -> cache version tracking) | Already in `dlp-agent/Cargo.toml` from Phase 49 |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Manual FNV-1a | `fnv` crate | `fnv` is 1.0.7 and stable, but manual implementation is 5 lines and avoids a dependency. CONTEXT.md D-03 locks manual FNV-1a. |
| AtomicU64 version word | Separate AtomicU64 + AtomicBool | Single atomic read is faster and eliminates torn-read risk. CONTEXT.md D-04 locks combined word. |
| `CreateThread` from DllMain | `QueueUserWorkItem` | `CreateThread` is simpler for a single background thread; `QueueUserWorkItem` requires thread pool cleanup. Both are acceptable; CONTEXT.md prefers `CreateThread`. |
| `std::time::Instant` | `QueryPerformanceCounter` | `Instant` is portable and sufficient for TTL checks. `QueryPerformanceCounter` needed only for sub-microsecond latency telemetry (p95 measurement). |

**Installation:**
```bash
# No new crates needed -- all dependencies already in workspace.
# Hook DLL needs additional windows features:
#   "Win32_System_Performance"  # for QueryPerformanceCounter
#   "Win32_System_Memory"       # for CreateFileMappingW, MapViewOfFile (already enabled)
#   "Win32_System_Threading"    # for CreateThread, WaitForSingleObject
```

**Version verification:**
- `windows` crate: 0.62.2 (current in Cargo.lock)
- `bincode`: 1.3.3 (current in Cargo.lock)
- `parking_lot`: 0.12.5 (current in Cargo.lock)
- Rust: 1.94.1 (confirmed via `rustc --version`)

## Package Legitimacy Audit

> No new external packages are required for this phase. All dependencies are already in the workspace Cargo.lock and have been used in prior phases.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `windows` | crates.io | 4+ yrs | 50M+ | github.com/microsoft/windows-rs | N/A (already used) | Approved |
| `bincode` | crates.io | 10+ yrs | 100M+ | github.com/bincode-org/bincode | N/A (already used) | Approved |
| `parking_lot` | crates.io | 7+ yrs | 100M+ | github.com/Amanieu/parking_lot | N/A (already used) | Approved |
| `crossbeam-channel` | crates.io | 6+ yrs | 100M+ | github.com/crossbeam-rs/crossbeam | N/A (already used) | Approved |
| `dashmap` | crates.io | 5+ yrs | 50M+ | github.com/xacrimon/dashmap | N/A (already used) | Approved |

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
Agent Service (SYSTEM, session 0)
|
|-- ClassificationCache (owns shared memory)
|   |-- CreateFileMappingW("Global\DlpClassificationCache", 2 MiB, PAGE_READWRITE)
|   |-- Double-buffered layout: Buffer 0 + Buffer 1 + root-prefix table + allowlist array
|   |-- AtomicU64 version_word at offset 0: [63:1] = version, [0] = active buffer
|   |
|   |-- On policy change:
|   |   |-- Build new cache in inactive buffer
|   |   |-- MemoryBarrier() / atomic::fence(AcqRel)
|   |   |-- Atomic increment+flip of version_word
|   |
|   |-- On agent startup:
|   |   |-- Pre-populate T3/T4 Protected Path roots
|   |   |-- Set initial version = 1
|
|-- HookIpcServer (existing)
|   |-- Handle HookRequest with cache_version field
|   |-- Return HookResponse with cache_hint + cache_version
|   |-- Push HookMessage::CacheDelta on classification change
|
|-- classification_pusher.rs (NEW)
|   |-- Subscribe to policy_store changes
|   |-- Rebuild shared-memory cache
|   |-- Atomic version flip

Named Pipe (\\.\pipe\DlpHookPipe)
|
v
Hook DLL (injected into every user process)
|
|-- DllMain(DLL_PROCESS_ATTACH)
|   |-- self-allowlist check (existing)
|   |-- OpenFileMappingW("Global\DlpClassificationCache", FILE_MAP_READ)
|   |-- MapViewOfFile -> *const CacheHeader (read-only)
|   |-- Spawn background thread (ISOLATED-state RESYNC detection)
|
|-- File I/O Call (e.g., WriteFile)
|   |-- SEH __try/__except (existing)
|   |   |-- catch_unwind (existing)
|   |       |-- allowlist_check(path) -> ALLOW immediately if trusted
|   |       |-- cache_lookup(path)
|   |       |   |-- Read atomic version_word (single u64 load)
|   |       |   |-- Extract buffer_index = version_word & 1
|   |       |   |-- Extract version = version_word >> 1
|   |       |   |-- Root-prefix table: longest-prefix match
|   |       |   |-- Per-file hash table: FNV-1a + open addressing
|   |       |   |-- Check TTL: entry.ttl_bits vs cache_version_seen_at
|   |       |   |-- Return Classification (or None on miss/expired)
|   |       |
|   |       |-- If cache hit:
|   |       |   |-- T3/T4 + write op -> DENY (skip pipe in HEALTHY/DEGRADED)
|   |       |   |-- T1/T2 -> ALLOW (skip pipe)
|   |       |
|   |       |-- If cache miss OR expired:
|   |       |   |-- pipe_client::send_request (existing)
|   |       |   |-- On success: store cache_hint in thread-local LRU
|   |       |   |-- On failure: increment fail counter, state machine transition
|   |       |   |-- Re-decide based on fail-mode state
|   |       |
|   |       |-- fail-mode state machine:
|   |           |-- HEALTHY: pipe on miss; cache hit skips pipe
|   |           |-- DEGRADED: cache-only; retry pipe every 10th call
|   |           |-- ISOLATED: cache-only; no pipe attempts
|   |           |-- RESYNC: flush LRU, reset counters, -> HEALTHY
|   |
|   |-- Background thread (ISOLATED state only)
|   |   |-- WaitForSingleObject(event, 100ms)
|   |   |-- Read atomic version_word
|   |   |-- If version > last_seen: signal RESYNC
|   |
|   |-- Performance telemetry
|       |-- QueryPerformanceCounter before/after cache lookup
|       |-- Track p50/p95/p99 latency in thread-local histogram
|       |-- Emit aggregated telemetry every 1000 calls via pipe
```

### Recommended Project Structure

```
dlp-hook-dll/src/
├── lib.rs                    # Extend DllMain with shared-memory mapping
├── pipe_client.rs            # Reuse existing; add fail-mode bypass
├── trampolines.rs            # Add cache_lookup before classify_path/classify_handle
├── crash_guard.rs            # Reuse existing
├── fail_closed.rs            # Reuse existing
├── pe_utils.rs               # Reuse existing
├── classification_cache.rs   # NEW: shared-memory reader, cache lookup, LRU
├── fail_mode.rs              # NEW: state machine, counters, transitions
├── allowlist.rs              # NEW: hardcoded + shared-memory allowlist check
├── perf_telemetry.rs         # NEW: QPC measurement, histogram, aggregation
└── background_thread.rs      # NEW: ISOLATED-state RESYNC detection thread

dlp-agent/src/
├── service.rs                # Add ClassificationCache initialization
├── hook_ipc.rs               # Extend HookRequest/HookResponse
├── classification_cache.rs   # NEW: shared-memory writer, cache builder, version flip
│   └── (agent-side cache owner)
├── cache_pusher.rs           # NEW: policy_store subscriber, delta builder
└── lib.rs                    # Add new modules

dlp-common/src/
├── hook_ipc.rs               # Extend with cache_version, cache_hint, HookOp
├── classification.rs         # Reuse existing Classification enum
└── lib.rs                    # Export new types
```

### Pattern 1: Double-Buffered Atomic Version Flip
**What:** Agent writes to inactive buffer, then atomically flips a version word so all DLLs see the new buffer simultaneously. No locks, no blocking readers.
**When to use:** Any multi-reader/single-writer shared memory where readers must never see torn writes.
**Example:**
```rust
// Source: CONTEXT.md D-04 + lock-free data structure patterns
use std::sync::atomic::{AtomicU64, Ordering};

/// Layout at offset 0 of shared memory.
#[repr(C)]
struct CacheHeader {
    /// High 63 bits = monotonic version number; low bit = active buffer (0 or 1).
    version_word: AtomicU64,
    // ... rest of header
}

/// Agent side: flip to new buffer after writing.
fn publish_new_cache(header: &CacheHeader, new_version: u64, new_buffer: u8) {
    // new_buffer must be 0 or 1.
    let new_word = (new_version << 1) | u64::from(new_buffer);
    // Memory fence ensures all writes to the inactive buffer are visible
    // before the version word update.
    std::sync::atomic::fence(Ordering::Release);
    header.version_word.store(new_word, Ordering::Release);
}

/// DLL side: single atomic read gets both version and buffer index.
fn read_version(header: &CacheHeader) -> (u64, u8) {
    let word = header.version_word.load(Ordering::Acquire);
    let version = word >> 1;
    let buffer = (word & 1) as u8;
    (version, buffer)
}
```

### Pattern 2: FNV-1a 64-bit with Open Addressing
**What:** Fast, simple hash function with collision resolution via linear probing. 8-byte hash stored per entry for verification.
**When to use:** Fixed-size hash tables where simplicity and speed matter more than perfect distribution.
**Example:**
```rust
// Source: dlp-agent/src/cache.rs (existing FNV-1a implementation) + CONTEXT.md D-03
/// FNV-1a 64-bit hash.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[repr(C)]
struct HashEntry {
    hash: u64,      // FNV-1a hash of the path
    tier: u8,       // Classification tier (1-4)
    ttl_bits: u16,  // TTL in seconds (encoded)
    _pad: u8,       // Padding to 16 bytes
}

const HASH_TABLE_SLOTS: usize = 14_336; // ~14K slots per 900 KiB buffer
const EMPTY_HASH: u64 = 0;

/// Lookup with open addressing (linear probing).
/// Returns the tier if found, None if not present or expired.
unsafe fn hash_lookup(table: *const HashEntry, path: &str, now_secs: u32) -> Option<u8> {
    let hash = fnv1a_64(path.as_bytes());
    let mut idx = (hash as usize) % HASH_TABLE_SLOTS;
    for _ in 0..HASH_TABLE_SLOTS {
        let entry = table.add(idx);
        if (*entry).hash == EMPTY_HASH {
            return None; // Empty slot = not found
        }
        if (*entry).hash == hash {
            // Verify TTL before returning
            let ttl_secs = u32::from((*entry).ttl_bits);
            if now_secs.saturating_sub(CACHE_VERSION_SEEN_AT) < ttl_secs {
                return Some((*entry).tier);
            }
            return None; // Expired
        }
        idx = (idx + 1) % HASH_TABLE_SLOTS;
    }
    None // Table full, not found
}
```

### Pattern 3: Longest-Prefix Matching
**What:** Sort prefixes by length descending; on lookup, try longest to shortest. First match wins.
**When to use:** Directory hierarchy classification where parent directories have broader policies than children.
**Example:**
```rust
// Source: CONTEXT.md D-02 + standard routing table pattern
#[repr(C)]
struct PrefixEntry {
    prefix_len: u16,           // Length of prefix in bytes
    prefix: [u8; 260],         // UTF-8 path prefix (MAX_PATH)
    tier: u8,
    ttl_secs: u16,
}

/// Prefixes must be sorted by prefix_len descending before writing to shared memory.
unsafe fn longest_prefix_match(
    table: *const PrefixEntry,
    count: usize,
    path: &str,
    now_secs: u32,
) -> Option<u8> {
    let path_bytes = path.as_bytes();
    for i in 0..count {
        let entry = table.add(i);
        let len = (*entry).prefix_len as usize;
        if len == 0 {
            break;
        }
        // Check prefix match (case-insensitive on Windows)
        if path_bytes.len() >= len
            && path_bytes[..len].eq_ignore_ascii_case(&(*entry).prefix[..len])
        {
            let ttl = u32::from((*entry).ttl_secs);
            if now_secs.saturating_sub(CACHE_VERSION_SEEN_AT) < ttl {
                return Some((*entry).tier);
            }
            // Expired prefix entry: continue to shorter prefixes
        }
    }
    None
}
```

### Pattern 4: Fail-Mode State Machine in Rust
**What:** Atomic counters track consecutive failures; state transitions are deterministic and idempotent.
**When to use:** Any system that must degrade gracefully when a dependency becomes unreachable.
**Example:**
```rust
// Source: CONTEXT.md D-05..D-08
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FailState {
    Healthy = 0,
    Degraded = 1,
    Isolated = 2,
    Resync = 3,
}

struct FailModeState {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    cache_version_seen_at: AtomicU32, // timestamp when cache was last valid
}

impl FailModeState {
    fn record_pipe_success(&self, cache_version: u64) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        // If we were ISOLATED and now have a successful pipe with fresh cache, transition.
        let current = self.state.load(Ordering::Relaxed);
        if current == FailState::Isolated as u8 || current == FailState::Resync as u8 {
            // Verify cache version is newer than what we last saw
            // ...transition logic...
            self.state.store(FailState::Healthy as u8, Ordering::Relaxed);
        }
    }

    fn record_pipe_failure(&self) -> FailState {
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        let current = self.state.load(Ordering::Relaxed);

        match current {
            x if x == FailState::Healthy as u8 && fails >= 3 => {
                self.state.store(FailState::Degraded as u8, Ordering::Relaxed);
                FailState::Degraded
            }
            x if x == FailState::Degraded as u8 && fails >= 10 => {
                self.state.store(FailState::Isolated as u8, Ordering::Relaxed);
                FailState::Isolated
            }
            _ => unsafe { std::mem::transmute(current) },
        }
    }
}
```

### Pattern 5: Background Thread from DLL
**What:** Spawn a thread on `DLL_PROCESS_ATTACH` that polls the atomic version word every 100ms when in ISOLATED state.
**When to use:** Non-blocking detection of shared-memory changes without busy-waiting.
**Example:**
```rust
// Source: CONTEXT.md D-14 + Windows threading patterns
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
use windows::Win32::Foundation::HANDLE;

struct BackgroundThread {
    shutdown_event: HANDLE,
    last_seen_version: AtomicU64,
}

impl BackgroundThread {
    /// Called from DllMain (after loader lock is released, or via CreateThread).
    unsafe fn spawn(shutdown_event: HANDLE, cache_header: *const CacheHeader) {
        // IMPORTANT: Do NOT call CreateThread from inside DllMain directly.
        // The current code spawns from a separate initialization routine
        // that runs after DllMain returns.
        std::thread::spawn(move || {
            loop {
                // Wait 100ms or until shutdown signal
                let wait = WaitForSingleObject(shutdown_event, 100);
                if wait == 0 {
                    // Shutdown signaled
                    break;
                }

                // Only poll when in ISOLATED state
                if get_fail_state() == FailState::Isolated {
                    let word = (*cache_header).version_word.load(Ordering::Acquire);
                    let version = word >> 1;
                    if version > LAST_SEEN_VERSION.load(Ordering::Relaxed) {
                        // Signal RESYNC transition
                        trigger_resync(version);
                    }
                }
            }
        });
    }
}
```

### Anti-Patterns to Avoid
- **Calling `CreateThread` from `DllMain`:** The loader lock is held during `DLL_PROCESS_ATTACH`; creating a thread can deadlock. Defer thread creation to a post-attach work item or use `QueueUserWorkItem`.
- **Using `std::time::Instant` for cross-process timestamps:** `Instant` is not comparable across processes. Use `QueryPerformanceCounter` (QPC) for cross-process time comparisons, or store wall-clock seconds for TTL checks.
- **Writing to shared memory from the DLL:** The DLL must map the cache `FILE_MAP_READ` only. Any write would be a security vulnerability (any hooked process could modify classifications).
- **Forgetting `MemoryBarrier()` before atomic flip:** Without a release fence, the CPU may reorder writes to the inactive buffer after the version word update, causing readers to see partially-written data.
- **Using `Ordering::Relaxed` for version word reads:** Readers need `Ordering::Acquire` to ensure they see all writes to the buffer before the version word update.
- **Not handling 32-bit/64-bit pointer size differences:** The shared-memory layout must use fixed-size types (`u64` for pointers/handles, not `usize`) so a 32-bit DLL can read a cache written by a 64-bit agent.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Cross-process shared memory on Windows | Custom IPC protocol | `CreateFileMappingW` + `MapViewOfFile` | Standard Windows API; handles all security, session, and lifecycle concerns |
| Hash function for cache keys | Custom hash | FNV-1a 64-bit (5 lines) | Well-understood, fast, good distribution for short strings like paths |
| State machine framework | `machine` crate or complex enum | Simple atomic u8 + match | Only 4 states; a framework adds complexity without benefit |
| Background thread scheduling | Custom timer queue | `WaitForSingleObject(event, 100)` | Standard Windows primitive; no extra dependencies |
| Latency histogram | Custom histogram | Simple array of buckets (10us, 50us, 100us, 500us, 1ms, 5ms, 10ms) | Only need p95 for cache hit; simple array is sufficient |

**Key insight:** The shared-memory cache is intentionally simple -- no `dashmap`, no `moka`, no complex data structures. The agent rebuilds the entire cache on policy change (rare event), and the DLL does a single atomic read to get the version. This eliminates all cross-process synchronization complexity.

## Runtime State Inventory

> This phase involves shared-memory naming and process-level state. After every file in the repo is updated, the following runtime systems still carry the old string or state:

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None -- shared memory is ephemeral (created on agent startup, destroyed on shutdown). No persistent datastore stores the cache. | N/A |
| Live service config | Agent service creates `Global\DlpClassificationCache` on startup. If agent restarts, old mapping is unmapped; new mapping created with same name. | Code edit: agent must close handle on shutdown; DLL must re-open on next attach |
| OS-registered state | `Global\` namespace requires `SeCreateGlobalPrivilege` (SYSTEM has this). No registry entries for shared memory. | N/A |
| Secrets/env vars | None -- shared memory has no authentication beyond Windows ACLs. The mapping is created with a security descriptor restricting access to SYSTEM and Administrators. | Code edit: ensure security descriptor is set correctly |
| Build artifacts | `dlp_hook_dll.dll` and `dlp_hook_dll_x86.dll` are the injection targets. After rebuild, already-injected processes still have the old DLL loaded until they exit. | Document: full cache feature requires process restart or agent re-injection sweep |

**Nothing found in category:** Stored data -- verified: shared memory is ephemeral by design.

## Common Pitfalls

### Pitfall 1: DllMain Deadlock on Thread Creation
**What goes wrong:** Calling `CreateThread` from inside `DllMain` during `DLL_PROCESS_ATTACH` can deadlock because the loader lock is held.
**Why it happens:** Windows holds the loader lock while `DllMain` runs. `CreateThread` may need to acquire the loader lock to initialize the new thread's TLS.
**How to avoid:** Defer thread creation to a post-attach work item. Options: (a) use `QueueUserWorkItem` from `DllMain` (does not acquire loader lock), (b) set a flag in `DllMain` and check it on first hook call, creating the thread then, (c) use a one-shot timer callback.
**Warning signs:** Process hangs at startup after hook DLL is injected.

### Pitfall 2: Torn Read of Version Word
**What goes wrong:** On 32-bit systems, a 64-bit atomic read may not be atomic without proper alignment.
**Why it happens:** x86 guarantees atomicity for aligned 64-bit reads, but unaligned reads may tear. The shared-memory layout must ensure `CacheHeader.version_word` is 8-byte aligned.
**How to avoid:** Use `#[repr(C, align(8))]` for the header struct, or place the version word at offset 0 (always aligned).
**Warning signs:** DLL occasionally sees impossible version numbers (very large or alternating between old/new).

### Pitfall 3: Cache Version Seen At Not Updated on Pipe Success
**What goes wrong:** The DLL stamps `cache_version_seen_at` on each successful pipe round-trip. If this is not updated, TTL checks will incorrectly treat fresh cache entries as expired.
**Why it happens:** The stamp must happen in the success path of `pipe_client::send_request`, not in the cache lookup path. If the stamp is forgotten, all entries appear stale after their TTL expires.
**How to avoid:** Wrap `send_request` in a helper that always stamps on success, even when the response is ALLOW.
**Warning signs:** Cache entries expire prematurely; pipe round-trips increase despite cache hits.

### Pitfall 4: 32-bit DLL Reading 64-bit Agent's Pointers
**What goes wrong:** If the shared-memory layout uses `usize` for offsets or pointers, a 32-bit DLL reading a 64-bit agent's cache will misinterpret the data.
**Why it happens:** `usize` is 4 bytes on x86 and 8 bytes on x64. The shared-memory layout must be architecture-agnostic.
**How to avoid:** Use `u64` for all offsets, sizes, and pointer values in the shared-memory layout. The 32-bit DLL casts to `usize` after reading.
**Warning signs:** Cache lookups return garbage on WoW64 processes.

### Pitfall 5: ABA Problem on Version Word
**What goes wrong:** If the version number wraps around (after 2^63 updates), a DLL might see an old buffer as new.
**Why it happens:** The version is 63 bits. While practically impossible to exhaust (would require billions of updates per second for centuries), the design must be theoretically sound.
**How to avoid:** The monotonic version ensures no ABA -- even if the version wraps, the buffer index bit ensures the DLL sees a different buffer. Additionally, the agent can enforce a minimum version increment of 1.
**Warning signs:** Not observable in practice; theoretical concern only.

### Pitfall 6: Shared Memory Not Cleaned Up on Agent Crash
**What goes wrong:** If the agent crashes, the `Global\DlpClassificationCache` mapping may persist until the last hooked process unmaps it.
**Why it happens:** Windows shared memory has reference counting -- it is destroyed when the last handle is closed.
**How to avoid:** The agent should open the mapping with a name that includes a generation counter (e.g., `Global\DlpClassificationCache_v{N}`) and update the name in a well-known location (registry or another small shared memory). Alternatively, accept that stale mappings are harmless -- they are read-only and the new agent creates a new mapping.
**Warning signs:** Memory usage grows slowly over many agent restarts. Mitigation: agent cleanup on startup (enumerate and close old handles).

### Pitfall 7: Trusted Path Allowlist Bypassing Classification
**What goes wrong:** A path like `C:\Windows\System32\evil.dll` is allowlisted because it starts with `C:\Windows\System32\`. An attacker places a malicious file there.
**Why it happens:** The trusted path allowlist is a performance optimization, not a security control. It assumes these paths are never T3/T4 by policy.
**How to avoid:** The allowlist is ONLY for paths that are physically impossible to be T3/T4 (system directories). The DACL tripwire (Phase 52) is the security backstop. Document that the allowlist is a performance feature, not a security boundary.
**Warning signs:** Audit events show T3/T4 classifications for allowlisted paths -- this is a policy misconfiguration, not a bug.

## Code Examples

### Shared Memory Layout (Architecture-Agnostic)
```rust
// Source: CONTEXT.md D-01..D-04 + existing codebase patterns
/// 2 MiB total shared memory layout.
/// All offsets and sizes use u64 for 32/64-bit compatibility.
#[repr(C, align(8))]
pub struct CacheHeader {
    /// Atomic version word: [63:1] = version, [0] = active buffer.
    pub version_word: AtomicU64,
    /// Offset to root-prefix table from start of mapping.
    pub prefix_table_offset: u64,
    /// Number of prefix entries.
    pub prefix_count: u64,
    /// Offset to per-file hash table (buffer 0).
    pub hash_table_offset_0: u64,
    /// Offset to per-file hash table (buffer 1).
    pub hash_table_offset_1: u64,
    /// Number of hash slots per buffer.
    pub hash_slots: u64,
    /// Offset to allowlist array.
    pub allowlist_offset: u64,
    /// Number of allowlist entries.
    pub allowlist_count: u64,
    /// Padding to 64-byte cache line.
    _pad: [u8; 64 - 56],
}

/// Root-prefix entry (sorted by prefix_len descending).
#[repr(C)]
pub struct PrefixEntry {
    pub prefix_len: u16,
    pub prefix: [u8; 260], // MAX_PATH in UTF-8
    pub tier: u8,
    pub ttl_secs: u16,
    _pad: [u8; 5],
}

/// Per-file hash entry (open addressing).
#[repr(C)]
pub struct HashEntry {
    pub hash: u64,      // FNV-1a 64-bit
    pub tier: u8,
    pub ttl_bits: u16,
    _pad: [u8; 5],
}

/// Allowlist entry (path prefix).
#[repr(C)]
pub struct AllowlistEntry {
    pub prefix_len: u16,
    pub prefix: [u8; 260],
    pub category: u8, // 0=system, 1=build-tool
    _pad: [u8; 5],
}
```

### Cache Lookup Integration in Trampoline
```rust
// Source: CONTEXT.md D-01..D-12 + existing trampolines.rs pattern
fn classify_and_log_path(
    path: &str,
    action: &str,
    fn_name: &str,
) -> Option<crate::fail_closed::DenyReturn> {
    let path_hash = crate::hash_path(path);
    let start_qpc = unsafe { query_performance_counter() };

    // 1. Check allowlist first (fastest path).
    if allowlist::is_allowed(path) {
        return None;
    }

    // 2. Check shared-memory cache.
    let cache_result = classification_cache::lookup(path);
    let latency_qpc = unsafe { query_performance_counter() } - start_qpc;

    match cache_result {
        Some(classification) => {
            // Cache hit -- decision without pipe round-trip.
            perf_telemetry::record_cache_hit(latency_qpc);
            if classification.is_sensitive() && is_write_action(action) {
                return Some(crate::fail_closed::DenyReturn::BoolFalse);
            }
            return None;
        }
        None => {
            // Cache miss -- fall through to pipe.
            perf_telemetry::record_cache_miss(latency_qpc);
        }
    }

    // 3. Pipe round-trip (existing logic).
    let decision = crate::classify_path(path, action, crate::DEFAULT_PIPE_NAME);
    // ... existing decision handling ...
}
```

### QueryPerformanceCounter Wrapper
```rust
// Source: Windows API documentation + CLAUDE.md performance requirements
use windows::Win32::System::Performance::QueryPerformanceCounter;

/// Returns the current QPC value.
///
/// # Safety
///
/// This function is safe to call from any thread. QPC is available
/// on all Windows versions since XP.
pub unsafe fn query_performance_counter() -> i64 {
    let mut qpc = 0i64;
    let _ = QueryPerformanceCounter(&mut qpc);
    qpc
}

/// Converts QPC delta to microseconds.
///
/// Call `QueryPerformanceFrequency` once at startup and cache the result.
pub fn qpc_to_us(delta: i64, freq: i64) -> u64 {
    (delta as u64 * 1_000_000) / freq as u64
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Named-pipe round-trip for every file operation (v0.9.0) | Shared-memory cache lookup + pipe only on miss (Phase 50) | 2026-05-20 (planned) | p95 latency drops from ~5ms to <50us on cache hit |
| Single-buffer shared memory (risk of torn reads) | Double-buffered atomic version flip (Phase 50) | 2026-05-20 (planned) | Eliminates torn-read risk; wait-free for readers |
| Fail-closed on any pipe error (v0.9.0) | Tier-gated asymmetric fail: T3/T4 closed, T1/T2 open (Phase 50) | 2026-05-20 (planned) | Build workloads (T1/T2) continue working when agent is down |
| No cache TTL (v0.9.0 stub) | Per-tier staleness budgets with TTL enforcement (Phase 50) | 2026-05-20 (planned) | Prevents stale classifications from persisting indefinitely |

**Deprecated/outdated:**
- `std::time::Instant` for cross-process timing: not comparable across processes. Use `QueryPerformanceCounter` for latency telemetry, wall-clock seconds for TTL.
- `static mut` for shared state in DLL: existing code uses `static mut` for original function pointers (Phase 48 pattern). The cache header pointer should also be `static mut` for simplicity, but access is read-only after initialization.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `CreateFileMappingW` with `Global\` prefix works from a SYSTEM service and is mappable by user-mode processes | Shared Memory on Windows | If wrong, shared memory is invisible to hooked processes; fallback to pipe-only mode |
| A2 | `AtomicU64::load(Acquire)` + `AtomicU64::store(Release)` provides sufficient ordering for the double-buffer pattern on x86/x64 Windows | Lock-Free Cache Design | If wrong, readers may see partially-written cache entries. Mitigation: `fence(SeqCst)` on agent side |
| A3 | FNV-1a 64-bit has sufficiently low collision rate for ~14K hash slots with ~5K entries | Hash Table Design | If wrong, collision rate causes false positives/negatives. Mitigation: 8-byte hash verification per entry |
| A4 | `QueryPerformanceCounter` is available and monotonic on all target Windows versions | Performance Measurement | If wrong, latency telemetry is unavailable. Mitigation: fall back to `Instant::now()` for coarse measurement |
| A5 | A background thread spawned from the DLL (not from DllMain) can safely poll shared memory every 100ms | Background Thread in DLL | If wrong, thread creation fails or deadlocks. Mitigation: use `QueueUserWorkItem` or deferred creation |
| A6 | The 2 MiB shared memory size is sufficient for ~5K T3/T4 paths + ~480 prefix entries + allowlist | Integration Points | If wrong, cache overflows. Mitigation: agent logs overflow and falls back to pipe-only for excess paths |

## Open Questions (RESOLVED)

1. **QPC frequency stability on virtualized endpoints** — RESOLVED
   - Resolution: Measure QPC frequency once at DLL load and verify it is >1 MHz (typical). If not, fall back to `Instant::now()`. Implemented in `perf_telemetry.rs` initialization.

2. **Shared-memory security descriptor** — RESOLVED
   - Resolution: Use SDDL `D:(A;;GA;;;SY)(A;;GR;;;AU)` — SYSTEM has generic all, Authenticated Users have generic read. Verified with `ConvertStringSecurityDescriptorToSecurityDescriptorW`. Implemented in `ClassificationCache::create_mapping()`.

3. **Cache rebuild frequency under rapid policy changes** — RESOLVED
   - Resolution: 500ms debounce timer in `CachePusher` — batch rapid changes into a single rebuild. Implemented in Plan 02 Task 2 (`cache_pusher.rs`).

4. **x86 DLL shared-memory pointer size** — RESOLVED
   - Resolution: Cache header uses `#[repr(C, align(8))]` ensuring 8-byte alignment. x86 Windows guarantees atomic 64-bit aligned reads/writes via `cmpxchg8b`. Verified in `CacheHeader` struct definition.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows SDK (shared memory APIs) | Cache creation | Yes | 10.0.22621+ | N/A -- required |
| `QueryPerformanceCounter` | Latency telemetry | Yes | All Windows | `Instant::now()` (coarser) |
| `CreateThread` | Background thread | Yes | All Windows | `QueueUserWorkItem` |
| `Global\` namespace privilege | Cross-session shared memory | Yes | SYSTEM has `SeCreateGlobalPrivilege` | N/A -- agent runs as SYSTEM |
| 2 MiB address space per process | Shared memory mapping | Yes | All Windows | Reduce cache size |
| x86 build target (`i686-pc-windows-msvc`) | WoW64 DLL | Yes | Installed in CI | N/A -- required for WoW64 |

**Missing dependencies with no fallback:**
- None identified.

**Missing dependencies with fallback:**
- None identified.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `cargo test` |
| Config file | None -- standard Rust test runner |
| Quick run command | `cargo test -p dlp-hook-dll` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CACHE-01 | Agent creates shared memory; DLL maps it read-only | unit | `cargo test -p dlp-agent classification_cache::tests::create_and_map` | No -- Wave 0 |
| CACHE-01 | Double-buffered version flip is atomic | unit | `cargo test -p dlp-agent classification_cache::tests::atomic_flip` | No -- Wave 0 |
| CACHE-02 | DLL thread-local LRU stores 128 entries | unit | `cargo test -p dlp-hook-dll classification_cache::tests::lru_capacity` | No -- Wave 0 |
| CACHE-03 | Extended HookRequest serializes correctly | unit | `cargo test -p dlp-common hook_ipc::tests::extended_request_roundtrip` | No -- Wave 0 |
| CACHE-04 | Agent rebuilds cache on policy change | integration | `cargo test -p dlp-agent cache_pusher::tests::rebuild_on_change` | No -- Wave 0 |
| CACHE-05 | Trusted path allowlist bypasses cache + pipe | unit | `cargo test -p dlp-hook-dll allowlist::tests::system32_bypass` | No -- Wave 0 |
| CACHE-06 | Build-tool allowlist bypasses pipe | unit | `cargo test -p dlp-hook-dll allowlist::tests::cargo_exe_bypass` | No -- Wave 0 |
| FAIL-01 | HEALTHY->DEGRADED after 3 pipe failures | unit | `cargo test -p dlp-hook-dll fail_mode::tests::degraded_transition` | No -- Wave 0 |
| FAIL-01 | DEGRADED->ISOLATED after 10 failures | unit | `cargo test -p dlp-hook-dll fail_mode::tests::isolated_transition` | No -- Wave 0 |
| FAIL-01 | ISOLATED->RESYNC on fresh cache + pipe ok | unit | `cargo test -p dlp-hook-dll fail_mode::tests::resync_transition` | No -- Wave 0 |
| FAIL-02 | T3/T4 fail-closed when ISOLATED | unit | `cargo test -p dlp-hook-dll fail_mode::tests::t3_t4_fail_closed` | No -- Wave 0 |
| FAIL-02 | T1/T2 fail-open when ISOLATED | unit | `cargo test -p dlp-hook-dll fail_mode::tests::t1_t2_fail_open` | No -- Wave 0 |
| FAIL-03 | TTL enforcement expires entries correctly | unit | `cargo test -p dlp-hook-dll classification_cache::tests::ttl_expiry` | No -- Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-hook-dll`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-hook-dll/src/classification_cache.rs` -- module + tests for CACHE-01, CACHE-02, FAIL-03
- [ ] `dlp-hook-dll/src/fail_mode.rs` -- module + tests for FAIL-01, FAIL-02
- [ ] `dlp-hook-dll/src/allowlist.rs` -- module + tests for CACHE-05, CACHE-06
- [ ] `dlp-hook-dll/src/perf_telemetry.rs` -- module + tests for latency measurement
- [ ] `dlp-hook-dll/src/background_thread.rs` -- module + tests for ISOLATED-state detection
- [ ] `dlp-agent/src/classification_cache.rs` -- module + tests for agent-side cache writer
- [ ] `dlp-agent/src/cache_pusher.rs` -- module + tests for policy change detection
- [ ] `dlp-common/src/hook_ipc.rs` -- extend with cache_version, cache_hint, HookOp
- [ ] `dlp-hook-dll/Cargo.toml` -- add `Win32_System_Performance` feature

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | N/A -- no auth in cache layer |
| V3 Session Management | No | N/A -- no sessions in cache layer |
| V4 Access Control | Yes | Shared memory mapped read-only by DLL; writable only by SYSTEM agent |
| V5 Input Validation | Yes | Path length capped at 260 bytes; prefix matching bounds-checked |
| V6 Cryptography | No | N/A -- no crypto in cache layer |
| V7 Error Handling | Yes | Fail-closed for T3/T4; fail-open for T1/T2 |
| V8 Data Protection | Yes | Shared memory ACL restricts write to SYSTEM only |
| V10 Malicious Code | Yes | DLL never writes to shared memory; read-only mapping |

### Known Threat Patterns for Windows Hook DLL + Shared Memory

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malicious process modifies shared memory | Tampering | Map read-only (`FILE_MAP_READ`); Windows enforces at MMU level |
| Denial of service via cache flooding | Denial of Service | Fixed 2 MiB size; agent controls content; overflow falls back to pipe |
| Stale cache data after policy change | Information Disclosure | Atomic version flip; TTL enforcement; max staleness triggers ISOLATED |
| DLL bypasses cache entirely | Elevation of Privilege | Cache is performance optimization, not security boundary; DACL tripwire is backstop |
| Process pretends to be agent and creates fake cache | Spoofing | `Global\` namespace requires `SeCreateGlobalPrivilege`; only SYSTEM can create |

## Sources

### Primary (HIGH confidence)
- `dlp-hook-dll/src/lib.rs` -- existing DllMain, IAT patching, HOOKS table, trampolines (verified by direct read)
- `dlp-hook-dll/src/pipe_client.rs` -- thread-local buffer, bincode framing, PipeError enum (verified by direct read)
- `dlp-hook-dll/src/trampolines.rs` -- 12 trampoline implementations with classify_and_log_path/handle (verified by direct read)
- `dlp-hook-dll/src/crash_guard.rs` -- catch_unwind + SEH + reentrancy guard (verified by direct read)
- `dlp-hook-dll/src/fail_closed.rs` -- DenyReturn enum + fail_closed! macro (verified by direct read)
- `dlp-common/src/classification.rs` -- Classification enum with is_sensitive() (verified by direct read)
- `dlp-common/src/hook_ipc.rs` -- HookRequest/HookResponse types (verified by direct read)
- `dlp-common/src/abac.rs` -- Decision enum with is_denied() (verified by direct read)
- `dlp-agent/src/cache.rs` -- FNV-1a 64-bit hash implementation (verified by direct read)
- `dlp-agent/src/allowlist.rs` -- AllowlistMatcher with signer caching (verified by direct read)
- `dlp-agent/src/hook_ipc.rs` -- HookIpcServer with bincode framing (verified by direct read)
- `dlp-agent/src/hook_injector.rs` -- WaitForSingleObject usage pattern (verified by grep)
- `.planning/research/ARCHITECTURE.md` -- v0.10.0 architecture with shared memory layout and fail-mode state machine (verified by direct read)
- `.planning/research/PITFALLS.md` -- CRIT-04 (perf death-spiral), MOD-08 (pipe storm), MIN-04 (DllMain loader lock) (verified by direct read)
- `50-CONTEXT.md` -- All locked decisions D-01..D-16 (verified by direct read)

### Secondary (MEDIUM confidence)
- Context7 `/microsoft/windows-rs` -- Windows API bindings documentation (partial retrieval due to CLI limitations)
- Microsoft Learn -- `CreateFileMappingW`, `MapViewOfFile`, `OpenFileMappingW` documentation (training knowledge, not verified live)
- Microsoft Learn -- AppInit_DLLs and Secure Boot (cited in PITFALLS.md)
- Windows Internals 7th Edition -- loader lock behavior, shared memory semantics (training knowledge)

### Tertiary (LOW confidence)
- None -- all critical claims verified against codebase or official documentation.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all packages already in workspace, versions verified
- Architecture: HIGH -- design is locked in CONTEXT.md; existing codebase provides solid patterns
- Pitfalls: HIGH -- CRIT/MOD pitfalls from research docs are well-documented and mitigated in design
- Windows API specifics: MEDIUM-HIGH -- APIs are standard but some edge cases (QPC on virtualization, x86 atomic 64-bit) need empirical validation

**Research date:** 2026-05-20
**Valid until:** 2026-06-20 (30 days for stable design; Windows APIs are stable)
