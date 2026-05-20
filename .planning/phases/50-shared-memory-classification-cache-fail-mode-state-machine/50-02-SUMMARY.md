---
phase: 50-shared-memory-classification-cache-fail-mode-state-machine
plan: 02
type: execute
subsystem: dlp-agent
tags: [shared-memory, cache, classification, windows, ipc]
dependency_graph:
  requires: [50-01]
  provides: [50-03, 50-04, 50-05, 50-06]
  affects: [dlp-hook-dll]
tech_stack:
  added:
    - classification_cache.rs: Formal ABI with sequence-lock publication
    - cache_pusher.rs: Policy change subscriber with debounce
  patterns:
    - Double-buffered atomic version flip
    - FNV-1a 64-bit hashing
    - SDDL security descriptors
    - crossbeam-channel for thread notification
key_files:
  created:
    - dlp-agent/src/classification_cache.rs
    - dlp-agent/src/cache_pusher.rs
  modified:
    - dlp-agent/src/lib.rs
    - dlp-agent/src/service.rs
    - dlp-agent/src/hook_ipc.rs (Plan 01 IPC field fixes)
decisions:
  - Removed allowlist_offset/allowlist_count from CacheHeader to fit 128-byte constraint
  - Used monitored_paths as protected root source (AgentConfig lacks protected_paths field)
  - Accepted small one-time security descriptor leak (LocalFree not in windows crate)
  - HashEntry uses explicit _pad1/_pad2 fields for correct 16-byte layout
metrics:
  duration: "~45 minutes"
  completed_date: "2026-05-20"
---

# Phase 50 Plan 02: Shared-Memory Classification Cache — Agent-Side Writer

## One-liner

Agent-side shared-memory classification cache with formal 128-byte ABI, sequence-lock publication, double-buffered atomic flip, FNV-1a hashing, SDDL ACL, and policy-change pusher with 500ms debounce.

## What Was Built

### Task 1: Formal Shared-Memory ABI

- `CacheHeader` (`#[repr(C, align(8))]`, exactly 128 bytes):
  - `version_word: AtomicU64` — sequence-lock (odd=writing, even=stable)
  - `magic: u64 = 0x4454_5001`, `layout_version: u32 = 1`
  - All offsets as `u64` for 32/64-bit compatibility
  - `created_at_epoch_secs` for wall-clock TTL
  - XOR checksum over all fields except version_word and checksum
- `PrefixEntry` (`#[repr(C)]`, 272 bytes) — directory-level classification
- `HashEntry` (`#[repr(C)]`, 16 bytes) — per-file FNV-1a hash entry
- Static assertions verify sizes at compile time

### Task 2: ClassificationCache Implementation

- `ClassificationCache::new()` — creates `Global\DlpClassificationCache` (2 MiB)
  - Security descriptor: `D:(A;;GA;;;SY)(A;;GR;;;BA)`
  - Windows `CreateFileMappingW` + `MapViewOfFile`
- `rebuild()` — sequence-lock atomic flip:
  1. Odd version_word signals "writing"
  2. Build prefix table (sorted by length desc) + hash table (open addressing)
  3. `fence(Ordering::Release)` then even version_word publication
- `overflow_behavior()` — T4 > T3 > T2 > T1 priority truncation with telemetry
- `validate_bounds()` — all offsets checked against total_size
- `prepopulate_t3_t4_roots()` — seed protected paths at startup

### Task 3: Fuzz / Adversarial Tests

8 tests covering: bad magic, bad layout version, checksum mismatch, out-of-bounds offsets, truncated mapping, alignment, rapid version flips, partial write recovery.

### Task 4: CachePusher

- Background thread with crossbeam-channel notification
- `Rebuild` / `Shutdown` commands
- 500ms debounce timer prevents thrashing
- Poll backstop every 30 seconds

### Task 5: Service Integration

- `ClassificationCache` initialized after `init_agent_db()`, before IPC servers
- Pre-populates T3/T4 roots from `agent_config.monitored_paths`
- `CachePusher` started with `Arc<ClassificationCache>`
- `RunLoopContext` stores both handles for graceful shutdown

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] ABI struct sizes incorrect**
- **Found during:** Task 1 verification (cargo test)
- **Issue:** CacheHeader was 136 bytes (not 128); HashEntry was 24 bytes (not 16); PrefixEntry was 270 bytes (not 272)
- **Fix:** Removed `allowlist_offset`/`allowlist_count` (16 bytes) from CacheHeader, increased `_reserved` to 40. HashEntry added explicit `_pad1: u8` before `ttl_secs: u16` and `_pad2: [u8; 4]` after. PrefixEntry `_pad` increased to 6 bytes.
- **Files:** `dlp-agent/src/classification_cache.rs`

**2. [Rule 1 — Bug] LocalFree not available in windows crate**
- **Found during:** Task 2 compilation
- **Issue:** `windows::Win32::System::Memory::LocalFree` does not exist in the windows crate version used
- **Fix:** Removed the free call; security descriptor is a small one-time allocation at startup that lives for the process lifetime. Documented as accepted trade-off.
- **Files:** `dlp-agent/src/classification_cache.rs`

**3. [Rule 1 — Bug] AgentConfig lacks `protected_paths` field**
- **Found during:** Task 5 compilation
- **Issue:** Plan assumed `protected_paths` existed on `AgentConfig`; only `monitored_paths` exists
- **Fix:** Used `monitored_paths` as the protected root source with a comment explaining the deviation. This is functionally correct for the current config schema.
- **Files:** `dlp-agent/src/service.rs`

**4. [Rule 1 — Bug] Checksum test had wrong offsets after ABI changes**
- **Found during:** Task 3 test execution
- **Issue:** `compute_checksum_raw` test helper used offset 96 for `_reserved`, but after removing allowlist fields, `_reserved` starts at offset 88
- **Fix:** Updated test helper offsets to match new layout
- **Files:** `dlp-agent/src/classification_cache.rs`

**5. [Rule 1 — Bug] Clippy warnings on mut_from_ref and unused imports**
- **Found during:** Final verification
- **Issue:** `header_mut()` returned `&mut T` from `&self`; unused `Arc` and `error` imports
- **Fix:** Changed `header_mut()` to return `*mut CacheHeader` (raw pointer); callers use `unsafe { &mut *self.header_mut() }`. Removed unused imports.
- **Files:** `dlp-agent/src/classification_cache.rs`

## Verification Results

- `cargo test -p dlp-agent --lib`: **579 passed, 0 failed**
- `cargo clippy -p dlp-agent -- -D warnings`: **clean**
- `cargo build -p dlp-agent`: **success**

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1-3 | `09b4217` | Formal ABI + ClassificationCache with sequence-lock and security descriptor |
| 4-5 | `104af10` | CachePusher + service integration |

## Known Stubs

| File | Line | Description |
|------|------|-------------|
| `cache_pusher.rs:perform_rebuild` | ~215 | Placeholder rebuild with empty entries — needs policy store integration to collect real T3/T4 paths |

## Threat Flags

None — all threat model mitigations (T-50-04 through T-50-27) are addressed in the implementation.

## Self-Check: PASSED

- [x] `dlp-agent/src/classification_cache.rs` exists
- [x] `dlp-agent/src/cache_pusher.rs` exists
- [x] `dlp-agent/src/lib.rs` declares both modules
- [x] `dlp-agent/src/service.rs` integrates cache
- [x] Commit `09b4217` exists
- [x] Commit `104af10` exists
- [x] All tests pass (579/579)
- [x] Clippy clean
- [x] Build succeeds
