---
phase: 58-differentiators-bundle-override-diagnostic-hash-evidence-sel
plan: 01
subsystem: hook-dll + dlp-common
completed: 2026-06-02
tags: [diff-03, diff-02, sha-256, diagnostics, ipc, audit]
dependency_graph:
  requires: []
  provides: [DIFF-03, DIFF-02]
  affects: [58-02, 58-03, 58-04, 58-05, 58-06]
tech_stack:
  added:
    - sha2 = "0.10"
    - rayon = "1.10"
    - hex = "0.4"
    - crossbeam-queue = "0.3"
  patterns:
    - OnceLock lazy initialization (never from DllMain)
    - Thread pool offloading for CPU-bound work
    - Lock-free ring buffer with lazy eviction
key_files:
  created:
    - dlp-hook-dll/src/hash_compute.rs
    - dlp-hook-dll/src/diagnostic_ring.rs
  modified:
    - dlp-common/src/hook_ipc.rs
    - dlp-common/src/audit.rs
    - dlp-hook-dll/Cargo.toml
    - dlp-hook-dll/src/lib.rs
    - dlp-e2e/tests/bincode_compat.rs
    - dlp-server/src/alert_router.rs
decisions:
  - "AuditEvent content hash fields use Option<String> with skip_serializing_if for backward compat"
  - "DiagnosticSnapshot uses QPC timestamps for platform-independent expiry logic"
  - "Hash thread pool uses 2 threads to balance throughput vs resource usage"
  - "Golden fixture updated from 47 to 49 bytes to account for volume class fields"
metrics:
  duration: "~45 min"
  tasks_completed: 3
  tests_added: 31
  files_created: 2
  files_modified: 8
---

# Phase 58 Plan 01: Foundational Hook DLL Modules Summary

## One-liner

Created SHA-256 content hash computation (DIFF-03) and lock-free diagnostic snapshot ring buffer (DIFF-02) modules, extended IPC protocol with 5 new payload variants, and added content hash fields to AuditEvent.

## Tasks Completed

### Task 1: Extend dlp-common IPC and audit types

**Commit:** `cc0267c`

- Extended `IpcPayloadV1` with 5 new variants: `RequestOverride`, `PullDiagnostics`, `DiagnosticsResponse`, `PullHealth`, `HealthResponse`
- Added `ClassificationSource` enum (`CacheHit`, `CacheMiss`, `Pipe`) with `#[default]` on `CacheHit`
- Added `OverrideRequest`, `PullDiagnosticsRequest`, `DiagnosticSnapshot`, `DiagnosticsResponse`, `PullHealthRequest`, `HookHealthSnapshot`, `HealthResponse` structs
- Added `content_sha256`, `hash_truncated`, `hash_skipped` fields to `AuditEvent` with `#[serde(skip_serializing_if = "Option::is_none")]`
- Added `with_content_hash` builder method to `AuditEvent`
- Added 18 unit tests for roundtrip serialization, defaults, backward compatibility

### Task 2: Create hash_compute.rs

**Commit:** `88e52ac`

- Created `dlp-hook-dll/src/hash_compute.rs` with two entry points:
  - `compute_content_hash` — inline SHA-256 for small buffers (< 64KB)
  - `compute_content_hash_offloaded` — thread pool hashing for large buffers
- 100MB cap (`HASH_CAP_BYTES`) per D-14 to prevent DoS
- Thread pool lazily initialized via `OnceLock` (never from `DllMain`)
- 7 unit tests covering known values, empty buffer, zero len, truncation, offloading

### Task 3: Create diagnostic_ring.rs

**Commit:** `88e52ac` (same as Task 2)

- Created `dlp-hook-dll/src/diagnostic_ring.rs` with:
  - `push_snapshot` — fire-and-forget push with overwrite-on-full
  - `drain_snapshots` — drain up to limit with QPC-based lazy eviction
- 1000-entry capacity (`RING_CAPACITY`) bounding memory to ~1MB per process
- 1-hour lazy eviction (`ENTRY_EXPIRY_QPC_TICKS = 36_000_000_000_000`)
- 6 unit tests covering push/drain, capacity, overwrite, limit, expiry, empty drain

### Workspace Fix-up

**Commit:** `291bcf5`

- Fixed `dlp-server/src/alert_router.rs` AuditEvent struct literals to include new content hash fields
- Updated `dlp-e2e/tests/bincode_compat.rs` golden fixture from 47 to 49 bytes (volume class fields)
- Added `source_volume_class`/`destination_volume_class` to test initializers

### Formatting

**Commit:** `e02fec7`

- `cargo fmt` on `diagnostic_ring.rs`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] ClassificationSource Default derive error**
- **Found during:** Task 1
- **Issue:** `#[derive(Default)]` on enum requires `#[default]` on one variant
- **Fix:** Added `#[default]` to `CacheHit` variant
- **Commit:** `cc0267c`

**2. [Rule 1 - Bug] Raw pointer Send error in hash_compute.rs**
- **Found during:** Task 2
- **Issue:** `*const u8` cannot be sent between threads in `pool.install()`
- **Fix:** Copy buffer data into `Vec` before sending to thread pool
- **Commit:** `88e52ac`

**3. [Rule 1 - Bug] Workspace build failure in alert_router.rs**
- **Found during:** Post-task verification
- **Issue:** `AuditEvent` struct literals missing new `content_sha256`, `hash_truncated`, `hash_skipped` fields
- **Fix:** Added the three fields with `None` values to all 6 struct literals
- **Commit:** `291bcf5`

**4. [Rule 1 - Bug] Bincode golden fixture mismatch**
- **Found during:** Post-task verification
- **Issue:** Golden fixture was 47 bytes (pre-volume-class) but current struct serializes to 49 bytes
- **Fix:** Updated fixture to 49 bytes with correct field breakdown comments
- **Commit:** `291bcf5`

**5. [Rule 2 - Missing Critical] Clippy not_unsafe_ptr_arg_deref**
- **Found during:** Post-task verification
- **Issue:** Public functions taking raw pointers should be marked `unsafe`
- **Fix:** Marked `compute_content_hash` and `compute_content_hash_offloaded` as `pub unsafe fn`
- **Commit:** `291bcf5`

## Known Stubs

| File | Line | Description | Resolution |
|------|------|-------------|------------|
| `dlp-hook-dll/src/lib.rs` | N/A | `pub mod hash_compute` and `pub mod diagnostic_ring` declared but not wired into trampolines | Plan 58-02 will wire hash_compute into WriteFile/WriteFileEx trampolines |
| `dlp-hook-dll/src/lib.rs` | N/A | `pub mod diagnostic_ring` declared but push_snapshot not called from trampolines | Plan 58-03 will wire diagnostic_ring into DENY paths |

## Threat Flags

No new security-relevant surface introduced beyond what is documented in the plan's threat model.

## Self-Check

- [x] `dlp-hook-dll/src/hash_compute.rs` exists and compiles
- [x] `dlp-hook-dll/src/diagnostic_ring.rs` exists and compiles
- [x] `dlp-common/src/hook_ipc.rs` has new IPC types
- [x] `dlp-common/src/audit.rs` has content hash fields
- [x] All dlp-common tests pass (301 passed)
- [x] All dlp-hook-dll tests pass (292 passed, single-threaded for diagnostic_ring)
- [x] All dlp-e2e bincode_compat tests pass (8 passed)
- [x] All dlp-server tests pass (574 passed)
- [x] Workspace builds with no errors
- [x] `cargo fmt` clean

## Self-Check: PASSED
