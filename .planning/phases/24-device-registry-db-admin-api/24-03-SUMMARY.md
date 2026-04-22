---
phase: 24-device-registry-db-admin-api
plan: "03"
subsystem: dlp-agent/device_registry
tags: [agent, cache, usb, device-registry, tokio, rwlock, tdd]
dependency_graph:
  requires: [DeviceRegistryRepository, DeviceRegistryRow, GET /admin/device-registry]
  provides: [DeviceRegistryCache, fetch_device_registry, REGISTRY_CACHE static, set_registry_cache, set_registry_client, set_registry_runtime_handle]
  affects:
    - dlp-agent/src/device_registry.rs
    - dlp-agent/src/server_client.rs
    - dlp-agent/src/lib.rs
    - dlp-agent/src/service.rs
    - dlp-agent/src/detection/usb.rs
tech_stack:
  added: []
  patterns:
    - RwLock<HashMap> for lock-free concurrent reads (parking_lot)
    - OnceLock statics for cross-thread access from unsafe extern "system" callback
    - tokio::runtime::Handle stored in static to bridge std::thread -> tokio boundary
    - spawn_poll_task pattern matching AuditBuffer::spawn_flush_task (30s interval + shutdown watch)
    - Approach A: USB registration moved inside run_loop for live tokio Handle access
key_files:
  created:
    - dlp-agent/src/device_registry.rs
  modified:
    - dlp-agent/src/server_client.rs
    - dlp-agent/src/lib.rs
    - dlp-agent/src/service.rs
    - dlp-agent/src/detection/usb.rs
decisions:
  - "Approach A chosen over Approach B: USB notification registration moved into run_loop so usb_wndproc can use tokio::runtime::Handle::current() stored in REGISTRY_RUNTIME_HANDLE static"
  - "Three OnceLock statics in usb.rs (REGISTRY_CACHE, REGISTRY_CLIENT, REGISTRY_RUNTIME_HANDLE) bridge the unsafe extern system callback to the async world without a second tokio runtime"
  - "std::thread::spawn does NOT inherit the tokio context — Handle must be explicitly captured and stored before spawning the USB message-loop thread"
  - "DeviceRegistryCache uses parking_lot::RwLock (not std::sync::RwLock) matching the existing codebase pattern in UsbDetector"
metrics:
  duration_seconds: 780
  completed_date: "2026-04-22"
  tasks_completed: 2
  files_changed: 5
---

# Phase 24 Plan 03: Agent Device Registry Cache — Summary

**One-liner:** `DeviceRegistryCache` with `RwLock<HashMap>` polling `GET /admin/device-registry` every 30s, wired into agent startup and USB arrival via OnceLock statics bridging the `unsafe extern "system"` callback to the tokio runtime.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (GREEN) | DeviceRegistryCache + fetch_device_registry (TDD) | b934396 | dlp-agent/src/device_registry.rs, server_client.rs, lib.rs |
| 2 | Wire into service.rs startup and usb.rs USB arrival | dd638af | dlp-agent/src/service.rs, detection/usb.rs |

## Verification Results

- `cargo test -p dlp-agent device_registry`: 5/5 pass (4 cache unit tests + 1 fetch unreachable server)
- `cargo test -p dlp-agent` (lib.rs): 165 passed, 0 failed
- `cargo build --all`: zero warnings
- `cargo clippy -p dlp-agent -- -D warnings`: zero warnings
- `grep "DeviceRegistryCache" dlp-agent/src/service.rs`: spawn call at line 396, 408
- `grep "REGISTRY_CACHE" dlp-agent/src/detection/usb.rs`: static at line 233, set at 262, get at 348
- `grep "UsbTrustTier::Blocked" dlp-agent/src/device_registry.rs`: fail-safe default at line 72

## Deviations from Plan

### Architectural Decision: Approach A Implementation Detail

**Found during:** Task 2

**Issue:** The plan noted that `std::thread::spawn` does NOT inherit the tokio context. The plan offered two options (Approach A = move USB inside run_loop, Approach B = mpsc Notify). Approach A was chosen.

**Implementation detail:** The plan's Approach A description said "Move USB setup from run_service into run_loop." The actual challenge is that even inside `run_loop`, `std::thread::spawn` for the USB message-loop thread does not inherit the tokio `Handle`. The fix: capture `tokio::runtime::Handle::current()` before spawning the USB thread, store it in `REGISTRY_RUNTIME_HANDLE: OnceLock<Handle>`, and use `handle.spawn(...)` from `usb_wndproc`.

**Three statics added to usb.rs** (instead of two as suggested in plan):
- `REGISTRY_CACHE: OnceLock<Arc<DeviceRegistryCache>>`
- `REGISTRY_CLIENT: OnceLock<ServerClient>`
- `REGISTRY_RUNTIME_HANDLE: OnceLock<tokio::runtime::Handle>` (additional — plan did not explicitly list this)

**Files modified:** `dlp-agent/src/detection/usb.rs`, `dlp-agent/src/service.rs`

**Commits:** b934396, dd638af

## Known Stubs

None — all methods are fully implemented. The DBT_DEVICEARRIVAL refresh trigger fires actual async refresh on the live tokio runtime.

## Threat Surface Scan

Threat mitigations from the plan's threat model:

| Threat ID | Mitigation | Status |
|-----------|------------|--------|
| T-24-09 | 30s fixed poll interval, single warn log on error, no retry loop | Implemented |
| T-24-10 | trust_tier_for returns UsbTrustTier::Blocked for unknown devices (default deny) | Implemented — verified by test |
| T-24-08 | 30s poll interval accepted as latency bound | Accepted (no code needed) |
| T-24-11 | REGISTRY_CACHE static contains only VID/PID/serial/tier — no credentials or PII | Accepted |

No new threat surface introduced beyond what the plan anticipated. The `REGISTRY_RUNTIME_HANDLE` static is read-only after initialization and contains no sensitive data.

## Self-Check: PASSED

- [x] `dlp-agent/src/device_registry.rs` exists (created)
- [x] `dlp-agent/src/server_client.rs` contains `DeviceRegistryEntry` and `fetch_device_registry`
- [x] `dlp-agent/src/lib.rs` contains `pub mod device_registry`
- [x] `dlp-agent/src/service.rs` contains `DeviceRegistryCache::spawn_poll_task` call
- [x] `dlp-agent/src/detection/usb.rs` contains `REGISTRY_CACHE` static and `set_registry_cache` + DBT_DEVICEARRIVAL refresh trigger
- [x] Commit b934396 present in git log
- [x] Commit dd638af present in git log
- [x] 165 dlp-agent unit tests pass (was 160 before this plan — 5 new tests added)
- [x] Zero compiler warnings
- [x] Zero clippy warnings
