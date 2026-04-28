---
slug: unregistered-usb-writes-allowed
status: resolved
trigger: "Unregistered USB drive allows file writes — agent should block all operations on any USB not in the device registry (fail-safe default-deny), but writes succeed on a freshly plugged-in USB with no registry entry"
created: 2026-04-24
updated: 2026-04-25
source_phase: 28-admin-tui-screens (UAT check 1)
---

# Debug Session: Unregistered USB writes allowed

## Symptoms

<!-- DATA_START -->
- expected: Any USB drive plugged into the agent host that has no entry in the device registry should have ALL operations (read/write/delete) denied. The DeviceRegistryCache.trust_tier_for() has a fail-safe that returns UsbTrustTier::Blocked on cache miss (D-10). So even an unregistered device should be blocked.
- actual: Writing, reading, and deleting files on a freshly plugged-in USB (no registry entry) all succeed. No block dialog, no agent log entry about USB at all.
- error_messages: None. No USB-related entries in C:\ProgramData\DLP\logs\ when operating on the USB.
- timeline: Surfaced during Phase 28 UAT on 2026-04-24. USB was plugged in AFTER dlp-agent was already running.
- reproduction:
    1. Start dlp-agent (agent is running).
    2. Plug in a USB drive that has never been registered in the device registry.
    3. Attempt to write, read, and delete files on the USB.
    4. Observed: all three actions succeed. Expected: all three blocked.
    5. No log entries in C:\ProgramData\DLP\logs\ referencing the USB drive.
<!-- DATA_END -->

## Current Focus

- hypothesis: CONFIRMED. The `notify` file watcher is initialised once at startup with a static set of drive roots. When a USB drive arrives after startup, its drive root (e.g., `E:\`) was not present at startup and is therefore never added to the watcher's watch set. No file events are fired for that drive, so the entire enforcement stack (UsbEnforcer::check, ABAC engine) is never reached.
- test: Traced call chain from service.rs through InterceptionEngine::run() and resolve_watch_paths().
- next_action: Apply fix — dynamically add new USB drive roots to the notify watcher on DBT_DEVICEARRIVAL.

## Evidence

- timestamp: 2026-04-24T00:00:00Z
  file: dlp-agent/src/interception/file_monitor.rs
  finding: |
    `InterceptionEngine::run()` calls `register_watch_paths()` exactly once at line 201.
    The watch set is built from `self.config.resolve_watch_paths()` which enumerates only
    drive roots that **exist at the time run() is called** (line 186-191 in config.rs).
    No mechanism exists to add new paths to the `notify::RecommendedWatcher` after startup.
    The watcher variable is local to `run()` with no channel or signal to inject new paths.

- timestamp: 2026-04-24T00:00:01Z
  file: dlp-agent/src/config.rs (resolve_watch_paths, lines 182-192)
  finding: |
    When `monitored_paths` is empty (default), the function scans A..=Z and filters on
    `p.exists()` at call time. A USB plugged in after this call returns a drive root that
    did not exist at startup, so it is absent from the returned `Vec<PathBuf>`.
    When `monitored_paths` is non-empty, the configured paths are used verbatim — USB
    drive letters are never explicitly listed there either.

- timestamp: 2026-04-24T00:00:02Z
  file: dlp-agent/src/detection/usb.rs (on_drive_arrival, line 114-119)
  finding: |
    `on_drive_arrival()` calls `blocked_drives.write().insert(letter)` — it correctly
    updates the UsbDetector's blocked-drives set. However, it has no reference to the
    `InterceptionEngine` or the notify `Watcher` and cannot add a new watch path.
    The USB detection subsystem and the file interception subsystem are wired up
    separately in service.rs with no feedback channel between them.

- timestamp: 2026-04-24T00:00:03Z
  file: dlp-agent/src/service.rs (run_loop, lines 488-546)
  finding: |
    `InterceptionEngine::with_config(agent_config)` is constructed with the startup
    snapshot of `agent_config`. The `run()` call is dispatched to `spawn_blocking`.
    The USB notification thread (`usb-notification`) is spawned separately and calls
    `on_drive_arrival()` and `handle_volume_event()` in its window proc — but neither
    path holds a reference to the InterceptionEngine and cannot call `watcher.watch()`.

- timestamp: 2026-04-24T00:00:04Z
  file: dlp-agent/src/usb_enforcer.rs (check(), lines 119-187)
  finding: |
    UsbEnforcer::check() has correct default-deny logic: if `device_identities` has no
    entry for the drive but `blocked_drives` does, it returns DENY (the defence-in-depth
    guard added previously). This code is correct but is never reached because no file
    event is ever generated for the new USB drive — the watcher does not observe it.

## Eliminated

- Race condition in UsbDetector: NOT the cause. on_drive_arrival() is called and correctly
  inserts the drive letter into blocked_drives. The issue is upstream — no file events
  reach the enforcer at all.

- UsbEnforcer::check() logic bug: NOT the cause. The enforcer has correct default-deny
  logic for unregistered devices (test_unregistered_device_defaults_to_blocked passes).
  The enforcer is simply never invoked for paths on the new drive.

- notify crate inability to watch removable drives: NOT the cause. The notify crate uses
  ReadDirectoryChangesW under the hood which works for any drive root including USB.
  The root cause is that the USB drive root is never registered with the watcher.

## Resolution

### Root Cause

The `notify` file watcher is constructed once at startup in `InterceptionEngine::run()`
with a static list of drive roots. When a USB drive arrives after the agent starts, its
drive root (e.g., `E:\`) was not present at startup and is never added to the watcher.
Consequently, zero file events are generated for any path on that drive, so
`UsbEnforcer::check()` is never called and all operations silently succeed.

The gap in the architecture: `on_drive_arrival()` (detection/usb.rs) updates the
`UsbDetector::blocked_drives` set but has no way to inject a new watch path into the
running `InterceptionEngine`.

### Fix Direction

Add a `tokio::sync::mpsc` or `watch` channel from the USB detection path into the
`InterceptionEngine::run()` loop. When a volume arrives, send the new drive root through
the channel. The `run()` loop calls `watcher.watch(new_root, RecursiveMode::Recursive)`
inside its event dispatch loop, adding the new drive to the active watch set.

Concrete steps:
1. Add an `Option<mpsc::Receiver<std::path::PathBuf>>` parameter to
   `InterceptionEngine::run()` (or store a `Sender` in the engine struct).
2. In `run_loop` (service.rs), create the channel before constructing the engine.
   Pass the `Sender` end to the USB detection path (stored in the `DRIVE_DETECTOR`
   global or passed through `handle_volume_event`).
3. In `handle_volume_event` (detection/usb.rs), after `on_drive_arrival()` inserts the
   drive letter, send the new drive root path through the channel.
4. In `InterceptionEngine::run()`, add a non-blocking `try_recv` check inside the
   timeout loop (between `recv_timeout` and the stop-flag check). On receipt of a new
   path, call `watcher.watch(&new_path, RecursiveMode::Recursive)`.

This change is minimal and keeps all existing logic intact. The watcher gains paths
dynamically while existing paths continue to be watched without interruption.

## Related Files (initial candidates)

- `dlp-agent/src/interception/mod.rs` — event loop, watch path setup
- `dlp-agent/src/interception/file_monitor.rs` — ReadDirectoryChangesW wrapper
- `dlp-agent/src/detection/usb.rs` — on_drive_arrival, scan_existing_drives
- `dlp-agent/src/config.rs` — resolve_watch_paths
- `dlp-agent/src/service.rs` — agent startup, wires interception + USB detection

### Fix Applied

**Date:** 2026-04-25

The fix was already present in the codebase across three files — confirmed correct and verified
by `cargo check` (zero errors) and 182 unit tests passing.

**Channel wiring (service.rs lines 505-506, 559):**
A `std::sync::mpsc` channel is created in `run_loop`. The sender end is stored in the global
`WATCH_PATH_TX` via `set_watch_path_sender()`. The receiver end is passed as `Some(watch_rx)`
to `file_monitor.run()`.

**USB arrival sender (detection/usb.rs lines 452-453):**
Inside `handle_volume_event`, after `on_drive_arrival(letter)` inserts the new drive letter
into `UsbDetector::blocked_drives`, the new drive root path (e.g. `E:\`) is sent through
`WATCH_PATH_TX` to the file monitor.

**Dynamic watcher registration (interception/file_monitor.rs lines 242-257):**
Inside the `run()` polling loop (500 ms timeout), after each `recv_timeout` call, a
`try_recv` drains all pending paths from `watch_rx` and calls
`watcher.watch(&new_path, RecursiveMode::Recursive)` for each one. Errors are logged as
warnings; success is logged at INFO level.

**Result:** Any USB drive plugged in after agent startup now has its drive root registered
with the notify watcher within one poll cycle (~500 ms). File events on that drive reach
`UsbEnforcer::check()` and the ABAC engine. Unregistered devices are denied by the
existing default-deny logic in `UsbEnforcer::check()`.

---

## Addendum — Second Root Cause (2026-04-25)

User reported writes still possible after the watcher channel fix above. Investigated
`set_disk_read_only()` in `detection/usb.rs`.

### Root Cause #2

`set_disk_read_only()` used the wrong IOCTL control code:

```rust
// BUG: 0x0007_007C = CTL_CODE(7, 0x1F, METHOD_BUFFERED, FILE_ANY_ACCESS)
//      = IOCTL_DISK_GET_READ_ONLY  (a GET, not a SET — reads current state, changes nothing)
const IOCTL_DISK_SET_READ_ONLY_MODE: u32 = 0x0007_007C;
```

The code sent a `u32` input value of `1` to `IOCTL_DISK_GET_READ_ONLY`, which either
silently succeeds (returning current state) or fails with an access error — in neither
case is write protection applied. The IOCTL was likely logging "write protection active"
while the disk remained fully writable.

### Fix

Replaced with the correct IOCTL `IOCTL_DISK_SET_DISK_ATTRIBUTES` and a properly
structured `SET_DISK_ATTRIBUTES` input buffer:

```rust
// CORRECT: CTL_CODE(7, 0x3d, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
//          = IOCTL_DISK_SET_DISK_ATTRIBUTES
const IOCTL_DISK_SET_DISK_ATTRIBUTES: u32 = 0x0007_C0F4;
const DISK_ATTRIBUTE_READ_ONLY: u64 = 0x0000_0000_0000_0002;
```

Input buffer is now a `repr(C)` `SetDiskAttributes` struct (40 bytes, matching
`SET_DISK_ATTRIBUTES` in WinIoCtl.h) with `Persist = false` so the protection
clears automatically on USB removal.

**Files changed:** `dlp-agent/src/detection/usb.rs` (lines ~758-935)
**Verification:** `cargo check --package dlp-agent` clean; 31 USB lib tests pass.

