# Phase 36: Disk Enforcement - Pattern Map

**Mapped:** 2026-05-04
**Files analyzed:** 7 (2 new, 5 modified)
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-agent/src/disk_enforcer.rs` | enforcer/service | request-response | `dlp-agent/src/usb_enforcer.rs` | exact |
| `dlp-agent/src/detection/device_watcher.rs` | dispatcher/middleware | event-driven | `dlp-agent/src/detection/usb.rs` (register_usb_notifications + usb_wndproc) | exact |
| `dlp-agent/src/detection/disk.rs` | service | event-driven + CRUD | `dlp-agent/src/detection/disk.rs` (existing) + `dlp-agent/src/detection/usb.rs` (arrival/removal handlers) | role-match |
| `dlp-agent/src/detection/mod.rs` | config | transform | `dlp-agent/src/detection/mod.rs` (existing) | exact |
| `dlp-agent/src/interception/mod.rs` | middleware | request-response | `dlp-agent/src/interception/mod.rs` (USB enforcement block, lines 86-162) | exact |
| `dlp-agent/src/service.rs` | config/wiring | CRUD | `dlp-agent/src/service.rs` (USB enforcer + DiskEnumerator wiring, lines 440-524, 635-648) | exact |
| `dlp-common/src/audit.rs` | model | transform | `dlp-common/src/audit.rs` (with_discovered_disks pattern, lines 326-330) | exact |

---

## Pattern Assignments

### `dlp-agent/src/disk_enforcer.rs` (new — enforcer, request-response)

**Analog:** `dlp-agent/src/usb_enforcer.rs`

**Imports pattern** (usb_enforcer.rs lines 32-42):
```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dlp_common::{Decision, DiskIdentity};
use parking_lot::Mutex;

use crate::detection::disk::{get_disk_enumerator};
use crate::interception::FileAction;
```
Note: `DiskEnforcer` does NOT inject `Arc<DiskEnumerator>` at construction — it calls `get_disk_enumerator()` internally (Claude's Discretion recommendation). No `detector` / `registry` fields needed.

**Struct + constructor pattern** (usb_enforcer.rs lines 67-88):
```rust
/// Result returned by [`DiskEnforcer::check`] when a fixed-disk operation is blocked.
///
/// Carries all data needed by the interception event loop to emit an audit event
/// and — when `notify` is true — broadcast a toast notification to the UI.
///
/// `notify` is `false` when a per-drive-letter 30-second cooldown is active.
/// The block decision (`Decision::DENY`) is always applied regardless of `notify`.
#[derive(Debug, Clone, PartialEq)]
pub struct DiskBlockResult {
    pub decision: Decision,
    pub disk: DiskIdentity,
    pub notify: bool,
}

pub struct DiskEnforcer {
    /// Per-drive-letter timestamp of the last toast broadcast.
    /// Used to enforce the 30-second cooldown (D-02).
    last_toast: Mutex<HashMap<char, Instant>>,
}

impl DiskEnforcer {
    pub fn new() -> Self {
        Self { last_toast: Mutex::new(HashMap::new()) }
    }
}
```

**`should_notify` cooldown pattern** (usb_enforcer.rs lines 93-107 — copy verbatim, change arg name):
```rust
fn should_notify(&self, drive: char) -> bool {
    const COOLDOWN: Duration = Duration::from_secs(30);
    let mut map = self.last_toast.lock();
    let now = Instant::now();
    // `is_none_or` treats a missing entry as "expired" so the first call always
    // returns true. `duration_since` is safe here because `now` is always >= stored
    // `last`; both are monotonic `Instant` values from the same clock.
    let expired = map
        .get(&drive)
        .is_none_or(|last| now.duration_since(*last) >= COOLDOWN);
    if expired {
        map.insert(drive, now);
    }
    expired
}
```

**`check` method signature + action filter** (CONTEXT.md D-03/D-04; interception/mod.rs FileAction variants):
```rust
#[must_use]
pub fn check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult> {
    // D-04: only intercept write-path actions
    if !matches!(
        action,
        FileAction::Created { .. } | FileAction::Written { .. } | FileAction::Moved { .. }
    ) {
        return None;
    }
    // ... compound allowlist logic per D-06/D-07 ...
}
```

**Drive letter extraction helper** (usb_enforcer.rs lines 202-213 — identical logic):
```rust
fn drive_letter_from_path(path: &str) -> Option<char> {
    // UNC paths start with `\\` — they are never local fixed drives.
    if path.starts_with("\\\\") {
        return None;
    }
    let first = path.chars().next()?;
    if first.is_ascii_alphabetic() {
        Some(first.to_ascii_uppercase())
    } else {
        None
    }
}
```
This function already exists as `extract_drive_letter` in `usb_enforcer.rs`. Copy it (or re-export) into `disk_enforcer.rs` under the name `drive_letter_from_path`.

**Fail-closed and allowlist check** (CONTEXT.md specifics pseudocode — enumerate_complete gate then compound check):
```rust
let enumerator = match get_disk_enumerator() {
    Some(e) => e,
    None => {
        // Enumerator not yet initialized — treat as !is_ready() (D-06 fail-closed).
        let letter = drive_letter_from_path(path).unwrap_or('?');
        return Some(DiskBlockResult {
            decision: Decision::DENY,
            disk: DiskIdentity { drive_letter: Some(letter), ..Default::default() },
            notify: self.should_notify(letter),
        });
    }
};

if !enumerator.is_ready() {
    let letter = drive_letter_from_path(path).unwrap_or('?');
    return Some(DiskBlockResult {
        decision: Decision::DENY,
        disk: DiskIdentity { drive_letter: Some(letter), ..Default::default() },
        notify: self.should_notify(letter),
    });
}

let letter = drive_letter_from_path(path)?;
// None from disk_for_drive_letter = not a fixed disk we track => pass through (D-07 step 2)
let live_disk = enumerator.disk_for_drive_letter(letter)?;

let registered = enumerator.disk_for_instance_id(&live_disk.instance_id);

// D-07 step 4: serial mismatch closes physical-swap bypass
let serial_mismatch = registered.as_ref()
    .and_then(|r| r.serial.as_ref())
    .zip(live_disk.serial.as_ref())
    .map(|(stored, live)| stored != live)
    .unwrap_or(false);

if registered.is_none() || serial_mismatch {
    return Some(DiskBlockResult {
        decision: Decision::DENY,
        disk: live_disk,
        notify: self.should_notify(letter),
    });
}

None  // Allowlisted — fall through to ABAC
```

**Test module structure** (usb_enforcer.rs lines 215-551 — same Arrange-Act-Assert pattern):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{BusType, DiskIdentity};

    // Helper: build a DiskEnumerator pre-seeded with specific maps for unit testing.
    // Mirror make_detector() pattern from usb_enforcer.rs tests.

    #[test]
    fn test_read_action_returns_none() { ... }            // DISK-04
    #[test]
    fn test_write_blocked_when_not_ready() { ... }        // D-06 fail-closed
    #[test]
    fn test_write_blocked_when_enumerator_absent() { ... } // D-06 enumerator None
    #[test]
    fn test_path_not_in_drive_letter_map_passes() { ... } // D-07 step 2
    #[test]
    fn test_unregistered_disk_blocked() { ... }           // D-07 step 3
    #[test]
    fn test_serial_mismatch_blocked() { ... }             // D-07 step 4
    #[test]
    fn test_allowlisted_disk_passes() { ... }             // D-07 all pass
    #[test]
    fn test_should_notify_cooldown() { ... }              // D-02 cooldown
    #[test]
    fn test_unc_path_returns_none() { ... }               // UNC guard
}
```

---

### `dlp-agent/src/detection/device_watcher.rs` (new — dispatcher, event-driven)

**Analog:** `dlp-agent/src/detection/usb.rs` — `register_usb_notifications` (lines 1020-1198) + `usb_wndproc` (lines 359-444) + `read_dbcc_name` (lines 458-469)

**Module-level statics pattern** (usb.rs lines 245-315 — DRIVE_DETECTOR, NOTIFY_HANDLES global statics):
```rust
// Thread-affine: message loop references these statics; set before spawning thread.
static NOTIFY_HANDLES: parking_lot::Mutex<Option<(isize, isize, isize)>> =
    parking_lot::Mutex::new(None);
// (No detector raw pointer needed — device_watcher dispatches to module functions
//  which call get_disk_enumerator() / get_usb_detector() internally.)
```

**Window class registration + HWND channel pattern** (usb.rs lines 1035-1079):
```rust
pub fn spawn_device_watcher_task(
    audit_ctx: crate::audit_emitter::EmitContext,
) -> windows::core::Result<(HWND, std::thread::JoinHandle<()>)> {
    let (hwnd_tx, hwnd_rx) = std::sync::mpsc::channel::<windows::core::Result<usize>>();

    let thread = std::thread::Builder::new()
        .name("device-watcher".into())  // renamed from "usb-notification"
        .spawn(move || {
            // Step 1: RegisterClassW with device_watcher_wndproc
            let class_name: Vec<u16> = "DlpDeviceWatcherWindow\0".encode_utf16().collect();
            let wc = WNDCLASSW {
                lpfnWndProc: Some(device_watcher_wndproc),
                lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            let atom = unsafe { RegisterClassW(&wc) };
            // ... error handling per usb.rs pattern ...

            // Step 2: CreateWindowExW (message-only window)
            let hwnd = match unsafe {
                CreateWindowExW(WS_EX_NOACTIVATE, ..., None, ...)
            } { ... };

            // Step 3a: RegisterDeviceNotificationW for GUID_DEVINTERFACE_VOLUME
            // Step 3b: RegisterDeviceNotificationW for GUID_DEVINTERFACE_USB_DEVICE
            // Step 3c: RegisterDeviceNotificationW for GUID_DEVINTERFACE_DISK
            // (same 3-notification pattern as usb.rs lines 1081-1158)

            *NOTIFY_HANDLES.lock() = Some((vol_h.0 as isize, usb_h.0 as isize, disk_h.0 as isize));
            let _ = hwnd_tx.send(Ok(hwnd.0 as usize));

            // Step 4: GetMessageW message loop (thread-affine)
            let mut msg = MSG::default();
            loop {
                let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                if ret.0 == 0 { break; }
                let _ = unsafe { TranslateMessage(&msg) };
                let _ = unsafe { DispatchMessageW(&msg) };
            }
        })
        .expect("device-watcher thread must spawn");

    let hwnd_raw = hwnd_rx.recv().expect("...")?;
    let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);
    Ok((hwnd, thread))
}
```

**Dispatcher wndproc pattern** (usb.rs lines 359-444 — classguid dispatch):
```rust
#[cfg(windows)]
unsafe extern "system" fn device_watcher_wndproc(
    hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        WM_DEVICECHANGE => {
            let event_type = wparam.0 as u32;
            if (event_type == DBT_DEVICEARRIVAL || event_type == DBT_DEVICEREMOVECOMPLETE)
                && lparam.0 != 0
            {
                // SAFETY: lparam points to a DEV_BROADCAST_HDR produced by the OS;
                // valid for the duration of this callback.
                let hdr = unsafe { &*(lparam.0 as *const DEV_BROADCAST_HDR) };
                if hdr.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE {
                    let di = unsafe { &*(lparam.0 as *const DEV_BROADCAST_DEVICEINTERFACE_W) };
                    let classguid = di.dbcc_classguid;

                    if classguid == GUID_DEVINTERFACE_VOLUME {
                        // Re-scan drive letters for USB volume tracking (existing behavior).
                        // Delegate to usb::handle_volume_event or equivalent.
                    } else if classguid == GUID_DEVINTERFACE_USB_DEVICE {
                        let device_path = unsafe { read_dbcc_name(di) };
                        if event_type == DBT_DEVICEARRIVAL {
                            crate::detection::usb::on_usb_device_arrival(..., &device_path);
                            // registry cache refresh — same REGISTRY_RUNTIME_HANDLE pattern
                        } else {
                            crate::detection::usb::on_usb_device_removal(..., &device_path);
                        }
                    } else if classguid == GUID_DEVINTERFACE_DISK {
                        // SAFETY: di is valid for this callback duration.
                        let device_path = unsafe { read_dbcc_name(di) };
                        if event_type == DBT_DEVICEARRIVAL {
                            crate::detection::disk::on_disk_arrival(&device_path, &audit_ctx);
                        } else {
                            crate::detection::disk::on_disk_removal(&device_path);
                        }
                    }
                }
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}
```

**`read_dbcc_name` helper** (usb.rs lines 458-469 — move this function to device_watcher.rs):
```rust
// SAFETY: di must point to a live DEV_BROADCAST_DEVICEINTERFACE_W with valid
// dbcc_name data. The OS guarantees this for the duration of WM_DEVICECHANGE.
unsafe fn read_dbcc_name(di: &DEV_BROADCAST_DEVICEINTERFACE_W) -> String {
    let base = di.dbcc_name.as_ptr();
    let mut len = 0usize;
    while unsafe { *base.add(len) } != 0 && len < 32_768 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(base, len) };
    String::from_utf16_lossy(slice)
}
```

**`extract_disk_instance_id` helper** (usb.rs lines 739-743 — move to device_watcher.rs, renamed):
```rust
/// Extracts the device instance ID from a GUID_DEVINTERFACE_DISK dbcc_name.
///
/// Input:  `\\?\USBSTOR#Disk&Ven_Kingston#...#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`
/// Output: `USBSTOR\Disk&Ven_Kingston\...`
pub fn extract_disk_instance_id(device_path: &str) -> String {
    let without_prefix = device_path.strip_prefix(r"\\?\").unwrap_or(device_path);
    let without_guid = without_prefix.split("#{").next().unwrap_or(without_prefix);
    without_guid.replace("#", r"\")
}
```

**Unregister / cleanup pattern** (usb.rs lines 1206-1230 — copy verbatim, rename function):
```rust
pub fn unregister_device_watcher(hwnd: HWND, thread: std::thread::JoinHandle<()>) {
    if let Some((h_vol, h_usb, h_disk)) = NOTIFY_HANDLES.lock().take() {
        unsafe {
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_vol as *mut _));
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_usb as *mut _));
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_disk as *mut _));
        }
    }
    // ... PostMessageW(WM_CLOSE) + thread.join() + DestroyWindow pattern
}
```

---

### `dlp-agent/src/detection/disk.rs` (modified — add on_disk_arrival + on_disk_removal)

**Analog:** `dlp-agent/src/detection/usb.rs` lines 752-871 (`on_disk_device_arrival`) and lines 876-950+ (`on_disk_device_removal`) for structural shape; disk.rs existing patterns for map writes.

**`on_disk_arrival` function signature and pattern** (D-13):
```rust
/// Handles GUID_DEVINTERFACE_DISK arrival for DiskEnforcer drive_letter_map maintenance.
///
/// Resolves the drive letter for the arrived disk, updates drive_letter_map (D-10),
/// and emits a DiskDiscovery audit event if the disk is unregistered (D-13).
///
/// NOTE: does NOT touch instance_id_map (D-09/D-10 invariant — frozen allowlist).
///
/// # Arguments
/// * `device_path` - The dbcc_name from the WM_DEVICECHANGE callback.
/// * `audit_ctx` - EmitContext for audit emission (DiskDiscovery on unregistered arrival).
#[cfg(windows)]
pub fn on_disk_arrival(device_path: &str, audit_ctx: &crate::audit_emitter::EmitContext) {
    // 1. Enumerate fixed disks to find the newly visible drive letter.
    //    Use enumerate_fixed_disks() — the recommended approach per Claude's
    //    Discretion — because it produces instance IDs in exactly the form
    //    stored in instance_id_map (SetupDiGetDeviceInstanceIdW format),
    //    avoiding the GUID_DEVINTERFACE_DISK dbcc_name format mismatch (Pitfall 1).
    let Ok(live_disks) = enumerate_fixed_disks() else {
        warn!("on_disk_arrival: enumerate_fixed_disks failed — skipping map update");
        return;
    };

    let enumerator = match get_disk_enumerator() {
        Some(e) => e,
        None => {
            warn!("on_disk_arrival: DiskEnumerator not yet initialized");
            return;
        }
    };

    // 2. Find disks not already in drive_letter_map (newly visible).
    let existing_letters: HashSet<char> = enumerator.drive_letter_map.read().keys().copied().collect();
    for disk in live_disks {
        let Some(letter) = disk.drive_letter else { continue; };
        if existing_letters.contains(&letter) { continue; } // already tracked

        // 3. Update drive_letter_map only (D-10 — instance_id_map is NOT touched).
        enumerator.drive_letter_map.write().insert(letter, disk.clone());
        info!(drive = %letter, instance_id = %disk.instance_id, "disk arrived — drive_letter_map updated");

        // 4. Check if instance_id is in allowlist (instance_id_map = frozen allowlist D-09).
        if enumerator.disk_for_instance_id(&disk.instance_id).is_none() {
            // Unregistered disk — emit DiskDiscovery audit event immediately (D-13).
            warn!(
                drive = %letter,
                instance_id = %disk.instance_id,
                model = %disk.model,
                "unregistered disk arrived — emitting DiskDiscovery audit"
            );
            // Reuse emit_disk_discovery helper pattern from disk.rs lines 318-335.
            emit_disk_discovery_for_arrival(audit_ctx, &disk);
        } else {
            info!(drive = %letter, instance_id = %disk.instance_id, "registered disk reconnected");
        }
    }
}
```

**`on_disk_removal` function pattern** (D-14):
```rust
/// Handles GUID_DEVINTERFACE_DISK removal by removing the departed disk from
/// drive_letter_map only. Does NOT touch instance_id_map (D-10).
///
/// # Arguments
/// * `device_path` - The dbcc_name from the WM_DEVICECHANGE callback.
#[cfg(windows)]
pub fn on_disk_removal(device_path: &str) {
    // Note: extract_disk_instance_id is in device_watcher.rs after the refactor.
    let instance_id = crate::detection::device_watcher::extract_disk_instance_id(device_path);
    if instance_id.is_empty() {
        debug!("disk removal: empty instance ID — skipping");
        return;
    }

    let enumerator = match get_disk_enumerator() {
        Some(e) => e,
        None => return,
    };

    // Find and remove the entry from drive_letter_map whose instance_id matches.
    let letter_opt = {
        let map = enumerator.drive_letter_map.read();
        map.iter()
            .find(|(_, disk)| disk.instance_id == instance_id)
            .map(|(letter, _)| *letter)
    };

    if let Some(letter) = letter_opt {
        enumerator.drive_letter_map.write().remove(&letter);
        info!(
            drive = %letter,
            instance_id = %instance_id,
            "disk removed — drive_letter_map entry cleared (instance_id_map unchanged)"
        );
    } else {
        debug!(instance_id = %instance_id, "disk removal: instance_id not in drive_letter_map");
    }
    // D-14: No audit event on removal. D-10: instance_id_map NOT touched.
}
```

**DiskDiscovery emission helper for arrival** (mirrors disk.rs lines 318-335 `emit_disk_discovery`):
```rust
// Private helper: emit a DiskDiscovery event for a single unregistered arrival disk.
fn emit_disk_discovery_for_arrival(
    ctx: &crate::audit_emitter::EmitContext,
    disk: &DiskIdentity,
) {
    use dlp_common::{Action, AuditEvent, Classification, Decision, EventType};
    let mut event = AuditEvent::new(
        EventType::DiskDiscovery,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        "disk://arrival".to_string(),
        Classification::T1,
        Action::READ,
        Decision::ALLOW,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_discovered_disks(Some(vec![disk.clone()]));
    crate::audit_emitter::emit_audit(ctx, &mut event);
}
```

---

### `dlp-agent/src/detection/mod.rs` (modified — add device_watcher module)

**Analog:** `dlp-agent/src/detection/mod.rs` lines 11-26 (existing pub mod + pub use pattern)

**Pattern** (lines 11-26):
```rust
// Existing:
pub mod disk;
pub mod encryption;
pub mod network_share;
pub mod usb;

pub use disk::{get_disk_enumerator, set_disk_enumerator, spawn_disk_enumeration_task, DiskEnumerator};
// ...

// ADD:
pub mod device_watcher;
pub use device_watcher::spawn_device_watcher_task;
// (and unregister_device_watcher if needed at shutdown in service.rs)
```

---

### `dlp-agent/src/interception/mod.rs` (modified — add disk_enforcer parameter + block)

**Analog:** `dlp-agent/src/interception/mod.rs` lines 59-162 — USB enforcer parameter + block (exact copy pattern for disk enforcer).

**Function signature addition** (lines 59-65 — add `disk_enforcer` parameter after `usb_enforcer`):
```rust
pub async fn run_event_loop(
    mut rx: mpsc::Receiver<FileAction>,
    offline: Arc<OfflineManager>,
    ctx: EmitContext,
    session_map: Arc<SessionIdentityMap>,
    ad_client: Arc<Option<dlp_common::AdClient>>,
    usb_enforcer: Option<Arc<UsbEnforcer>>,
    disk_enforcer: Option<Arc<DiskEnforcer>>,   // ADD: Phase 36
) {
```

**Import to add** (lines 25-41 block — add after UsbEnforcer import):
```rust
use crate::disk_enforcer::DiskEnforcer;
```

**Disk enforcement block** (insert after USB enforcement block, lines 162-163, before `let abac_action = PolicyMapper::action_for(&action)`):
```rust
// ── Disk enforcement (pre-ABAC check) ────────────────────────────────
// Fires before the ABAC engine. Unregistered fixed-disk writes short-circuit
// here with a Block audit event (DISK-04, Phase 36).
if let Some(ref enforcer) = disk_enforcer {
    if let Some(disk_result) = enforcer.check(&path, &action) {
        let mut audit_event = AuditEvent::new(
            EventType::Block,
            user_sid.clone(),
            user_name.clone(),
            path.clone(),
            // Classification not yet resolved; T1 is conservative placeholder.
            dlp_common::Classification::T1,
            dlp_common::Action::WRITE,
            disk_result.decision,
            ctx.agent_id.clone(),
            ctx.session_id,
        )
        .with_access_context(AuditAccessContext::Local)
        .with_policy(
            String::new(),
            "Disk enforcement: unregistered fixed disk".to_string(),
        )
        .with_blocked_disk(disk_result.disk.clone());  // AUDIT-02

        emit_audit(&ctx, &mut audit_event);

        if disk_result.notify {
            crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast {
                title: "Unregistered Disk Blocked".to_string(),
                body: format!(
                    "{} ({}:) - this disk is not registered",
                    disk_result.disk.model,
                    disk_result.disk.drive_letter.unwrap_or('?')
                ),
            });
        }
        continue; // skip ABAC evaluation for this event
    }
}
```
Note: The toast message uses `-` (ASCII hyphen) not `—` (em dash) to comply with CLAUDE.md "NEVER use emoji or unicode that emulates emoji" and to avoid non-ASCII in string literals.

---

### `dlp-agent/src/service.rs` (modified — wire DiskEnforcer + device_watcher spawn)

**Analog:** `dlp-agent/src/service.rs` lines 498-524 (UsbEnforcer construction + register_usb_notifications call)

**DiskEnforcer construction pattern** (insert after disk_enumerator setup, lines 640-648):
```rust
// ── DiskEnforcer (Phase 36, DISK-04) ─────────────────────────────────────
// Constructed after set_disk_enumerator() so get_disk_enumerator() is available
// on first I/O event. DiskEnforcer wraps the global static internally.
let disk_enforcer_opt: Option<Arc<crate::disk_enforcer::DiskEnforcer>> =
    Some(Arc::new(crate::disk_enforcer::DiskEnforcer::new()));
```

**device_watcher spawn (replace register_usb_notifications)** (after UsbEnforcer construction, lines 507-524):
```rust
// ── Device watcher (Phase 36) — replaces register_usb_notifications ─────────
// spawn_device_watcher_task owns the hidden Win32 window + WM_DEVICECHANGE loop.
// Dispatches USB events to usb::on_usb_device_arrival/removal,
// disk events to disk::on_disk_arrival/removal.
let device_watcher_cleanup = match crate::detection::device_watcher::spawn_device_watcher_task(
    audit_ctx.clone(),
) {
    Ok((hwnd, thread)) => {
        info!(thread_id = ?thread.thread().id(), "device watcher registered");
        Some((hwnd, thread))
    }
    Err(e) => {
        warn!(
            error = %e,
            "device watcher unavailable — continuing without device monitoring"
        );
        None
    }
};
```

**run_event_loop call site** (line ~678 — add disk_enforcer_opt argument):
```rust
crate::interception::run_event_loop(
    rx,
    Arc::clone(&offline),
    ctx_ev,
    session_map_ev,
    ad_client_ev,
    usb_enforcer_opt,
    disk_enforcer_opt,   // ADD: Phase 36
)
.await;
```

**Shutdown cleanup** (lines 782-787 — mirror USB cleanup for device_watcher):
```rust
if let Some((hwnd, thread)) = device_watcher_cleanup {
    crate::detection::device_watcher::unregister_device_watcher(hwnd, thread);
}
```

---

### `dlp-common/src/audit.rs` (modified — add blocked_disk field + builder)

**Analog:** `dlp-common/src/audit.rs` lines 181-183 and 326-330 (`discovered_disks` field + `with_discovered_disks` builder — exact same pattern)

**Field addition in AuditEvent struct** (after `discovered_disks` field, line 183):
```rust
/// Discovered fixed disks emitted during agent startup disk enumeration
/// (populated by Phase 33 disk discovery).
#[serde(skip_serializing_if = "Option::is_none")]
pub discovered_disks: Option<Vec<DiskIdentity>>,
/// Fixed disk identity on block events from DiskEnforcer (AUDIT-02, Phase 36).
/// Populated only for EventType::Block events where a fixed disk was blocked.
/// Semantically distinct from discovered_disks (enumeration at startup).
#[serde(skip_serializing_if = "Option::is_none")]
pub blocked_disk: Option<DiskIdentity>,
```

**Constructor initialization** (in `AuditEvent::new()`, lines 213-240 — add to initializer block):
```rust
discovered_disks: None,
blocked_disk: None,   // ADD: Phase 36
```

**Builder method** (after `with_discovered_disks`, lines 326-330):
```rust
/// Sets the blocked disk identity on disk enforcement block events (AUDIT-02, Phase 36).
///
/// # Arguments
///
/// * `disk` — the [`DiskIdentity`] from `drive_letter_map` at enforcement time.
///
/// # Returns
///
/// `self` with `blocked_disk` set to `Some(disk)`.
pub fn with_blocked_disk(mut self, disk: DiskIdentity) -> Self {
    self.blocked_disk = Some(disk);
    self
}
```

**Test additions** (following audit.rs test module pattern, lines 333-725 — backward compat tests):
```rust
#[test]
fn test_audit_event_with_blocked_disk() { ... }            // AUDIT-02 field populated
#[test]
fn test_blocked_disk_json_contains_identity_fields() { ... } // AUDIT-02 JSON fields
#[test]
fn test_skip_serializing_none_blocked_disk() { ... }       // skip_serializing_if
#[test]
fn test_backward_compat_missing_blocked_disk() { ... }     // legacy JSON deserializes to None
```

---

## Shared Patterns

### `parking_lot::Mutex<HashMap<char, Instant>>` — per-drive toast cooldown
**Source:** `dlp-agent/src/usb_enforcer.rs` lines 72-107
**Apply to:** `DiskEnforcer` (copy verbatim — identical use case)
```rust
last_toast: Mutex<HashMap<char, Instant>>,

fn should_notify(&self, drive: char) -> bool {
    const COOLDOWN: Duration = Duration::from_secs(30);
    let mut map = self.last_toast.lock();
    let now = Instant::now();
    let expired = map
        .get(&drive)
        .is_none_or(|last| now.duration_since(*last) >= COOLDOWN);
    if expired { map.insert(drive, now); }
    expired
}
```

### `Option<Arc<T>>` enforcer parameter — pre-ABAC short-circuit
**Source:** `dlp-agent/src/interception/mod.rs` lines 64-65, 89-162
**Apply to:** `disk_enforcer: Option<Arc<DiskEnforcer>>` in `run_event_loop`
Pattern: `if let Some(ref enforcer) = disk_enforcer { if let Some(result) = enforcer.check(...) { ... continue; } }`

### `#[serde(skip_serializing_if = "Option::is_none")]` — backward-compatible optional audit fields
**Source:** `dlp-common/src/audit.rs` lines 122-183
**Apply to:** `blocked_disk` field on `AuditEvent`
```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub blocked_disk: Option<DiskIdentity>,
```

### `emit_audit` + AuditEvent builder chain — audit event emission
**Source:** `dlp-agent/src/detection/disk.rs` lines 318-358 (`emit_disk_discovery`)
**Apply to:** `emit_disk_discovery_for_arrival` in disk.rs, disk block emission in interception/mod.rs
```rust
let mut event = AuditEvent::new(EventType::Block, ...)
    .with_access_context(AuditAccessContext::Local)
    .with_policy(...)
    .with_blocked_disk(disk);
emit_audit(&ctx, &mut event);
```

### Win32 thread-affine message loop — `std::thread` + HWND channel
**Source:** `dlp-agent/src/detection/usb.rs` lines 1020-1197
**Apply to:** `device_watcher.rs::spawn_device_watcher_task`
Key invariants:
- Window MUST be created and message loop MUST run on the same `std::thread`
- HWND transmitted as `usize` via `mpsc::channel` (HWND is `!Send`)
- All async work scheduled via stored `tokio::runtime::Handle` (never block the message loop)
- `DEV_BROADCAST_DEVICEINTERFACE_W.dbcc_name` extracted synchronously in the callback via `read_dbcc_name`

### `#[must_use]` on check methods returning `Option`
**Source:** `dlp-agent/src/usb_enforcer.rs` line 129, `dlp-agent/src/detection/disk.rs` lines 69, 77, 86
**Apply to:** `DiskEnforcer::check()` — the caller MUST NOT ignore the Option

### `// SAFETY:` comment on every `unsafe` block
**Source:** `dlp-agent/src/detection/usb.rs` lines 379-386, 1048-1094
**Apply to:** All `unsafe` blocks in `device_watcher.rs` — mandatory per CLAUDE.md §9.10

### `tracing::warn!` with structured fields for block events
**Source:** `dlp-agent/src/interception/mod.rs` lines 129-135
**Apply to:** `DiskEnforcer::check` (log the block), `on_disk_arrival` (log unregistered arrival)
```rust
warn!(
    drive = %letter,
    instance_id = %live_disk.instance_id,
    model = %live_disk.model,
    "disk write blocked: unregistered fixed disk"
);
```

---

## No Analog Found

All 7 files have close analogs. No file requires falling back to RESEARCH.md patterns only.

---

## Metadata

**Analog search scope:** `dlp-agent/src/`, `dlp-common/src/`
**Files scanned:** 9 source files read in full (usb_enforcer.rs, audit.rs, disk.rs, usb.rs, interception/mod.rs, service.rs, detection/mod.rs) plus targeted grep passes
**Pattern extraction date:** 2026-05-04
