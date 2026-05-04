# Phase 36: Disk Enforcement - Context

**Gathered:** 2026-05-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Agent blocks I/O to unregistered fixed disks at runtime via a pre-ABAC `DiskEnforcer` in `run_event_loop`, and keeps `DiskEnumerator` in sync with hot-plug arrivals and removals. The `WM_DEVICECHANGE` message loop is refactored from `usb.rs` into a new `device_watcher.rs` dispatcher. Covers DISK-04, DISK-05, AUDIT-02.

**In scope:**
- `DiskEnforcer` struct with per-drive toast cooldown — blocks `FileAction::Create/Write/Move` to unregistered fixed disks
- Compound allowlist check: `instance_id` + serial number (when available) — closes physical-swap bypass
- `instance_id_map` frozen as allowlist after startup; `drive_letter_map` updated by arrivals
- `device_watcher.rs` — new module owning the Win32 hidden window + `WM_DEVICECHANGE` dispatcher
- `disk::on_disk_arrival()` / `on_disk_removal()` handlers in `disk.rs`
- `DiskDiscovery` audit event on unregistered disk arrival (immediate, before any write)
- `blocked_disk: Option<DiskIdentity>` field on `AuditEvent` (AUDIT-02)

**Out of scope:**
- Server-side disk registry (Phase 37)
- Admin TUI disk registry (Phase 38)
- Per-disk trust tiers (DISK-F4 — deferred)
- Mount-time volume locking (DISK-F1 — deferred)
- Toast notification content design beyond "Unregistered disk blocked" (no spec yet)
- Updating `instance_id_map` at runtime — admin adds disks only via Phase 37/38

</domain>

<decisions>
## Implementation Decisions

### DiskEnforcer struct
- **D-01:** `DiskEnforcer` lives in a new `dlp-agent/src/disk_enforcer.rs`, mirroring `usb_enforcer.rs`. It is passed as `Option<Arc<DiskEnforcer>>` into `run_event_loop` alongside the existing `usb_enforcer` parameter.
- **D-02:** `DiskEnforcer` is stateful — it carries `last_toast: parking_lot::Mutex<HashMap<char, Instant>>` for a 30-second per-drive toast cooldown, identical to `UsbEnforcer`. The block decision is always applied regardless of toast cooldown.
- **D-03:** `DiskEnforcer::check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult>`. Returns `Some(DiskBlockResult)` when a block fires; `None` when the path is allowed, is not on a fixed disk, or the action is not a write-path operation.
- **D-04:** Blocked action filter: `FileAction::Create / Write / Move` only. `FileAction::Read` is allowed even on unregistered disks. Matches DISK-04 spec exactly.
- **D-05:** `DiskBlockResult` carries `decision: Decision` and `disk: DiskIdentity` (the live identity from `drive_letter_map` — used to populate `blocked_disk` in the audit event).

### Enforcement logic (allowlist check)
- **D-06:** When `enumeration_complete = false` (startup window ~4s, or all 3 retries exhausted), `DiskEnforcer::check()` blocks ALL fixed-disk writes. True fail-closed — consistent with Phase 33 D-04. No unregistered disk can slip through the startup window.
- **D-07:** Compound allowlist check (in order):
  1. Extract drive letter from path (first ASCII alpha character).
  2. Look up `drive_letter_map[letter]` → live `DiskIdentity`. If `None` → path is not on a known fixed disk → pass through (not our concern).
  3. Check if `live_disk.instance_id` is a key in `instance_id_map` (the frozen allowlist). If absent → block.
  4. If present, and both `instance_id_map[instance_id].serial` and `live_disk.serial` are `Some(...)`, verify they are equal. If mismatch → block (physical-swap attack detected).
  5. If all checks pass → `None` (allow through to ABAC).
- **D-08:** The `is_boot_disk = true` path: boot disks are always present in `instance_id_map` (auto-allowlisted by Phase 33 D-15). No special boot-disk logic needed in `DiskEnforcer` — the allowlist check naturally allows them.

### Allowlist map semantics (critical invariant)
- **D-09:** `DiskEnumerator.instance_id_map` is a **frozen allowlist** once `enumeration_complete = true`. It is populated exclusively by `spawn_disk_enumeration_task` (TOML pre-load + live merge at startup). Post-startup hot-plug arrivals **never** update `instance_id_map`. Only Phase 37/38 admin operations add new entries.
- **D-10:** `DiskEnumerator.drive_letter_map` is the **live current state**. Updated by `disk::on_disk_arrival()` (add/update entry for the arrived disk's drive letter) and `disk::on_disk_removal()` (remove entry for the departed disk's drive letter). `instance_id_map` is NOT touched by either handler.
- **D-11:** The separation between D-09 and D-10 closes the physical-swap bypass: if an attacker swaps in a different disk into the same port slot (same `instance_id`, different serial), `drive_letter_map` is updated with the attacker's serial while `instance_id_map` retains the registered serial → serial mismatch → blocked.

### Device arrival/removal (WM_DEVICECHANGE refactor)
- **D-12:** New `dlp-agent/src/detection/device_watcher.rs` takes ownership of the hidden Win32 window and `WM_DEVICECHANGE` message loop, refactored out of `usb.rs`. The dispatcher calls:
  - `usb::on_usb_device_arrival/removal()` for `GUID_DEVINTERFACE_USB_DEVICE` events
  - `disk::on_disk_arrival/removal()` for `GUID_DEVINTERFACE_DISK` events
  `usb.rs` retains its USB-specific handler logic but no longer owns the window infrastructure.
- **D-13:** `disk::on_disk_arrival(device_path: &str, audit_ctx: &EmitContext)` in `dlp-agent/src/detection/disk.rs`:
  1. Resolve `instance_id` from the `GUID_DEVINTERFACE_DISK` `dbcc_name` (reuse existing `extract_disk_instance_id` helper in `usb.rs`).
  2. Look up the drive letter for the arrived instance ID (via `enumerate_fixed_disks()` or a targeted query — planner's choice).
  3. Update `drive_letter_map` only (D-10).
  4. Check if `instance_id` is in `instance_id_map`. If **not** → emit `DiskDiscovery` audit event immediately (unregistered disk plugged in). If **yes** → update drive letter silently (registered disk reconnected).
- **D-14:** `disk::on_disk_removal(device_path: &str)` in `disk.rs`:
  1. Resolve `instance_id` from `dbcc_name`.
  2. Remove the corresponding entry from `drive_letter_map` (D-10).
  3. Do NOT touch `instance_id_map` — disconnected allowlisted disks remain registered per Phase 35 D-06.
  4. No audit event on removal (removal of a known disk is informational; the disk remains in the allowlist).

### AuditEvent disk block identity (AUDIT-02)
- **D-15:** Add `blocked_disk: Option<DiskIdentity>` to `AuditEvent` in `dlp-common/src/audit.rs`. Populated for `EventType::Block` events emitted by `DiskEnforcer`. Semantically distinct from `discovered_disks` (enumeration) — SIEM rules can filter `event_type = BLOCK AND blocked_disk IS NOT NULL` for disk enforcement events.
- **D-16:** `blocked_disk` carries the full `DiskIdentity` from `drive_letter_map` at enforcement time: `instance_id`, `bus_type`, `model`, `drive_letter`, `serial`. Satisfies AUDIT-02 field requirements.

### Claude's Discretion
- Exact method for resolving drive letter for a newly arrived disk in `on_disk_arrival()` — recommended: call `enumerate_fixed_disks()` filtered to the arrived `instance_id`, since a full WMI query is already proven; alternatively, use `GetVolumePathNamesForVolumeNameW` if a targeted approach is preferred.
- Whether `DiskEnforcer` wraps `get_disk_enumerator()` internally or receives an `Arc<DiskEnumerator>` at construction — recommended: wrap the global static internally (same as `UsbEnforcer` wraps its injected caches), consistent with how `service.rs` wires enforcer instances.
- Whether `on_disk_removal()` emits a `tracing::info!` log line for the removal — recommended: yes, one structured line for operational visibility.
- Exact toast message text for disk block — recommended: title `"Unregistered Disk Blocked"`, body `"{model} ({drive_letter}:) — this disk is not registered"`.
- Whether `extract_disk_instance_id` is moved from `usb.rs` to `device_watcher.rs` or kept in `usb.rs` as a shared helper — recommended: move to `device_watcher.rs` since it parses `GUID_DEVINTERFACE_DISK` dbcc_name, not USB-specific.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements and Roadmap
- `.planning/ROADMAP.md` — Phase 36 goal, success criteria (4 items), depends-on Phase 35
- `.planning/REQUIREMENTS.md` — DISK-04, DISK-05, AUDIT-02 definitions; deferred DISK-F1/F4
- `.planning/PROJECT.md` — Architecture, tech stack, key design decisions

### Prior Phase Context (data models and patterns)
- `.planning/phases/33-disk-enumeration/33-CONTEXT.md` — `DiskIdentity` schema (D-10), `BusType`, boot disk auto-allowlist (D-15), `DiskEnumerator` pattern, fail-closed semantics (D-04)
- `.planning/phases/34-bitlocker-verification/34-CONTEXT.md` — encryption fields on `DiskIdentity`; why `instance_id_map` can carry `encryption_status` (D-20)
- `.planning/phases/35-disk-allowlist-persistence/35-CONTEXT.md` — `instance_id_map` IS the allowlist (D-10), `enumeration_complete` readiness flag (D-12), frozen-allowlist invariant, disconnected disk retention (D-06), merge algorithm

### Key Source Files (read before touching)
- `dlp-agent/src/detection/disk.rs` — `DiskEnumerator` struct fields (`instance_id_map`, `drive_letter_map`, `enumeration_complete`), `get_disk_enumerator()` / `set_disk_enumerator()`, `spawn_disk_enumeration_task` (Phase 35 implementation — shows how maps are populated)
- `dlp-agent/src/detection/usb.rs` — `usb_wndproc` (hidden window + `WM_DEVICECHANGE` loop to be extracted to `device_watcher.rs`), `on_disk_device_arrival` / `on_disk_device_removal` (existing handlers to be superseded), `extract_disk_instance_id` (helper to move to `device_watcher.rs`), `GUID_DEVINTERFACE_DISK` constant
- `dlp-agent/src/usb_enforcer.rs` — `UsbEnforcer`, `UsbBlockResult`, `should_notify()` 30s cooldown — direct template for `DiskEnforcer`
- `dlp-agent/src/interception/mod.rs` — `run_event_loop` (add `disk_enforcer: Option<Arc<DiskEnforcer>>` parameter; wire disk check after USB check, before ABAC)
- `dlp-agent/src/service.rs` — Service startup wiring; where `UsbEnforcer` is constructed and passed to `run_event_loop` — mirror this for `DiskEnforcer`; also where `device_watcher::spawn_device_watcher_task()` will be called instead of the current USB-window spawn
- `dlp-common/src/audit.rs` — `AuditEvent` struct — add `blocked_disk: Option<DiskIdentity>` field here; also add `with_blocked_disk(self, disk: DiskIdentity) -> Self` builder method
- `dlp-common/src/disk.rs` — `DiskIdentity` struct (all fields including Phase 34 encryption additions)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `UsbEnforcer` (`dlp-agent/src/usb_enforcer.rs`) — Direct template for `DiskEnforcer`. Copy the `should_notify()` cooldown pattern, `UsbBlockResult` shape → `DiskBlockResult`, and `Option<Arc<T>>` passing convention into `run_event_loop`.
- `DiskEnumerator::disk_for_drive_letter()` (`dlp-agent/src/detection/disk.rs:78`) — Fast `drive_letter_map` lookup; returns `Option<DiskIdentity>`. Phase 36 enforcement calls this first.
- `DiskEnumerator::disk_for_instance_id()` (`dlp-agent/src/detection/disk.rs:87`) — `instance_id_map` lookup; returns `Option<DiskIdentity>`. Used for the allowlist presence check and stored-serial retrieval.
- `DiskEnumerator::is_ready()` (`dlp-agent/src/detection/disk.rs:70`) — Returns `*enumeration_complete.read()`. Fail-closed gate in `DiskEnforcer::check()`.
- `AuditEvent::with_discovered_disks()` (`dlp-common/src/audit.rs`) — Builder pattern template for the new `with_blocked_disk()` builder.
- `usb_wndproc` + `RegisterDeviceNotification` infrastructure (`dlp-agent/src/detection/usb.rs:355+`) — The Win32 window code to extract into `device_watcher.rs`. Read carefully before moving — it is thread-affine and uses `Box::into_raw` / `Box::from_raw` for the detector pointer.
- `on_disk_device_arrival` / `on_disk_device_removal` (`dlp-agent/src/detection/usb.rs:752, 876`) — Existing handlers that walk the PnP tree; reference these when writing `disk::on_disk_arrival()` in `disk.rs`.
- `extract_disk_instance_id` (`dlp-agent/src/detection/usb.rs:733`) — Parses `GUID_DEVINTERFACE_DISK` `dbcc_name` to instance ID; move to `device_watcher.rs`.

### Established Patterns
- `parking_lot::Mutex<HashMap<char, Instant>>` for per-drive cooldown — `UsbEnforcer::last_toast` pattern
- `Option<Arc<T>>` enforcer parameter in `run_event_loop` — USB establishes this; disk follows identically
- Pre-ABAC `continue;` short-circuit in `run_event_loop` — USB block fires `continue` to skip ABAC; disk block does the same
- `Pipe2AgentMsg::Toast` broadcast via `BROADCASTER` — USB toast pattern reused for disk toast
- `tracing::warn!` with structured fields for block events — established logging style

### Integration Points
- `dlp-agent/src/interception/mod.rs::run_event_loop()` — Add `disk_enforcer: Option<Arc<DiskEnforcer>>` parameter. Insert disk check block immediately after the USB enforcer block (lines ~86-163), before `let abac_action = PolicyMapper::action_for(&action)`. Pattern is identical: `if let Some(ref enforcer) = disk_enforcer { if let Some(result) = enforcer.check(...) { ... continue; } }`.
- `dlp-agent/src/service.rs` — Replace `spawn_usb_watcher_thread()` call (or equivalent) with `device_watcher::spawn_device_watcher_task()`. Construct `DiskEnforcer` after `set_disk_enumerator()` and pass `Arc` clone into `run_event_loop`.
- `dlp-agent/src/detection/mod.rs` — Add `pub mod device_watcher; pub use device_watcher::spawn_device_watcher_task;` (or similar).
- `dlp-common/src/audit.rs` — `blocked_disk` field needs `#[serde(skip_serializing_if = "Option::is_none")]` to keep audit JSON compact when not set.

</code_context>

<specifics>
## Specific Requirements

### DiskEnforcer check logic (pseudocode)
```rust
pub fn check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult> {
    // Only intercept write-path actions (DISK-04)
    if !matches!(action, FileAction::Create(_) | FileAction::Write(_) | FileAction::Move { .. }) {
        return None;
    }

    let enumerator = get_disk_enumerator()?;

    // Fail-closed: block all writes before enumeration completes (D-06)
    if !enumerator.is_ready() {
        // Need a placeholder DiskIdentity for the audit event — use drive letter only
        let letter = drive_letter_from_path(path)?;
        return Some(DiskBlockResult::fail_closed(letter));
    }

    let letter = drive_letter_from_path(path)?;
    let live_disk = enumerator.disk_for_drive_letter(letter)?;  // None = not a fixed disk

    // Check allowlist (instance_id_map is frozen allowlist — D-09)
    let registered = enumerator.disk_for_instance_id(&live_disk.instance_id);
    let is_allowlisted = registered.is_some();

    // Compound serial check: close physical-swap bypass (D-07)
    let serial_mismatch = registered.as_ref().and_then(|r| r.serial.as_ref())
        .zip(live_disk.serial.as_ref())
        .map(|(stored, live)| stored != live)
        .unwrap_or(false);

    if !is_allowlisted || serial_mismatch {
        let notify = self.should_notify(letter);
        return Some(DiskBlockResult {
            decision: Decision::DENY,
            disk: live_disk,
            notify,
        });
    }

    None  // Allowed — fall through to ABAC
}
```

### AuditEvent addition (dlp-common/src/audit.rs)
```rust
pub struct AuditEvent {
    // ... existing fields ...
    pub discovered_disks: Option<Vec<DiskIdentity>>,  // Phase 33 — discovery events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_disk: Option<DiskIdentity>,            // Phase 36 — AUDIT-02 block events
}

impl AuditEvent {
    pub fn with_blocked_disk(mut self, disk: DiskIdentity) -> Self {
        self.blocked_disk = Some(disk);
        self
    }
}
```

### device_watcher.rs dispatch structure (target shape)
```rust
// dlp-agent/src/detection/device_watcher.rs
// Owns the hidden Win32 window + WM_DEVICECHANGE loop.
// Extracted from usb.rs; dispatches to per-module handlers.

WM_DEVICECHANGE handler:
  GUID_DEVINTERFACE_USB_DEVICE + DBT_DEVICEARRIVAL   → usb::on_usb_device_arrival()
  GUID_DEVINTERFACE_USB_DEVICE + DBT_DEVICEREMOVECOMPLETE → usb::on_usb_device_removal()
  GUID_DEVINTERFACE_DISK       + DBT_DEVICEARRIVAL   → disk::on_disk_arrival()
  GUID_DEVINTERFACE_DISK       + DBT_DEVICEREMOVECOMPLETE → disk::on_disk_removal()
```

</specifics>

<deferred>
## Deferred Ideas

- **Per-disk trust tiers** (`blocked`, `read_only`, `full_access`) — deferred to v0.7.1+ (DISK-F4). Phase 36 is binary allow/block only.
- **Mount-time volume locking** — deferred to v0.7.1+ (DISK-F1). Phase 36 uses I/O-time blocking only.
- **Disk block toast UX refinement** (custom icon, admin contact link, request-access flow) — deferred to v0.7.1+ (DISK-F3).
- **Read blocking on unregistered disks** — explicitly rejected; DISK-04 specifies write-path only; read blocking would require a spec change.
- **Updating instance_id_map on disk arrival** — rejected; would defeat the serial-based physical-swap protection (D-09/D-11).

</deferred>

---

*Phase: 36-disk-enforcement*
*Context gathered: 2026-05-04*
