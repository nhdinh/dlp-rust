# Phase 36: Disk Enforcement - Research

**Researched:** 2026-05-04
**Domain:** Windows I/O enforcement, WM_DEVICECHANGE hot-plug handling, pre-ABAC enforcement pipeline
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**DiskEnforcer struct**
- D-01: `DiskEnforcer` lives in `dlp-agent/src/disk_enforcer.rs`, mirroring `usb_enforcer.rs`. Passed as `Option<Arc<DiskEnforcer>>` into `run_event_loop` alongside the existing `usb_enforcer` parameter.
- D-02: `DiskEnforcer` is stateful — carries `last_toast: parking_lot::Mutex<HashMap<char, Instant>>` for a 30-second per-drive toast cooldown, identical to `UsbEnforcer`. Block decision is always applied regardless of cooldown.
- D-03: `DiskEnforcer::check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult>`. Returns `Some(DiskBlockResult)` when a block fires; `None` when path is allowed, not on a fixed disk, or action is not a write-path operation.
- D-04: Blocked action filter: `FileAction::Create / Write / Move` only. `FileAction::Read` is allowed. Matches DISK-04 exactly.
- D-05: `DiskBlockResult` carries `decision: Decision` and `disk: DiskIdentity`.

**Enforcement logic**
- D-06: When `enumeration_complete = false`, block ALL fixed-disk writes (fail-closed). Consistent with Phase 33 D-04.
- D-07: Compound allowlist check — extract drive letter → `drive_letter_map[letter]` → `instance_id_map` lookup → serial verification (physical-swap attack closure).
- D-08: Boot disks auto-allowlisted via Phase 33 D-15; no special boot-disk logic in `DiskEnforcer`.

**Allowlist map semantics**
- D-09: `instance_id_map` is a frozen allowlist after `enumeration_complete = true`. Never updated by hot-plug arrivals.
- D-10: `drive_letter_map` is live current state. Updated by `on_disk_arrival()` (add entry) and `on_disk_removal()` (remove entry). `instance_id_map` NOT touched by handlers.
- D-11: Physical-swap bypass closed: same `instance_id` but different serial → serial mismatch → blocked.

**Device arrival/removal (WM_DEVICECHANGE refactor)**
- D-12: New `dlp-agent/src/detection/device_watcher.rs` owns the Win32 hidden window + `WM_DEVICECHANGE` dispatcher. Extracted from `usb.rs`. Dispatches `GUID_DEVINTERFACE_USB_DEVICE` events to `usb::on_usb_device_*` and `GUID_DEVINTERFACE_DISK` events to `disk::on_disk_arrival/removal`.
- D-13: `disk::on_disk_arrival(device_path: &str, audit_ctx: &EmitContext)` in `disk.rs`. Resolve instance_id → update `drive_letter_map` only → check against `instance_id_map` → emit `DiskDiscovery` if unregistered.
- D-14: `disk::on_disk_removal(device_path: &str)` in `disk.rs`. Remove from `drive_letter_map` only. No audit event.

**AuditEvent disk block identity (AUDIT-02)**
- D-15: Add `blocked_disk: Option<DiskIdentity>` to `AuditEvent` in `dlp-common/src/audit.rs`. Populated for `EventType::Block` from `DiskEnforcer`.
- D-16: `blocked_disk` carries full `DiskIdentity` from `drive_letter_map` at enforcement time.

### Claude's Discretion

- Exact method for resolving drive letter for a newly arrived disk in `on_disk_arrival()` — recommended: call `enumerate_fixed_disks()` filtered to the arrived `instance_id` (WMI query already proven); alternative: `GetVolumePathNamesForVolumeNameW` if targeted approach preferred.
- Whether `DiskEnforcer` wraps `get_disk_enumerator()` internally or receives `Arc<DiskEnumerator>` at construction — recommended: wrap the global static internally (same as `UsbEnforcer` wraps injected caches), consistent with `service.rs` wiring.
- Whether `on_disk_removal()` emits a `tracing::info!` log line — recommended: yes.
- Exact toast message text — recommended: title `"Unregistered Disk Blocked"`, body `"{model} ({drive_letter}:) — this disk is not registered"`.
- Whether `extract_disk_instance_id` is moved from `usb.rs` to `device_watcher.rs` — recommended: move it, since it parses `GUID_DEVINTERFACE_DISK` dbcc_name, not USB-specific.

### Deferred Ideas (OUT OF SCOPE)

- Per-disk trust tiers (`blocked`, `read_only`, `full_access`) — DISK-F4, v0.7.1+
- Mount-time volume locking — DISK-F1, v0.7.1+
- Disk block toast UX refinement (custom icon, admin contact link) — DISK-F3, v0.7.1+
- Read blocking on unregistered disks — explicitly rejected (DISK-04 is write-path only)
- Updating `instance_id_map` on disk arrival — rejected (defeats serial-based physical-swap protection)
- Server-side disk registry — Phase 37
- Admin TUI disk registry — Phase 38

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DISK-04 | Agent blocks I/O (FileAction::Create/Write/Move) to unregistered fixed disks at runtime via pre-ABAC enforcement in `run_event_loop` | DiskEnforcer struct mirrors UsbEnforcer; pre-ABAC short-circuit pattern is established in `interception/mod.rs` lines 89-163 |
| DISK-05 | Agent handles WM_DEVICECHANGE DBT_DEVICEARRIVAL/DBT_DEVICEREMOVECOMPLETE for GUID_DEVINTERFACE_DISK | Current `usb_wndproc` already handles GUID_DEVINTERFACE_DISK at line 428; refactor to `device_watcher.rs` dispatcher with new disk handlers |
| AUDIT-02 | Disk block events include disk identity fields (instance_id, bus_type, model, drive letter) when an unregistered fixed disk is blocked | `AuditEvent` builder pattern established; add `blocked_disk: Option<DiskIdentity>` field + `with_blocked_disk()` builder matching existing `with_discovered_disks()` pattern |

</phase_requirements>

---

## Summary

Phase 36 adds the I/O enforcement half of the disk DLP feature. The data model and allowlist persistence (Phases 33-35) are complete. This phase wires three connected subsystems: a `DiskEnforcer` that blocks writes to unregistered fixed disks, a refactored `device_watcher.rs` that dispatches both USB and disk hot-plug events, and a new `blocked_disk` field on `AuditEvent`.

The codebase already contains every primitive needed. `UsbEnforcer` (`usb_enforcer.rs`) is a direct template for `DiskEnforcer` — the struct shape, `should_notify()` cooldown, `Option<Arc<T>>` parameter convention, and pre-ABAC `continue` short-circuit in `run_event_loop` all transfer verbatim. `DiskEnumerator` (Phase 35) already provides the three accessors the enforcer needs: `is_ready()`, `disk_for_drive_letter()`, and `disk_for_instance_id()`. The `AuditEvent` builder pattern (`with_discovered_disks()`) is the direct template for `with_blocked_disk()`.

The primary construction work is (a) extracting the hidden window from `usb.rs` into `device_watcher.rs` — a thread-affine `Box::into_raw`/`Box::from_raw` unsafe block that must be handled carefully — and (b) writing `on_disk_arrival` and `on_disk_removal` handlers in `disk.rs` for the new dispatcher. The drive-letter resolution strategy for `on_disk_arrival` is the only open design question the planner must resolve (see Claude's Discretion).

**Primary recommendation:** Implement in three sequential tasks: (1) `DiskEnforcer` + `DiskBlockResult` with full unit tests; (2) `device_watcher.rs` refactor + disk handler stubs; (3) wire enforcer into `run_event_loop` and `service.rs`, add `blocked_disk` to `AuditEvent`.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Write-path I/O blocking | Agent (interception layer) | — | DiskEnforcer fires in `run_event_loop` before ABAC, consistent with USB enforcement pattern |
| Allowlist lookup (is this disk registered?) | Agent (in-memory DiskEnumerator) | — | `instance_id_map` is the frozen allowlist; Phase 35 built it; Phase 36 reads it |
| Physical-swap detection | Agent (DiskEnforcer compound check) | — | Compound `instance_id` + serial check on every write |
| Fail-closed startup window | Agent (DiskEnforcer + is_ready()) | — | Block all fixed-disk writes until `enumeration_complete = true` |
| WM_DEVICECHANGE dispatch | Agent (device_watcher.rs hidden window) | — | Owns Win32 message loop; dispatches to per-module handlers |
| drive_letter_map maintenance | Agent (disk.rs handlers) | — | `on_disk_arrival` adds entry; `on_disk_removal` removes it |
| Unregistered arrival audit | Agent (disk.rs on_disk_arrival) | — | DiskDiscovery event emitted immediately on unregistered arrival |
| Block audit event enrichment | Agent (DiskEnforcer → AuditEvent) | dlp-common | `blocked_disk: Option<DiskIdentity>` field on AuditEvent per AUDIT-02 |

---

## Standard Stack

### Core (all already present in Cargo.toml — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows` crate | 0.58+ (workspace) | Win32 WM_DEVICECHANGE, GUID_DEVINTERFACE_DISK, RegisterDeviceNotificationW | Project standard; already used in `usb.rs` for all device notification infrastructure |
| `parking_lot` | workspace | `Mutex<HashMap<char, Instant>>` for cooldown; `RwLock` for DiskEnumerator fields | Project standard; UsbEnforcer already uses `parking_lot::Mutex` for `last_toast` |
| `std::sync::Arc` | stdlib | Share `DiskEnforcer` between service and event loop | Project standard; identical to `Option<Arc<UsbEnforcer>>` pattern |
| `tracing` | workspace | Structured logging for block events, arrival/removal | Project standard per CLAUDE.md §9.1 |
| `serde` + `serde_json` | workspace | `AuditEvent` JSON serialization with `skip_serializing_if` | Project standard; `DiskIdentity` is already `Serialize/Deserialize` |
| `thiserror` | workspace | Error types for any new fallible operations | Project standard per CLAUDE.md §9.5 |

[VERIFIED: existing Cargo.toml usage — all dependencies confirmed in source code grep]

### No New Dependencies Required

Phase 36 adds zero new crate dependencies. All Win32 types needed (`GUID_DEVINTERFACE_DISK`, `DBT_DEVICEARRIVAL`, `DBT_DEVICEREMOVECOMPLETE`, `DEV_BROADCAST_DEVICEINTERFACE_W`) are already imported in `usb.rs` and will migrate to `device_watcher.rs`.

---

## Architecture Patterns

### System Architecture Diagram

```
File I/O event
    |
    v
run_event_loop (interception/mod.rs)
    |
    +-- [1] DiskEnforcer::check(path, action)
    |       |
    |       +-- extract drive letter from path
    |       +-- is_ready()? NO --> BLOCK (fail-closed)
    |       +-- disk_for_drive_letter(letter)? None --> pass (not fixed disk)
    |       +-- disk_for_instance_id(instance_id)? None --> BLOCK
    |       +-- serial mismatch? --> BLOCK
    |       +-- all pass --> None (continue to ABAC)
    |
    +-- [2] BLOCK path
    |       |
    |       +-- AuditEvent::new(EventType::Block)
    |       |     .with_blocked_disk(live_disk)  <-- AUDIT-02
    |       +-- emit_audit()
    |       +-- Pipe2AgentMsg::Toast (if cooldown expired)
    |       +-- continue (skip ABAC)
    |
    +-- [3] ABAC path (unmodified)

WM_DEVICECHANGE (device_watcher.rs - new)
    |
    +-- GUID_DEVINTERFACE_USB_DEVICE + DBT_DEVICEARRIVAL --> usb::on_usb_device_arrival()
    +-- GUID_DEVINTERFACE_USB_DEVICE + DBT_DEVICEREMOVECOMPLETE --> usb::on_usb_device_removal()
    +-- GUID_DEVINTERFACE_DISK + DBT_DEVICEARRIVAL --> disk::on_disk_arrival()
    |       |
    |       +-- extract instance_id from dbcc_name
    |       +-- resolve drive letter (enumerate_fixed_disks or targeted query)
    |       +-- drive_letter_map.write().insert(letter, disk)  <-- D-10
    |       +-- instance_id_map lookup: missing? --> emit DiskDiscovery audit
    |
    +-- GUID_DEVINTERFACE_DISK + DBT_DEVICEREMOVECOMPLETE --> disk::on_disk_removal()
            |
            +-- extract instance_id
            +-- drive_letter_map.write().remove(letter)  <-- D-10
            +-- (instance_id_map untouched)
```

### Recommended Project Structure

New files this phase introduces:

```
dlp-agent/src/
├── disk_enforcer.rs          # NEW: DiskEnforcer, DiskBlockResult (mirrors usb_enforcer.rs)
├── detection/
│   ├── device_watcher.rs     # NEW: hidden Win32 window + WM_DEVICECHANGE dispatcher
│   ├── disk.rs               # MODIFIED: add on_disk_arrival(), on_disk_removal()
│   └── mod.rs                # MODIFIED: pub mod device_watcher; re-exports
dlp-common/src/
└── audit.rs                  # MODIFIED: add blocked_disk field + with_blocked_disk builder
dlp-agent/src/
├── interception/mod.rs       # MODIFIED: add disk_enforcer param + enforcement block
└── service.rs                # MODIFIED: wire DiskEnforcer construction + device_watcher spawn
```

### Pattern 1: DiskEnforcer (mirrors UsbEnforcer exactly)

```rust
// Source: dlp-agent/src/usb_enforcer.rs (direct template)

pub struct DiskEnforcer {
    // No injected caches — wraps global get_disk_enumerator() internally
    // (Claude's Discretion recommendation — matches how usb.rs uses the global).
    last_toast: parking_lot::Mutex<HashMap<char, Instant>>,
}

impl DiskEnforcer {
    pub fn new() -> Self {
        Self { last_toast: parking_lot::Mutex::new(HashMap::new()) }
    }

    fn should_notify(&self, drive: char) -> bool {
        const COOLDOWN: Duration = Duration::from_secs(30);
        let mut map = self.last_toast.lock();
        let now = Instant::now();
        let expired = map.get(&drive)
            .is_none_or(|last| now.duration_since(*last) >= COOLDOWN);
        if expired { map.insert(drive, now); }
        expired
    }

    pub fn check(&self, path: &str, action: &FileAction) -> Option<DiskBlockResult> {
        // Action filter (DISK-04): only Create/Write/Move
        if !matches!(action,
            FileAction::Created { .. } | FileAction::Written { .. } | FileAction::Moved { .. }
        ) {
            return None;
        }

        let enumerator = get_disk_enumerator()?;

        // Fail-closed: block all fixed-disk writes during startup window (D-06)
        let letter = drive_letter_from_path(path)?;
        if !enumerator.is_ready() {
            return Some(DiskBlockResult {
                decision: Decision::DENY,
                disk: DiskIdentity { drive_letter: Some(letter), ..Default::default() },
                notify: self.should_notify(letter),
            });
        }

        // Not a known fixed disk → pass through (D-07 step 2)
        let live_disk = enumerator.disk_for_drive_letter(letter)?;

        // Allowlist check (D-07 step 3)
        let registered = enumerator.disk_for_instance_id(&live_disk.instance_id);

        // Serial check: close physical-swap bypass (D-07 step 4)
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
    }
}
```

[VERIFIED: pattern derived from reading dlp-agent/src/usb_enforcer.rs and CONTEXT.md D-03 through D-07]

### Pattern 2: Pre-ABAC integration in run_event_loop

```rust
// Source: dlp-agent/src/interception/mod.rs lines 89-163 (USB enforcement block)
// Insert immediately after the USB block, before `let abac_action = PolicyMapper::action_for(&action)`:

if let Some(ref enforcer) = disk_enforcer {
    if let Some(disk_result) = enforcer.check(&path, &action) {
        let mut audit_event = AuditEvent::new(
            EventType::Block,
            user_sid.clone(),
            user_name.clone(),
            path.clone(),
            dlp_common::Classification::T1,  // placeholder, disk enforcement fires before classification
            dlp_common::Action::WRITE,
            disk_result.decision,
            ctx.agent_id.clone(),
            ctx.session_id,
        )
        .with_access_context(AuditAccessContext::Local)
        .with_policy(String::new(), "Disk enforcement: unregistered fixed disk".to_string())
        .with_blocked_disk(disk_result.disk.clone());  // AUDIT-02

        emit_audit(&ctx, &mut audit_event);

        if disk_result.notify {
            crate::ipc::pipe2::BROADCASTER.broadcast(&Pipe2AgentMsg::Toast {
                title: "Unregistered Disk Blocked".to_string(),
                body: format!(
                    "{} ({}:) — this disk is not registered",
                    disk_result.disk.model,
                    disk_result.disk.drive_letter.unwrap_or('?')
                ),
            });
        }
        continue;
    }
}
```

[VERIFIED: derived from reading interception/mod.rs USB enforcement block and CONTEXT.md D-15/D-16]

### Pattern 3: device_watcher.rs structure

The hidden Win32 window infrastructure in `usb.rs` uses an **unsafe thread-affine pattern**:

```rust
// Source: dlp-agent/src/detection/usb.rs lines 353-444 (usb_wndproc + Register... infra)

// Key unsafe pattern to preserve when moving to device_watcher.rs:
// 1. RegisterClassW → CreateWindowExW (message-only: HWND_MESSAGE parent)
// 2. RegisterDeviceNotificationW for GUID_DEVINTERFACE_VOLUME (USB volume tracking)
// 3. RegisterDeviceNotificationW for GUID_DEVINTERFACE_USB_DEVICE (USB identity)
// 4. RegisterDeviceNotificationW for GUID_DEVINTERFACE_DISK (NEW in Phase 36)
// 5. GetMessageW loop — thread-affine, must run on same std::thread as CreateWindowExW
// 6. WM_DESTROY → PostQuitMessage(0) pattern
//
// The dispatcher routes by classguid:
//   GUID_DEVINTERFACE_VOLUME        → handle_volume_event (stays in usb.rs)
//   GUID_DEVINTERFACE_USB_DEVICE    → usb::on_usb_device_arrival/removal (stays in usb.rs)
//   GUID_DEVINTERFACE_DISK          → disk::on_disk_arrival/removal (new in disk.rs)
```

[VERIFIED: read usb.rs lines 330-470 directly]

### Pattern 4: AuditEvent backward-compatible field addition

```rust
// Source: dlp-common/src/audit.rs (established by Phase 33 discovered_disks addition)

// In AuditEvent struct:
#[serde(skip_serializing_if = "Option::is_none")]
pub blocked_disk: Option<DiskIdentity>,  // Phase 36 — AUDIT-02 block events

// In AuditEvent::new() constructor initializer:
blocked_disk: None,

// New builder method (mirrors with_discovered_disks pattern):
pub fn with_blocked_disk(mut self, disk: DiskIdentity) -> Self {
    self.blocked_disk = Some(disk);
    self
}
```

[VERIFIED: read dlp-common/src/audit.rs lines 183-331 directly]

### Anti-Patterns to Avoid

- **Writing to `instance_id_map` in arrival handler:** Rejected explicitly (D-09/D-11). Defeats physical-swap protection. `instance_id_map` is frozen after `enumeration_complete = true`.
- **Returning `None` from `DiskEnforcer::check` when enumeration is incomplete:** Must block all fixed-disk writes when `!is_ready()` — fail-closed (D-06). Never default-allow during the startup window.
- **Calling `drive_letter_map` lookup without normalizing case:** `DiskEnumerator::disk_for_drive_letter` already calls `to_ascii_uppercase()` (disk.rs line 81); `drive_letter_from_path` helper must also uppercase before map lookup.
- **Acquiring `DiskEnumerator` write locks in arrival handler while holding other locks:** Lock order discipline — release all `DiskEnumerator` write locks before acquiring `AgentConfig` write lock (Pitfall from Phase 35 implementation).
- **Storing Win32 window pointer past the WM_DEVICECHANGE callback:** `DEV_BROADCAST_DEVICEINTERFACE_W` is only valid for the duration of the callback. Extract the `dbcc_name` string synchronously in the callback (the existing `read_dbcc_name()` helper does this correctly).
- **Confusing `GUID_DEVINTERFACE_DISK` and `GUID_DEVINTERFACE_VOLUME`:** DISK events carry the instance ID via `dbcc_name`; VOLUME events carry a volume GUID path with no drive letter. The existing `usb_wndproc` already distinguishes these (line 392 vs 428). `device_watcher.rs` must preserve this dispatch.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Toast cooldown per drive letter | Custom timer logic | `parking_lot::Mutex<HashMap<char, Instant>>` with `should_notify()` — copy from `UsbEnforcer` | Already solved; identical use case; adding a second implementation creates divergence |
| Drive letter extraction from Windows path | Custom parser | `extract_drive_letter()` from `usb_enforcer.rs` | UNC path handling, case normalization, empty-string guard already covered |
| Instance ID from `dbcc_name` | Custom parser | `disk_path_to_instance_id()` from `usb.rs` (rename to `extract_disk_instance_id` per CONTEXT.md) | Already handles `\\?\` prefix stripping and `#`→`\` replacement |
| Win32 hidden-window message loop | Custom implementation | Extract existing `usb_wndproc` infrastructure to `device_watcher.rs` | Thread-affine constraint, `RegisterDeviceNotificationW` lifecycle, `PostQuitMessage` pattern — all working in production |
| Fixed disk drive letter resolution at arrival time | Custom WMI query | Call `enumerate_fixed_disks()` (already in `dlp-common`) and filter by `instance_id` | Proven; used at startup; avoids a second WMI session |

**Key insight:** Every primitive is already written and tested. Phase 36 is a composition phase — wire, route, and expose, not invent.

---

## Common Pitfalls

### Pitfall 1: GUID_DEVINTERFACE_DISK instance ID format mismatch
**What goes wrong:** `dbcc_name` from a `GUID_DEVINTERFACE_DISK` notification looks like `\\?\USBSTOR#Disk&Ven_...#{53f56307-...}`. After `disk_path_to_instance_id()` strips the prefix and GUID suffix and replaces `#` with `\`, it becomes `USBSTOR\Disk&Ven_...`. But `DiskEnumerator.instance_id_map` was populated by `enumerate_fixed_disks()` which uses `SetupDiGetDeviceInstanceIdW` — a different string for the same physical device.
**Why it happens:** Two different Win32 APIs produce different forms of the "same" instance ID. The notification path uses the device interface path; SetupDi returns the device instance path.
**How to avoid:** When `on_disk_arrival()` extracts the instance ID from `dbcc_name`, look it up in `instance_id_map` by prefix matching or by calling `enumerate_fixed_disks()` and matching by drive letter rather than by the raw arrival string. The recommended approach (Claude's Discretion) of calling `enumerate_fixed_disks()` filtered to newly visible drive letters sidesteps this entirely — the `instance_id` in the result is guaranteed to match what's in the map.
**Warning signs:** All `on_disk_arrival` calls emit `DiskDiscovery` events for known-registered disks (instance ID lookup always returns None despite the disk being allowlisted).

### Pitfall 2: Lock order violation causing deadlock in arrival handler
**What goes wrong:** `on_disk_arrival` acquires a `DiskEnumerator.drive_letter_map` write lock while another code path already holds the `AgentConfig` write lock (e.g., config poll loop writing disk_allowlist).
**Why it happens:** Phase 35 established a strict lock order (DiskEnumerator locks BEFORE AgentConfig write lock). The arrival handler writes `drive_letter_map` but must not also touch `AgentConfig` in the same lock scope.
**How to avoid:** `on_disk_arrival` ONLY writes `drive_letter_map`. Never acquire `AgentConfig` lock in any `DiskEnumerator` handler. This is not needed for Phase 36 — `instance_id_map` is frozen; only `drive_letter_map` is mutable here.
**Warning signs:** Deadlock under hot-plug stress testing; service hangs when a disk is connected while config poll is running.

### Pitfall 3: Fail-open during `enumeration_complete = false` startup window
**What goes wrong:** `DiskEnforcer::check()` returns `None` for paths during the startup window because `get_disk_enumerator()` returns `None` (enumerator not yet set) or `is_ready()` is false. Writes to unregistered disks slip through to ABAC.
**Why it happens:** `get_disk_enumerator()` returns `Option<Arc<DiskEnumerator>>` — if no enumerator is set yet, returns `None`. The `?` operator on `None` short-circuits to return `None` from `check()` — which means "allowed." This is wrong; it should mean "no disk context available."
**How to avoid:** In `DiskEnforcer::check()`, handle the "no enumerator yet" case explicitly: treat it as `!is_ready()` and block. The pseudocode in CONTEXT.md shows `let enumerator = get_disk_enumerator()?` — but this `?` applies to the `Option` meaning "no fixed disk context = pass through." The correct intent is: if `get_disk_enumerator()` returns `None`, the agent hasn't initialized the enumerator yet → block (fail-closed D-06). Revise the check: if `get_disk_enumerator()` is `None`, return block result with placeholder identity.
**Warning signs:** Integration test shows writes to unregistered disk succeed during the first 4 seconds of agent startup.

### Pitfall 4: Race between `on_disk_arrival` and `DiskEnforcer::check` on `drive_letter_map`
**What goes wrong:** A disk arrives, `on_disk_arrival` starts updating `drive_letter_map` (write lock), and concurrently the interception loop calls `DiskEnforcer::check` which calls `disk_for_drive_letter()` (read lock). Under `parking_lot::RwLock`, this is safe — reads and writes are correctly serialized. However, if `on_disk_arrival` resolves the drive letter AFTER the first write to the new disk arrives at `DiskEnforcer::check`, the enforcer will see `None` from `disk_for_drive_letter()` (D-07 step 2 passes through) — meaning the first write to the new disk is not blocked.
**Why it happens:** There is an inherent time window between physical arrival and the `drive_letter_map` update.
**How to avoid:** This is acceptable behavior per the design: if `drive_letter_map` has no entry for the drive letter, the path "is not a known fixed disk" → pass through to ABAC. The risk window is small (tens of milliseconds between WM_DEVICECHANGE and `drive_letter_map` update). For an unregistered disk, this means one or a few writes might reach ABAC rather than the DiskEnforcer; ABAC will still evaluate them. The audit event may not have `blocked_disk` populated for these edge-case events, but the block decision is still applied if ABAC denies. Document this in the code comment.
**Warning signs:** Not a bug — expected behavior. Note in tests.

### Pitfall 5: device_watcher.rs thread-affinity violation
**What goes wrong:** The Win32 `GetMessageW` message loop must run on the same thread that called `CreateWindowExW`. If the dispatch function tries to call back into async Tokio code or spawn a task inline, it can block the message loop.
**Why it happens:** The existing `usb_wndproc` already has this solved — it uses stored statics (`REGISTRY_RUNTIME_HANDLE`) to schedule async work off the message thread. The pattern must be preserved in `device_watcher.rs`.
**How to avoid:** `on_disk_arrival` and `on_disk_removal` are synchronous. They write to `parking_lot::RwLock<HashMap>` which is sync. No async calls in the dispatch path. If an audit emission is needed from `on_disk_arrival`, it must use the `emit_audit()` function (which does file I/O synchronously) or schedule via a stored tokio Handle (same pattern as `REGISTRY_RUNTIME_HANDLE`). Per D-13, `DiskDiscovery` audit events are emitted from within `on_disk_arrival()` — use the stored `EmitContext` passed as parameter and call `emit_audit()` directly (file append is synchronous and fast).
**Warning signs:** Message loop hangs; USB notifications stop firing after disk arrival; `WM_DEVICECHANGE` events queue up unprocessed.

---

## Code Examples

### Drive letter extraction helper

```rust
// Source: derived from usb_enforcer.rs::extract_drive_letter (identical logic)
/// Extracts the uppercase drive letter from a Windows file path.
/// Returns None for UNC paths (\\...) and non-alpha first characters.
fn drive_letter_from_path(path: &str) -> Option<char> {
    if path.starts_with("\\\\") { return None; }
    let first = path.chars().next()?;
    if first.is_ascii_alphabetic() { Some(first.to_ascii_uppercase()) } else { None }
}
```

### Instance ID extraction from GUID_DEVINTERFACE_DISK dbcc_name

```rust
// Source: dlp-agent/src/detection/usb.rs::disk_path_to_instance_id (to be moved to device_watcher.rs)
/// Parses a GUID_DEVINTERFACE_DISK device interface path to a device instance ID.
/// Input:  "\\?\USBSTOR#Disk&Ven_Kingston#...#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
/// Output: "USBSTOR\Disk&Ven_Kingston\..."
fn extract_disk_instance_id(device_path: &str) -> String {
    let without_prefix = device_path.strip_prefix(r"\\?\").unwrap_or(device_path);
    let without_guid = without_prefix.split("#{").next().unwrap_or(without_prefix);
    without_guid.replace("#", r"\")
}
```

### AuditEvent.blocked_disk addition (backward-compatible)

```rust
// Source: dlp-common/src/audit.rs (extend existing struct)
// In AuditEvent struct (after discovered_disks field):
/// Fixed disk identity on block events from DiskEnforcer (AUDIT-02, Phase 36).
/// Populated only for EventType::Block events where a fixed disk was blocked.
/// Semantically distinct from discovered_disks (enumeration at startup).
#[serde(skip_serializing_if = "Option::is_none")]
pub blocked_disk: Option<DiskIdentity>,

// In AuditEvent::new() constructor:
blocked_disk: None,

// New builder method:
/// Sets the blocked disk identity on disk enforcement block events (AUDIT-02).
pub fn with_blocked_disk(mut self, disk: DiskIdentity) -> Self {
    self.blocked_disk = Some(disk);
    self
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `usb_wndproc` owns all device notifications | `device_watcher.rs` owns window; `usb.rs` + `disk.rs` own per-protocol handlers | Phase 36 | Cleaner separation; disk arrival handling no longer embedded in USB code |
| No disk write blocking at I/O time | `DiskEnforcer` pre-ABAC block in `run_event_loop` | Phase 36 | Closes the gap: unregistered fixed disks now blocked at I/O time like USB |
| `on_disk_device_arrival/removal` in `usb.rs` for USB-bridged disks only | `on_disk_arrival/removal` in `disk.rs` for all fixed disks | Phase 36 | USB-bridged disk handling in usb.rs was for USB identity capture; Phase 36 handles all fixed disks for allowlist enforcement |
| `AuditEvent` has no disk enforcement identity | `blocked_disk: Option<DiskIdentity>` on `AuditEvent` | Phase 36 | SIEM can filter `event_type = BLOCK AND blocked_disk IS NOT NULL` for disk enforcement events |

**Important distinction from existing code:** The existing `on_disk_device_arrival` and `on_disk_device_removal` functions in `usb.rs` (lines 752, 876) are **USB-specific handlers** — they walk the PnP tree looking for a USB ancestor and apply USB tier enforcement. Phase 36's `disk::on_disk_arrival` and `disk::on_disk_removal` are **entirely different** — they maintain `drive_letter_map` for ALL fixed disks (including internal SATA/NVMe) for allowlist-based enforcement. The two sets of handlers serve different purposes and must both exist after the refactor. [VERIFIED: read usb.rs lines 745-950]

---

## Runtime State Inventory

This phase is primarily code changes, not a rename/refactor with string-based state. However, one runtime state category applies:

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | `DiskEnumerator.instance_id_map` and `drive_letter_map` in-memory — populated by Phase 35 at startup | Code read-only; no migration needed. Maps are rebuilt from TOML + live enumeration on each startup. |
| Live service config | `agent-config.toml` disk_allowlist — populated by Phase 35 | No change; Phase 36 reads it via `DiskEnumerator`; allowlist format unchanged |
| OS-registered state | Win32 hidden window from `register_usb_notifications` — existing | Replaced by `device_watcher::spawn_device_watcher_task()` in Phase 36. Old window is unregistered during service shutdown; new window registered at next startup. No stale state. |
| Secrets/env vars | None | Not applicable |
| Build artifacts | None | Not applicable |

**Nothing found requiring data migration.** Phase 36 is additive — new code paths, new field on `AuditEvent`, refactored window ownership. Existing TOML allowlist data from Phase 35 is fully compatible.

---

## Open Questions

1. **Drive letter resolution strategy in `on_disk_arrival`**
   - What we know: `disk_path_to_instance_id(dbcc_name)` gives the device interface path form of the instance ID, which may not exactly match the `SetupDiGetDeviceInstanceIdW` form in `instance_id_map`.
   - What's unclear: Whether a `GUID_DEVINTERFACE_DISK` `dbcc_name`-derived instance ID reliably matches `instance_id_map` keys from `enumerate_fixed_disks()`.
   - Recommendation (per CONTEXT.md Claude's Discretion): Call `enumerate_fixed_disks()` and find the entry whose drive letter is newly visible (compare before/after or scan all fixed drive letters for ones not yet in `drive_letter_map`). This produces an instance ID in exactly the form stored in `instance_id_map`. Alternatively: look up the arrived instance ID via `CM_Get_Device_ID_List` to convert between forms. The planner should decide which approach to specify.

2. **`DiskEnforcer` construction: global static vs injected `Arc<DiskEnumerator>`**
   - What we know: CONTEXT.md Claude's Discretion recommends wrapping `get_disk_enumerator()` internally. `UsbEnforcer` receives its caches injected. `DiskEnumerator` is already behind a global static per Phase 33.
   - What's unclear: Whether the planner wants consistency with `UsbEnforcer` (inject) or consistency with how the enumerator is accessed everywhere else (global static).
   - Recommendation: Use the global static internally (simpler; the enumerator is set before `DiskEnforcer` is constructed in `service.rs`; no additional `Arc` clone at construction site).

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows OS (Win32 API) | device_watcher.rs, WM_DEVICECHANGE | Windows 11 confirmed | 10.0.26200 | `#[cfg(windows)]` gates; non-Windows builds compile to stubs |
| `cargo build --all` | Verification | Confirmed in repo | Rust 2021 edition workspace | — |
| `cargo test` | Unit tests | Confirmed | — | — |

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `cargo test` |
| Config file | None (workspace Cargo.toml) |
| Quick run command | `cargo test -p dlp-agent disk_enforcer -- --nocapture` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DISK-04 | `DiskEnforcer::check` returns `Some(DiskBlockResult)` for Create/Write/Move on unregistered disk | unit | `cargo test -p dlp-agent disk_enforcer` | Wave 0 |
| DISK-04 | `DiskEnforcer::check` returns `None` for Read on unregistered disk | unit | `cargo test -p dlp-agent disk_enforcer` | Wave 0 |
| DISK-04 | `DiskEnforcer::check` returns block when `enumeration_complete = false` (fail-closed) | unit | `cargo test -p dlp-agent disk_enforcer` | Wave 0 |
| DISK-04 | `DiskEnforcer::check` returns `None` for path not in `drive_letter_map` (not a fixed disk) | unit | `cargo test -p dlp-agent disk_enforcer` | Wave 0 |
| DISK-04 | `DiskEnforcer::check` returns block on serial mismatch (physical-swap) | unit | `cargo test -p dlp-agent disk_enforcer` | Wave 0 |
| DISK-04 | `DiskEnforcer::check` returns `None` for allowlisted disk with matching serial | unit | `cargo test -p dlp-agent disk_enforcer` | Wave 0 |
| DISK-04 | 30s toast cooldown: `should_notify` true on first call, false during cooldown | unit | `cargo test -p dlp-agent disk_enforcer` | Wave 0 |
| DISK-05 | `disk::on_disk_arrival` updates `drive_letter_map` | unit | `cargo test -p dlp-agent disk_arrival` | Wave 0 |
| DISK-05 | `disk::on_disk_arrival` does NOT update `instance_id_map` | unit | `cargo test -p dlp-agent disk_arrival` | Wave 0 |
| DISK-05 | `disk::on_disk_arrival` emits `DiskDiscovery` for unregistered disk | unit | `cargo test -p dlp-agent disk_arrival` | Wave 0 |
| DISK-05 | `disk::on_disk_removal` removes from `drive_letter_map` only | unit | `cargo test -p dlp-agent disk_removal` | Wave 0 |
| AUDIT-02 | `AuditEvent::with_blocked_disk` populates `blocked_disk` field | unit | `cargo test -p dlp-common audit` | Wave 0 |
| AUDIT-02 | `blocked_disk` serializes to JSON with correct DiskIdentity fields | unit | `cargo test -p dlp-common audit` | Wave 0 |
| AUDIT-02 | `blocked_disk: None` omitted from JSON (`skip_serializing_if`) | unit | `cargo test -p dlp-common audit` | Wave 0 |
| AUDIT-02 | Legacy JSON without `blocked_disk` deserializes to `None` (backward compat) | unit | `cargo test -p dlp-common audit` | Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p dlp-agent disk_enforcer && cargo test -p dlp-common audit`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `dlp-agent/src/disk_enforcer.rs` — `DiskEnforcer`, `DiskBlockResult`, `#[cfg(test)] mod tests` (covers DISK-04)
- [ ] `dlp-agent/src/detection/device_watcher.rs` — dispatch module (covers DISK-05 infrastructure)
- [ ] Test additions to `dlp-agent/src/detection/disk.rs` — `on_disk_arrival`, `on_disk_removal` unit tests (covers DISK-05)
- [ ] Test additions to `dlp-common/src/audit.rs` — `blocked_disk` field tests (covers AUDIT-02)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Disk enforcement is identity-agnostic (blocks by disk identity, not user) |
| V3 Session Management | no | Not applicable |
| V4 Access Control | yes | Allowlist-based access control: `instance_id_map` is the authoritative allowlist; default-deny for all disks not in it |
| V5 Input Validation | yes | `dbcc_name` from Win32 OS callback — treated as untrusted input; instance ID extracted and sanitized via `extract_disk_instance_id` |
| V6 Cryptography | no | Serial number comparison is plain string equality, not cryptographic |

### Known Threat Patterns for Disk Enforcement

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Physical disk swap (same enclosure, different disk) | Spoofing | Compound check: `instance_id` AND `serial` both must match (D-07/D-11) |
| Write during startup enumeration window | Tampering | Fail-closed: block ALL fixed-disk writes when `!is_ready()` (D-06) |
| Race condition on `drive_letter_map` write | Tampering | `parking_lot::RwLock` serializes concurrent access correctly |
| `dbcc_name` injection via malformed device path | Tampering | `extract_disk_instance_id` uses `strip_prefix` + `split("#{")` + `replace("#", "\\")` — no shell execution, no path traversal possible |
| Bypassing enforcement via `FileAction::Read` | Information Disclosure | Explicitly scoped to write-path only per DISK-04; read access to unregistered disks is allowed by design |
| Toast suppression attack (rapid plug/unplug to hide notifications) | Repudiation | Block decision is always applied regardless of toast cooldown (D-02). Audit log always records the block. |

---

## Project Constraints (from CLAUDE.md)

| Constraint | Impact on Phase 36 |
|------------|-------------------|
| Never use `.unwrap()` in production code | `get_disk_enumerator()` returns `Option` — handle `None` explicitly in `DiskEnforcer::check`; do not `.unwrap()` |
| Use `thiserror` for all custom error types | Any new `enum DiskEnforcerError` must use `#[derive(thiserror::Error)]` |
| `parking_lot::Mutex/RwLock` preferred | `last_toast` uses `parking_lot::Mutex` (same as `UsbEnforcer`) |
| No `unsafe` unless necessary; document safety invariants | `device_watcher.rs` inherits the `usb_wndproc` unsafe blocks; all must have `// SAFETY:` comments |
| 4 spaces indentation, 100 char line limit | Enforced by `rustfmt` |
| `#[must_use]` on methods returning `Option`/`Result` that callers must not ignore | Apply to `DiskEnforcer::check()` |
| Doc comments on all public items | `DiskEnforcer`, `DiskBlockResult`, all public methods must have `///` docs |
| No wildcard imports except test module | `use super::*` only in `#[cfg(test)]` modules |
| `sonar-scanner` verification before push | Quality gate; no new issues |
| `cargo clippy -- -D warnings` must pass | Zero warnings |
| `NEVER` use emoji in code | Toast message body uses plain text only |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `disk_path_to_instance_id(dbcc_name)` output may not exactly match `SetupDiGetDeviceInstanceIdW` output for the same disk | Common Pitfalls #1, Open Questions #1 | If IDs DO match, the "call enumerate_fixed_disks()" approach is still correct but conservative. If they DON'T match, using the dbcc_name-derived ID directly would always produce lookup misses. | 
| A2 | `enumerate_fixed_disks()` is fast enough to call from `on_disk_arrival` (OS callback context) | Architecture Patterns, Pattern 3 | If slow, it could delay the WM_DEVICECHANGE handler. Mitigation: call on a spawned thread/task via a stored tokio Handle rather than inline in the callback. |

[VERIFIED for all other claims: source code read directly for all patterns, types, and integration points]

---

## Sources

### Primary (HIGH confidence)

- `dlp-agent/src/usb_enforcer.rs` — complete source read; `UsbEnforcer` template for `DiskEnforcer`
- `dlp-agent/src/detection/disk.rs` — complete source read; `DiskEnumerator` API confirmed
- `dlp-common/src/audit.rs` — complete source read; `AuditEvent` builder pattern confirmed
- `dlp-common/src/disk.rs` — complete source read; `DiskIdentity` struct all fields confirmed
- `dlp-agent/src/detection/usb.rs` lines 330-950 — read; `usb_wndproc`, `disk_path_to_instance_id`, `on_disk_device_arrival/removal` confirmed
- `dlp-agent/src/interception/mod.rs` lines 1-200 — read; USB enforcement pattern confirmed; integration point located
- `dlp-agent/src/service.rs` lines 440-700 — read; `UsbEnforcer` wiring pattern confirmed; `DiskEnumerator` setup confirmed
- `dlp-agent/src/detection/mod.rs` — read; re-export pattern for new `device_watcher` module confirmed
- `.planning/phases/36-disk-enforcement/36-CONTEXT.md` — complete read; all 16 decisions confirmed

### Secondary (MEDIUM confidence)

- `.planning/REQUIREMENTS.md` — DISK-04, DISK-05, AUDIT-02 definitions confirmed
- `.planning/STATE.md` — phase status confirmed (ready to plan)
- `.planning/config.json` — validation enabled (`tests: true`, no `nyquist_validation: false`)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — zero new dependencies; all libraries confirmed present and in use
- Architecture: HIGH — all patterns derived by direct source code reading; no guesswork
- Pitfalls: HIGH — pitfalls 1-3 derived from reading Phase 33-35 code and CONTEXT decisions; pitfall 4-5 from reading usb.rs dispatch code

**Research date:** 2026-05-04
**Valid until:** 2026-06-03 (stable; no external dependencies; all facts are codebase-internal)
