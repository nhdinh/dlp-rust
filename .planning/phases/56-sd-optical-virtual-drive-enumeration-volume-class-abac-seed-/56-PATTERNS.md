# Phase 56: SD/Optical/Virtual Drive Enumeration + Volume-Class ABAC (SEED-004) - Pattern Map

**Mapped:** 2026-05-29
**Files analyzed:** 14
**Analogs found:** 14 / 14

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-common/src/abac.rs` | model | CRUD | `dlp-common/src/abac.rs` (existing) | exact |
| `dlp-common/src/audit.rs` | model | event-driven | `dlp-common/src/audit.rs` (existing) | exact |
| `dlp-common/src/lib.rs` | config | re-export | `dlp-common/src/lib.rs` (existing) | exact |
| `dlp-agent/src/detection/usb.rs` | service | event-driven | `dlp-agent/src/detection/usb.rs` (existing) | exact |
| `dlp-agent/src/detection/device_watcher.rs` | middleware | event-driven | `dlp-agent/src/detection/device_watcher.rs` (existing) | exact |
| `dlp-agent/src/detection/mod.rs` | config | re-export | `dlp-agent/src/detection/mod.rs` (existing) | exact |
| `dlp-hook-dll/src/trampolines.rs` | middleware | request-response | `dlp-hook-dll/src/trampolines.rs` (existing) | exact |
| `dlp-hook-dll/src/volume_class_cache.rs` | utility | transform | `dlp-hook-dll/src/classification_cache.rs` | role-match |
| `dlp-server/src/policy_store.rs` | service | CRUD | `dlp-server/src/policy_store.rs` (existing) | exact |
| `dlp-admin-cli/src/app.rs` | model | CRUD | `dlp-admin-cli/src/app.rs` (existing) | exact |
| `dlp-admin-cli/src/screens/dispatch.rs` | controller | request-response | `dlp-admin-cli/src/screens/dispatch.rs` (existing) | exact |
| `dlp-admin-cli/src/screens/render.rs` | component | request-response | `dlp-admin-cli/src/screens/render.rs` (existing) | exact |
| `dlp-admin-cli/src/screens/allowlist.rs` | component | request-response | `dlp-admin-cli/src/screens/allowlist.rs` (existing) | exact |
| `dlp-agent/src/detection/encryption.rs` | service | event-driven | `dlp-agent/src/detection/encryption.rs` (existing) | exact |

## Pattern Assignments

### `dlp-common/src/abac.rs` (model, CRUD)

**Analog:** `dlp-common/src/abac.rs` (self)

**Imports pattern** (lines 1-8):
```rust
use crate::endpoint::AppIdentity;
use serde::{Deserialize, Serialize};
```

**VolumeClass enum pattern** (new, follow existing enum patterns at lines 117-129):
```rust
/// The class of a Windows volume for ABAC policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum VolumeClass {
    /// Local fixed disk (NTFS).
    #[default]
    LocalNTFS,
    /// USB removable storage.
    USBRemovable,
    /// SD card.
    SDCard,
    /// Optical drive (CD/DVD/Blu-ray).
    Optical,
    /// Virtual drive (VHD, VHDX, ISO mount, Daemon Tools).
    Virtual,
    /// Network share (mapped drive or UNC path).
    NetworkShare,
}

impl std::fmt::Display for VolumeClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::LocalNTFS => "LocalNTFS",
            Self::USBRemovable => "USBRemovable",
            Self::SDCard => "SDCard",
            Self::Optical => "Optical",
            Self::Virtual => "Virtual",
            Self::NetworkShare => "NetworkShare",
        })
    }
}
```

**AbacContext optional field pattern** (lines 249-269):
```rust
    /// Resolved identity of the application that initiated the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_application: Option<AppIdentity>,
    /// Resolved identity of the destination application (paste target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_application: Option<AppIdentity>,
    /// Source origin URL for browser clipboard events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<String>,
    /// Destination origin URL for browser clipboard events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_origin: Option<String>,
    /// The filesystem path of the resource, used for label-aware evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
```

**New fields to add after `resource_path`**:
```rust
    /// Volume class of the source path (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_volume_class: Option<VolumeClass>,
    /// Volume class of the destination path (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_volume_class: Option<VolumeClass>,
```

**PolicyCondition extension pattern** (lines 433-514):
```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "attribute", rename_all = "snake_case")]
pub enum PolicyCondition {
    // ... existing 9 variants ...
    /// Match by the source volume class.
    ///
    /// If `source_volume_class` is `None` on the [`AbacContext`], this condition does NOT match
    /// (fails closed — no volume class means the condition cannot be confirmed, per D-03).
    SourceVolumeClass {
        #[serde(rename = "op")]
        op: String,
        value: VolumeClass,
    },
    /// Match by the destination volume class.
    ///
    /// If `destination_volume_class` is `None` on the [`AbacContext`], this condition does NOT match
    /// (fails closed — no volume class means the condition cannot be confirmed, per D-03).
    DestinationVolumeClass {
        #[serde(rename = "op")]
        op: String,
        value: VolumeClass,
    },
}
```

**From<EvaluateRequest> for AbacContext conversion** (lines 397-430):
```rust
impl From<EvaluateRequest> for AbacContext {
    fn from(req: EvaluateRequest) -> Self {
        let resource_path = Some(req.resource.path.clone());
        Self {
            subject: req.subject,
            resource: req.resource,
            environment: req.environment,
            action: req.action,
            source_application: req.source_application,
            destination_application: req.destination_application,
            source_origin: req.source_origin,
            destination_origin: req.destination_origin,
            resource_path,
            // New fields default to None (serde default)
            source_volume_class: None,
            destination_volume_class: None,
        }
    }
}
```

---

### `dlp-common/src/audit.rs` (model, event-driven)

**Analog:** `dlp-common/src/audit.rs` (self)

**EventType extension pattern** (lines 28-89):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    // ... existing variants ...
    /// Phase 56: A volume arrived (USB, SD, optical, virtual, or network).
    VolumeArrival,
}
```

**routed_to_siem update** (lines 94-125):
Add `Self::VolumeArrival` to the `matches!` list in `routed_to_siem()`.

**AuditEvent builder pattern** (lines 402-430):
```rust
    /// Sets the volume class for a VolumeArrival event.
    pub fn with_volume_class(mut self, volume_class: VolumeClass) -> Self {
        // Add volume_class field to AuditEvent (new optional field)
        // Or use a dedicated field if added to struct
        self
    }
```

**AuditEvent optional field pattern** (lines 230-285):
```rust
    /// Source origin URL for Chrome Content Analysis clipboard events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<String>,
    /// Destination origin URL for Chrome Content Analysis clipboard events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_origin: Option<String>,
```

---

### `dlp-common/src/lib.rs` (config, re-export)

**Analog:** `dlp-common/src/lib.rs` (self)

**Export pattern** (lines 22-44):
```rust
pub use abac::*;
```

**Add after existing `pub use` statements**:
```rust
// VolumeClass is already re-exported via `pub use abac::*;` above.
// If a dedicated volume_class module is created, add:
// pub mod volume_class;
// pub use volume_class::VolumeClass;
```

---

### `dlp-agent/src/detection/usb.rs` (service, event-driven)

**Analog:** `dlp-agent/src/detection/usb.rs` (self)

**Imports pattern** (lines 32-46):
```rust
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use dlp_common::usb::{parse_usb_device_path, setupdi_description_for_device};
use dlp_common::{Classification, DeviceIdentity, UsbTrustTier};
use parking_lot::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
```

**GetDriveTypeW pattern** (lines 318-332):
```rust
    fn is_removable_drive(&self, letter: char) -> bool {
        use windows::Win32::Storage::FileSystem::GetDriveTypeW;
        const DRIVE_REMOVABLE: u32 = 2;
        let root: Vec<u16> = OsStr::new(&format!("{}:\\", letter))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };
        drive_type == DRIVE_REMOVABLE
    }
```

**UsbDetector extension pattern** (lines 50-74):
```rust
#[derive(Debug, Default)]
pub struct UsbDetector {
    pub blocked_drives: RwLock<HashSet<char>>,
    pub device_identities: RwLock<HashMap<char, DeviceIdentity>>,
    pub(crate) pending_identity: Mutex<Option<DeviceIdentity>>,
    // NEW: Volume class map for all drive letters (not just USB).
    pub volume_class_map: RwLock<HashMap<char, VolumeClass>>,
}
```

**Volume classification method** (new, based on `is_removable_drive`):
```rust
    /// Classifies a drive letter into a VolumeClass.
    ///
    /// Uses GetDriveTypeW for coarse bucketing, then WMI Win32_DiskDrive
    /// for disambiguation of removable (USB vs SD) and fixed (local vs virtual).
    #[cfg(windows)]
    pub fn classify_drive(&self, letter: char) -> VolumeClass {
        use windows::Win32::Storage::FileSystem::GetDriveTypeW;
        const DRIVE_REMOVABLE: u32 = 2;
        const DRIVE_FIXED: u32 = 3;
        const DRIVE_REMOTE: u32 = 4;
        const DRIVE_CDROM: u32 = 5;

        let root: Vec<u16> = OsStr::new(&format!("{}:\\", letter))
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };

        match drive_type {
            DRIVE_REMOTE => VolumeClass::NetworkShare,
            DRIVE_CDROM => VolumeClass::Optical,
            DRIVE_REMOVABLE => self.disambiguate_removable(letter),
            DRIVE_FIXED => self.disambiguate_fixed(letter),
            _ => VolumeClass::LocalNTFS, // fallback
        }
    }
```

**handle_volume_event_dispatch pattern** (lines 1070-1076):
```rust
#[cfg(windows)]
pub fn handle_volume_event_dispatch(event_type: u32) {
    let detector_opt = *DRIVE_DETECTOR.lock();
    if let Some(detector) = detector_opt {
        handle_volume_event(detector, event_type);
    }
}
```

**handle_volume_event extension** (lines 494-503):
```rust
#[cfg(windows)]
fn handle_volume_event(detector: &UsbDetector, event_type: u32) {
    let before: HashSet<char> = detector.blocked_drives.read().iter().copied().collect();
    let now_present = scan_removable_drives(detector);

    if event_type == DBT_DEVICEARRIVAL {
        handle_volume_arrival(detector, &before, &now_present);
        // NEW: classify and emit VolumeArrival for ALL volume types
        emit_volume_arrivals(detector, &before, &now_present);
    } else {
        handle_volume_removal(detector, &before, &now_present);
    }
}
```

**extract_drive_letter pattern** (lines 1133-1140):
```rust
fn extract_drive_letter(path: &str) -> Option<char> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        Some((bytes[0] as char).to_ascii_uppercase())
    } else {
        None
    }
}
```

---

### `dlp-agent/src/detection/device_watcher.rs` (middleware, event-driven)

**Analog:** `dlp-agent/src/detection/device_watcher.rs` (self)

**Deferred processing pattern** (lines 224-245):
```rust
#[cfg(windows)]
fn handle_disk_arrival(device_path: &str) {
    if let (Some(handle), Some(ctx)) = (RUNTIME_HANDLE.get(), AUDIT_CTX.get()) {
        let ctx = ctx.clone();
        let path = device_path.to_owned();
        std::mem::drop(handle.spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            crate::detection::disk::on_disk_arrival(&path, &ctx);
        }));
        return;
    }
}
```

**GUID_DEVINTERFACE_VOLUME dispatch** (lines 200-206):
```rust
#[cfg(windows)]
fn handle_volume_device_change(event_type: u32) {
    crate::detection::usb::handle_volume_event_dispatch(event_type);
}
```

**dispatch_device_change routing** (lines 264-302):
```rust
unsafe fn dispatch_device_change(event_type: u32, lparam: LPARAM) {
    // ... header checks ...
    if classguid == GUID_DEVINTERFACE_VOLUME {
        handle_volume_device_change(event_type);
        return;
    }
    // ... other GUIDs ...
}
```

---

### `dlp-agent/src/detection/mod.rs` (config, re-export)

**Analog:** `dlp-agent/src/detection/mod.rs` (self)

**Module export pattern** (lines 12-31):
```rust
pub mod app_identity;
pub mod device_watcher;
pub mod disk;
pub mod encryption;
pub mod network_share;
pub mod usb;

pub use device_watcher::{...};
pub use disk::{...};
pub use encryption::{...};
pub use network_share::{...};
pub use usb::UsbDetector;
```

**Add if new volume classification module is created**:
```rust
// pub mod volume_class;
// pub use volume_class::{VolumeClassCache, classify_drive_letter};
```

---

### `dlp-hook-dll/src/trampolines.rs` (middleware, request-response)

**Analog:** `dlp-hook-dll/src/trampolines.rs` (self)

**classify_and_log_path pattern** (lines 83-323):
```rust
fn classify_and_log_path(
    path: &str,
    action: &str,
    fn_name: &str,
    handle_value: u64,
    journal_op: u8,
) -> Option<crate::fail_closed::DenyReturn> {
    let path_hash = crate::hash_path(path);
    let op = if is_write_action(action) { HookOp::Write } else { HookOp::Read };
    // ... existing classification logic ...
    match crate::classify_path(path, action, crate::DEFAULT_PIPE_NAME) {
        Ok(crate::Decision::ALLOW) | Ok(crate::Decision::AllowWithLog) => { ... }
        Ok(crate::Decision::DENY) | Ok(crate::Decision::DenyWithAlert) => { ... }
        Err(_) => { ... }
    }
}
```

**Volume class resolution before classify_path** (new, inserted before pipe call):
```rust
    // Resolve volume class from path for ABAC context enrichment.
    let source_volume_class = resolve_volume_class_from_path(path);
    let destination_volume_class = if action.eq_ignore_ascii_case("COPY") || action.eq_ignore_ascii_case("MOVE") {
        // For copy/move, destination is the same path (target). Hook DLL
        // may need additional path extraction for destination.
        None
    } else {
        None
    };
    
    // Pass volume classes to classify_path (extend HookRequest or use cache).
```

**CopyFileExW trampoline** (lines ~700+ in full file):
```rust
// CopyFileExW evaluates both source and destination paths.
// For each path, resolve volume class and populate AbacContext fields.
```

---

### `dlp-hook-dll/src/volume_class_cache.rs` (utility, transform)

**Analog:** `dlp-hook-dll/src/classification_cache.rs`

**Thread-local cache pattern** (lines 619-651):
```rust
pub mod lru {
    use super::*;

    thread_local! {
        static LRU: RefCell<LruCache> = RefCell::new(LruCache::new());
    }

    pub fn get(path: &str, current_version: u64) -> Option<Classification> { ... }
    pub fn insert(path: &str, classification: Classification, version: u64) { ... }
    pub fn clear_all() { ... }
}
```

**Volume class cache implementation** (new file):
```rust
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use dlp_common::VolumeClass;

const VOLUME_CLASS_TTL: Duration = Duration::from_secs(30);

thread_local! {
    static VOLUME_CLASS_CACHE: RefCell<HashMap<char, (VolumeClass, Instant)>> =
        RefCell::new(HashMap::new());
}

/// Resolves the volume class for a drive letter, using a thread-local cache.
pub fn resolve_volume_class(letter: char) -> VolumeClass {
    VOLUME_CLASS_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((class, inserted)) = cache.get(&letter) {
            if inserted.elapsed() < VOLUME_CLASS_TTL {
                return *class;
            }
        }
        // Cache miss or expired — query via pipe or fallback.
        let class = query_volume_class_from_agent(letter);
        cache.insert(letter, (class, Instant::now()));
        class
    })
}

/// Resolves volume class from a filesystem path.
pub fn resolve_volume_class_from_path(path: &str) -> Option<VolumeClass> {
    // UNC path check first.
    if path.starts_with("\\\\") {
        return Some(VolumeClass::NetworkShare);
    }
    // Drive letter extraction.
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let letter = (bytes[0] as char).to_ascii_uppercase();
        Some(resolve_volume_class(letter))
    } else {
        None
    }
}

fn query_volume_class_from_agent(letter: char) -> VolumeClass {
    // TODO: Implement pipe round-trip or shared-memory lookup.
    // Fallback for now.
    VolumeClass::LocalNTFS
}
```

---

### `dlp-server/src/policy_store.rs` (service, CRUD)

**Analog:** `dlp-server/src/policy_store.rs` (self)

**condition_matches extension** (lines 378-412):
```rust
fn condition_matches(
    condition: &PolicyCondition,
    ctx: &AbacContext,
    resource: &dlp_common::abac::Resource,
) -> bool {
    match condition {
        // ... existing 9 arms ...
        PolicyCondition::SourceVolumeClass { op, value } => {
            volume_class_matches(op, value, ctx.source_volume_class)
        }
        PolicyCondition::DestinationVolumeClass { op, value } => {
            volume_class_matches(op, value, ctx.destination_volume_class)
        }
    }
}
```

**New volume_class_matches helper** (after compare_op at lines 418-426):
```rust
/// Evaluates a volume-class condition against an optional actual value.
///
/// Returns `false` (fails closed) if the actual volume class is `None`.
fn volume_class_matches(op: &str, expected: &VolumeClass, actual: Option<VolumeClass>) -> bool {
    let Some(actual) = actual else {
        return false; // fails closed: no volume class means condition cannot be confirmed
    };
    match op {
        "eq" => actual == *expected,
        "ne" => actual != *expected,
        "in" => actual == *expected, // "in" with single value = eq
        _ => false,
    }
}
```

---

### `dlp-admin-cli/src/app.rs` (model, CRUD)

**Analog:** `dlp-admin-cli/src/app.rs` (self)

**ConditionAttribute extension** (lines 196-229):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionAttribute {
    Classification,
    MemberOf,
    DeviceTrust,
    NetworkLocation,
    AccessContext,
    SourceApplication,
    DestinationApplication,
    SourceOrigin,
    DestinationOrigin,
    // NEW:
    SourceVolumeClass,
    DestinationVolumeClass,
}

pub const ATTRIBUTES: [ConditionAttribute; 11] = [
    ConditionAttribute::Classification,
    ConditionAttribute::MemberOf,
    ConditionAttribute::DeviceTrust,
    ConditionAttribute::NetworkLocation,
    ConditionAttribute::AccessContext,
    ConditionAttribute::SourceApplication,
    ConditionAttribute::DestinationApplication,
    ConditionAttribute::SourceOrigin,
    ConditionAttribute::DestinationOrigin,
    ConditionAttribute::SourceVolumeClass,
    ConditionAttribute::DestinationVolumeClass,
];
```

**label() extension** (lines 236-248):
```rust
impl ConditionAttribute {
    pub fn label(self) -> &'static str {
        match self {
            // ... existing 9 arms ...
            Self::SourceVolumeClass => "Source Volume Class",
            Self::DestinationVolumeClass => "Destination Volume Class",
        }
    }
}
```

---

### `dlp-admin-cli/src/screens/dispatch.rs` (controller, request-response)

**Analog:** `dlp-admin-cli/src/screens/dispatch.rs` (self)

**operators_for extension** (lines 3126-3158):
```rust
pub(crate) fn operators_for(
    attr: ConditionAttribute,
    field: Option<dlp_common::abac::AppField>,
) -> &'static [(&'static str, bool)] {
    use dlp_common::abac::AppField;
    match attr {
        // ... existing arms ...
        ConditionAttribute::SourceVolumeClass | ConditionAttribute::DestinationVolumeClass => {
            &[("eq", true), ("ne", true), ("in", true)]
        }
    }
}
```

**value_count_for extension** (lines 3172-3188):
```rust
fn value_count_for(attr: ConditionAttribute, field: Option<dlp_common::abac::AppField>) -> usize {
    use dlp_common::abac::AppField;
    match attr {
        // ... existing arms ...
        ConditionAttribute::SourceVolumeClass | ConditionAttribute::DestinationVolumeClass => 6,
    }
}
```

**build_condition extension** (lines 3366-3397):
```rust
fn build_condition(...) -> Option<dlp_common::abac::PolicyCondition> {
    let op = op.to_string();
    match attr {
        // ... existing arms ...
        ConditionAttribute::SourceVolumeClass => {
            build_volume_class_condition(op, picker_selected, true)
        }
        ConditionAttribute::DestinationVolumeClass => {
            build_volume_class_condition(op, picker_selected, false)
        }
    }
}
```

**New volume class builder**:
```rust
fn build_volume_class_condition(
    op: String,
    picker_selected: usize,
    is_source: bool,
) -> Option<dlp_common::abac::PolicyCondition> {
    use dlp_common::VolumeClass;
    let value = match picker_selected {
        0 => VolumeClass::LocalNTFS,
        1 => VolumeClass::USBRemovable,
        2 => VolumeClass::SDCard,
        3 => VolumeClass::Optical,
        4 => VolumeClass::Virtual,
        5 => VolumeClass::NetworkShare,
        _ => return None,
    };
    if is_source {
        Some(dlp_common::abac::PolicyCondition::SourceVolumeClass { op, value })
    } else {
        Some(dlp_common::abac::PolicyCondition::DestinationVolumeClass { op, value })
    }
}
```

**condition_to_prefill extension** (lines 3495-3561):
```rust
fn condition_to_prefill(...) -> (ConditionAttribute, String, usize, String) {
    match cond {
        // ... existing arms ...
        PolicyCondition::SourceVolumeClass { op, value } => (
            ConditionAttribute::SourceVolumeClass,
            op.clone(),
            volume_class_to_idx(value),
            String::new(),
        ),
        PolicyCondition::DestinationVolumeClass { op, value } => (
            ConditionAttribute::DestinationVolumeClass,
            op.clone(),
            volume_class_to_idx(value),
            String::new(),
        ),
    }
}
```

**New helper**:
```rust
fn volume_class_to_idx(value: &dlp_common::VolumeClass) -> usize {
    match value {
        dlp_common::VolumeClass::LocalNTFS => 0,
        dlp_common::VolumeClass::USBRemovable => 1,
        dlp_common::VolumeClass::SDCard => 2,
        dlp_common::VolumeClass::Optical => 3,
        dlp_common::VolumeClass::Virtual => 4,
        dlp_common::VolumeClass::NetworkShare => 5,
    }
}
```

**condition_display extension** (lines 3569-3592):
```rust
pub fn condition_display(cond: &dlp_common::abac::PolicyCondition) -> String {
    match cond {
        // ... existing arms ...
        PolicyCondition::SourceVolumeClass { op, value } => {
            format!("SourceVolumeClass {op} {value}")
        }
        PolicyCondition::DestinationVolumeClass { op, value } => {
            format!("DestinationVolumeClass {op} {value}")
        }
    }
}
```

---

### `dlp-admin-cli/src/screens/render.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/render.rs` (self)

**Value constants pattern** (lines 496-519):
```rust
const CLASSIFICATION_VALUES: [&str; 4] = ["T1: Public", "T2: Internal", "T3: Confidential", "T4: Restricted"];
const DEVICE_TRUST_VALUES: [&str; 4] = ["Managed", "Unmanaged", "Compliant", "Unknown"];
const NETWORK_LOCATION_VALUES: [&str; 4] = ["Corporate", "CorporateVpn", "Guest", "Unknown"];
const ACCESS_CONTEXT_VALUES: [&str; 2] = ["Local", "Smb"];
```

**Add**:
```rust
const VOLUME_CLASS_VALUES: [&str; 6] = [
    "LocalNTFS",
    "USBRemovable",
    "SDCard",
    "Optical",
    "Virtual",
    "NetworkShare",
];
```

**picker_items extension** (lines 603-662):
```rust
fn picker_items(...) -> Vec<ListItem<'static>> {
    match step {
        // ... step 1 and 2 ...
        3 => {
            let attr = match selected_attribute { ... };
            match attr {
                // ... existing arms ...
                ConditionAttribute::SourceVolumeClass
                | ConditionAttribute::DestinationVolumeClass => VOLUME_CLASS_VALUES
                    .iter()
                    .map(|v| ListItem::new(v.to_string()))
                    .collect(),
            }
        }
        _ => vec![],
    }
}
```

**step_flags extension** (lines 831-868):
```rust
fn step_flags(...) -> (bool, bool) {
    // ... existing logic ...
    // Volume class attributes do NOT have a sub-step (no AppField equivalent).
    // They use picker in Step 3, so no text input.
    let is_text_input_step3 = is_member_of_step3 || is_app_text_step3 || is_origin_text_step3;
    (in_app_field_sub_step, is_text_input_step3)
}
```

---

### `dlp-admin-cli/src/screens/allowlist.rs` (component, request-response)

**Analog:** `dlp-admin-cli/src/screens/allowlist.rs` (self)

**AllowlistEntryUi extension** (lines 42-57):
```rust
#[derive(Debug, Clone)]
pub struct AllowlistEntryUi {
    pub id: String,
    pub match_type: String,
    pub value: String,
    pub description: String,
    pub category: String,
    pub priority: i64,
    pub enabled: bool,
    // NEW: volume class badge for SD/Optical/Virtual entries.
    pub volume_class: Option<String>,
}
```

**Render extension** (lines 211-216):
```rust
ListItem::new(format!(
    "{} {} | {} | {} | {}{}",
    status,
    entry.match_type,
    entry.value,
    entry.category,
    entry.description,
    entry.volume_class.as_ref().map(|v| format!(" | [{}]", v)).unwrap_or_default()
))
```

---

### `dlp-agent/src/detection/encryption.rs` (service, event-driven)

**Analog:** `dlp-agent/src/detection/encryption.rs` (self)

**WMI query pattern** (lines 46-55, 267+):
```rust
#[cfg(windows)]
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename = "Win32_EncryptableVolume")]
#[serde(rename_all = "PascalCase")]
struct EncryptableVolume {
    drive_letter: Option<String>,
    protection_status: Option<u32>,
    conversion_status: Option<u32>,
    encryption_method: Option<u32>,
}

let conn = wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2")?;
let volumes: Vec<EncryptableVolume> = conn.query()?;
```

**Win32_DiskDrive WMI struct for volume classification** (new):
```rust
#[cfg(windows)]
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename = "Win32_DiskDrive")]
#[serde(rename_all = "PascalCase")]
struct WmiDiskDrive {
    #[serde(rename = "DeviceID")]
    device_id: String,
    interface_type: Option<String>,
    media_type: Option<String>,
    model: Option<String>,
    #[serde(rename = "PNPDeviceID")]
    pnp_device_id: Option<String>,
}
```

**WMI connection with proxy blanket** (from encryption.rs):
```rust
let conn = wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2")?;
conn.set_proxy_blanket(wmi::AuthLevel::PktPrivacy)?;
```

---

## Shared Patterns

### Authentication/Authorization
**Source:** N/A for this phase — no new auth patterns.
**Apply to:** None.

### Error Handling
**Source:** `dlp-agent/src/detection/encryption.rs`
**Apply to:** All WMI query code in usb.rs volume classification.
```rust
#[derive(Debug, thiserror::Error)]
pub enum VolumeClassError {
    #[error("WMI connection failed: {0}")]
    WmiConnectionFailed(String),
    #[error("WMI query failed: {0}")]
    WmiQueryFailed(String),
    #[error("drive letter not found")]
    DriveLetterNotFound,
}
```

### WMI Query Pattern
**Source:** `dlp-agent/src/detection/encryption.rs`
**Apply to:** `dlp-agent/src/detection/usb.rs` volume classification.
```rust
#[cfg(windows)]
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(rename = "Win32_DiskDrive")]
#[serde(rename_all = "PascalCase")]
struct WmiDiskDrive {
    #[serde(rename = "DeviceID")]
    device_id: String,
    interface_type: Option<String>,
    media_type: Option<String>,
    model: Option<String>,
}

let conn = wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2")?;
let drives: Vec<WmiDiskDrive> = conn.query()?;
```

### Thread-Local Cache Pattern
**Source:** `dlp-hook-dll/src/classification_cache.rs`
**Apply to:** `dlp-hook-dll/src/volume_class_cache.rs`
```rust
thread_local! {
    static VOLUME_CLASS_CACHE: RefCell<HashMap<char, (VolumeClass, Instant)>> =
        RefCell::new(HashMap::new());
}
```

### Optional Field Serde Pattern
**Source:** `dlp-common/src/abac.rs`
**Apply to:** All new optional fields on `AbacContext` and `AuditEvent`.
```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub source_volume_class: Option<VolumeClass>,
```

### PolicyCondition Extension Pattern
**Source:** `dlp-common/src/abac.rs`
**Apply to:** New `SourceVolumeClass` and `DestinationVolumeClass` variants.
```rust
#[serde(tag = "attribute", rename_all = "snake_case")]
pub enum PolicyCondition {
    // existing variants...
    SourceVolumeClass { op: String, value: VolumeClass },
    DestinationVolumeClass { op: String, value: VolumeClass },
}
```

### Deferred Processing Pattern
**Source:** `dlp-agent/src/detection/device_watcher.rs`
**Apply to:** Volume arrival event emission (if deferred classification needed).
```rust
std::mem::drop(handle.spawn(async move {
    tokio::time::sleep(Duration::from_millis(500)).await;
    // ... classification and emission ...
}));
```

### Admin TUI 3-Step Builder Pattern
**Source:** `dlp-admin-cli/src/screens/dispatch.rs` + `render.rs`
**Apply to:** Volume class conditions builder.
- Step 1: Add `SourceVolumeClass` / `DestinationVolumeClass` to `ATTRIBUTES` array.
- Step 2: Add operator arm in `operators_for()` returning `[("eq", true), ("ne", true), ("in", true)]`.
- Step 3: Add value arm in `picker_items()` returning 6-element list; add `VOLUME_CLASS_VALUES` constant.
- Add builder function `build_volume_class_condition()`.
- Add prefill mapping `volume_class_to_idx()`.
- Add display arm in `condition_display()`.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| None | — | — | All files have strong analogs in the existing codebase. |

## Metadata

**Analog search scope:**
- `dlp-common/src/` — abac.rs, audit.rs, lib.rs
- `dlp-agent/src/detection/` — usb.rs, device_watcher.rs, mod.rs, encryption.rs
- `dlp-hook-dll/src/` — trampolines.rs, classification_cache.rs, lib.rs
- `dlp-server/src/` — policy_store.rs
- `dlp-admin-cli/src/` — app.rs, screens/dispatch.rs, screens/render.rs, screens/allowlist.rs

**Files scanned:** 14
**Pattern extraction date:** 2026-05-29
**Confidence:** HIGH — all patterns are derived from existing, proven code in the codebase.
