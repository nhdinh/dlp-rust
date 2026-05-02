# Phase 34: BitLocker Verification — Pattern Map

**Mapped:** 2026-05-02
**Files analyzed:** 9 (2 NEW, 7 MODIFY)
**Analogs found:** 9 / 9

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `dlp-agent/src/detection/encryption.rs` (NEW) | service / detector | event-driven (startup) + periodic poll + WMI request-response | `dlp-agent/src/detection/disk.rs` | exact |
| `dlp-common/src/disk.rs` (MODIFY — enums + 3 fields) | model | data | same file (`BusType` + `DiskIdentity`) | exact (in-file analog) |
| `dlp-common/src/lib.rs` (MODIFY — re-exports) | config / barrel | data | existing `pub use disk::{...}` block | exact |
| `dlp-agent/src/config.rs` (MODIFY — `[encryption]` section) | config | data + validation | existing `AgentConfig` field pattern (`heartbeat_interval_secs`) | exact |
| `dlp-agent/src/detection/mod.rs` (MODIFY — re-export) | barrel | data | existing `pub mod disk; pub use disk::{...};` | exact |
| `dlp-agent/src/service.rs` (MODIFY — chain task) | wiring | event-driven | existing `spawn_disk_enumeration_task` call site (lines 622–632) | exact |
| `dlp-agent/Cargo.toml` (MODIFY — add `wmi`, bump `windows`) | config | data | existing `windows = "0.58"` features block (lines 36–68) | exact |
| `dlp-common/Cargo.toml` (MODIFY — bump `windows` 0.61 → 0.62) | config | data | existing `windows = "0.61"` features block (lines 22–35) | exact |
| `dlp-agent/tests/encryption_integration.rs` (NEW) | test | request-response | `dlp-agent/tests/device_registry_cache.rs` | role-match (cache + arrange/act/assert harness; no spawn-task analog exists) |

---

## Pattern Assignments

### 1. `dlp-agent/src/detection/encryption.rs` (NEW — controller / service)

**Analog:** `dlp-agent/src/detection/disk.rs`
**Why:** This is the canonical "global singleton + parking_lot::RwLock state + spawn-task with retry-then-fail-closed-audit" detector pattern that CONTEXT.md D-18 / D-20 explicitly says `EncryptionChecker` must mirror. Same crate, same module folder, same lifecycle.

**Module-level docstring + imports** — copy header shape:

```rust
// dlp-agent/src/detection/disk.rs:1-32
//! Disk enumeration background task and in-memory disk registry.
//!
//! Spawns at agent startup, enumerates fixed disks, emits audit events, and
//! maintains an in-memory cache of discovered disks for Phase 35/36 consumption.
//!
//! ## Lifecycle
//!
//! 1. `service.rs` calls `set_disk_enumerator(Arc::new(DiskEnumerator::new()))`
//!    during startup.
// ...
use dlp_common::{DiskIdentity, enumerate_fixed_disks, get_boot_drive_letter};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};
```

**Singleton struct + Default + unsafe Send/Sync** — copy 1:1, swap field types:

```rust
// dlp-agent/src/detection/disk.rs:43-106
#[derive(Debug)]
pub struct DiskEnumerator {
    pub discovered_disks: RwLock<Vec<DiskIdentity>>,
    pub drive_letter_map: RwLock<HashMap<char, DiskIdentity>>,
    pub instance_id_map: RwLock<HashMap<String, DiskIdentity>>,
    pub enumeration_complete: RwLock<bool>,
}

impl DiskEnumerator {
    pub fn new() -> Self {
        Self {
            discovered_disks: RwLock::new(Vec::new()),
            // ...
            enumeration_complete: RwLock::new(false),
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        *self.enumeration_complete.read()
    }
}

impl Default for DiskEnumerator { fn default() -> Self { Self::new() } }

// SAFETY: DiskEnumerator contains only RwLock<T> where T: Send + Sync.
unsafe impl Send for DiskEnumerator {}
unsafe impl Sync for DiskEnumerator {}
```

**Variation needed:** swap `discovered_disks: RwLock<Vec<DiskIdentity>>` for the fields specified in CONTEXT.md `<specifics>`:

```rust
// Target shape for EncryptionChecker (from 34-CONTEXT.md <specifics>):
pub struct EncryptionChecker {
    pub encryption_status_map: parking_lot::RwLock<HashMap<String, EncryptionStatus>>,
    pub last_check_at: parking_lot::RwLock<Option<DateTime<Utc>>>,
    pub check_complete: parking_lot::RwLock<bool>,
    // Add: is_first_check: RwLock<bool> for D-16 "alert on initial total failure only"
    //      (Pitfall E in 34-RESEARCH.md — flag must flip after first attempt regardless of outcome).
}
```

**Global OnceLock + setter/getter** — copy verbatim, rename:

```rust
// dlp-agent/src/detection/disk.rs:112-131
static DISK_ENUMERATOR: OnceLock<Arc<DiskEnumerator>> = OnceLock::new();

pub fn set_disk_enumerator(enumerator: Arc<DiskEnumerator>) {
    let _ = DISK_ENUMERATOR.set(enumerator);
}

#[must_use]
pub fn get_disk_enumerator() -> Option<Arc<DiskEnumerator>> {
    DISK_ENUMERATOR.get().cloned()
}
```

**Variation needed:** rename to `ENCRYPTION_CHECKER` / `set_encryption_checker` / `get_encryption_checker`. Identical body.

**Async spawn task with retry-and-fail-closed** — copy schedule, swap inner work:

```rust
// dlp-agent/src/detection/disk.rs:151-229
pub fn spawn_disk_enumeration_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    _agent_config_path: Option<String>,
) {
    runtime_handle.spawn(async move {
        let retry_delays = [
            Duration::from_millis(200),
            Duration::from_millis(1000),
            Duration::from_millis(4000),
        ];
        let mut last_error: Option<String> = None;

        for (attempt, delay) in retry_delays.iter().enumerate() {
            info!(attempt = attempt + 1, "starting fixed disk enumeration");
            match enumerate_fixed_disks() {
                Ok(mut disks) => {
                    // ... mutate global state via RwLock writers ...
                    if let Some(enumerator) = get_disk_enumerator() {
                        let mut discovered = enumerator.discovered_disks.write();
                        let mut drive_map = enumerator.drive_letter_map.write();
                        let mut instance_map = enumerator.instance_id_map.write();
                        let mut complete = enumerator.enumeration_complete.write();
                        *discovered = disks.clone();
                        // ...
                        *complete = true;
                    }
                    emit_disk_discovery(&audit_ctx, &disks);
                    info!(disk_count = disks.len(), "fixed disk enumeration complete");
                    return;
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    warn!(attempt = attempt + 1, error = %e,
                          "disk enumeration failed -- will retry");
                    if attempt < retry_delays.len() - 1 {
                        sleep(*delay).await;
                    }
                }
            }
        }
        // All retries exhausted -- fail closed.
        let error_msg = last_error.unwrap_or_else(|| "unknown error".to_string());
        error!(error = %error_msg,
               "disk enumeration failed after all retries -- failing closed");
        emit_disk_enumeration_failed(&audit_ctx, &error_msg);
    });
}
```

**Variations needed:**
- Replace `[200ms, 1s, 4s]` with `[100ms, 500ms]` per CONTEXT.md "discretion" (per-disk transient WMI retry, two attempts).
- Replace `enumerate_fixed_disks()` (sync `Result`) with the per-disk fan-out (`tokio::task::JoinSet` of `tokio::task::spawn_blocking` wrapped in `tokio::time::timeout(Duration::from_secs(5), …)` per RESEARCH §"DCOM / WMI in Tokio Pattern A").
- After the in-task work returns, **chain a `tokio::time::interval(recheck_interval)` loop** for the periodic re-check (D-10). The loop body re-runs the same per-disk fan-out and compares `EncryptionStatus` against the cached value to decide whether to emit `DiskDiscovery` with `with_justification("encryption status changed: …")` (D-12, D-25) or silently update `encryption_checked_at`.
- Update `DiskEnumerator` writers in place (D-20): `enumerator.instance_id_map.write().get_mut(&id).map(|d| d.encryption_status = Some(new))` — never replace the whole map.
- Mutate the `is_first_check` flag exactly once after the first attempt (Pitfall E).

**Audit emission helpers** — copy verbatim, rename event resource path:

```rust
// dlp-agent/src/detection/disk.rs:239-279
fn emit_disk_discovery(ctx: &crate::audit_emitter::EmitContext, disks: &[DiskIdentity]) {
    use dlp_common::{Action, Classification, Decision, EventType, AuditEvent};

    let mut event = AuditEvent::new(
        EventType::DiskDiscovery,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        "disk://discovery".to_string(),
        Classification::T1,
        Action::READ,
        Decision::ALLOW,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_discovered_disks(Some(disks.to_vec()));
    crate::audit_emitter::emit_audit(ctx, &mut event);
}

fn emit_disk_enumeration_failed(ctx: &crate::audit_emitter::EmitContext, error: &str) {
    use dlp_common::{Action, Classification, Decision, EventType, AuditEvent};

    let mut event = AuditEvent::new(
        EventType::Alert,
        ctx.user_sid.clone(),
        ctx.user_name.clone(),
        "disk://enumeration-failed".to_string(),
        Classification::T4,
        Action::READ,
        Decision::DENY,
        ctx.agent_id.clone(),
        ctx.session_id,
    )
    .with_justification(format!("Disk enumeration failed after 3 retries: {error}"));
    crate::audit_emitter::emit_audit(ctx, &mut event);
}
```

**Variations needed:**
- Reuse `EventType::DiskDiscovery` for the post-Phase-34 "disks vector now carries encryption fields" emission (D-09, D-24). Phase 34's `emit_disk_discovery` chain may add `.with_justification("encryption status changed: …")` when D-25 fires.
- Resource path for the all-disks-failed Alert (D-16): `"encryption://verification-failed"` (parallel to `"disk://enumeration-failed"`).

**Tests in `#[cfg(test)] mod tests`** — copy harness shape:

```rust
// dlp-agent/src/detection/disk.rs:285-499
#[cfg(test)]
mod tests {
    use super::*;
    use dlp_common::{BusType, DiskIdentity};

    #[test]
    fn test_disk_enumerator_default_empty() {
        let enumerator = DiskEnumerator::new();
        assert!(enumerator.all_disks().is_empty());
        assert!(!enumerator.is_ready());
    }

    #[test]
    fn test_global_static_get_set() {
        let enumerator = Arc::new(DiskEnumerator::new());
        set_disk_enumerator(Arc::clone(&enumerator));
        let retrieved = get_disk_enumerator();
        assert!(retrieved.is_some());
        assert!(Arc::ptr_eq(&enumerator, &retrieved.unwrap()));
    }
    // ... emit-builds-correct-event tests ...
}
```

---

### 2. `dlp-common/src/disk.rs` (MODIFY — add enums + 3 fields)

**Analog:** in-file `BusType` (lines 73–110) and `DiskIdentity` (lines 116–138).
**Why:** D-06 / D-07 explicitly say "alongside `BusType`" and D-08 says "additive `Option<...>` fields on the existing struct."

**Enum shape — copy `BusType` (lines 73–110):**

```rust
// dlp-common/src/disk.rs:73-87
/// Physical bus type of a storage device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BusType {
    /// Bus type could not be determined.
    #[default]
    Unknown,
    /// Serial ATA.
    Sata,
    /// NVM Express.
    Nvme,
    /// USB-bridged enclosure or native USB storage.
    Usb,
    /// SCSI or SAS.
    Scsi,
}
```

**Variations needed for `EncryptionStatus`:**
- Drop `Copy` (`Encrypted`, `Suspended`, `Unencrypted`, `Unknown` are all unit variants so `Copy` is fine — keep it; CONTEXT.md D-06 omits `Copy` but Pitfall D's explicit-disambiguation requirement reads better with `Copy + PartialEq`. **Keep `Copy`.**)
- Use `#[default] Unknown` per Assumption A4 in RESEARCH.md.
- Doc-comment each variant with the `(ProtectionStatus, ConversionStatus)` derivation per CONTEXT.md `<specifics>` table.

**Variations needed for `EncryptionMethod`:**
- 9 variants (None, Aes128Diffuser, Aes256Diffuser, Aes128, Aes256, Hardware, XtsAes128, XtsAes256, Unknown).
- Add `impl From<u32> for EncryptionMethod` mirroring `BusType::from(u32)` below.

**`From<u32>` impl — copy `BusType::from` (lines 89–110):**

```rust
// dlp-common/src/disk.rs:89-110
impl From<u32> for BusType {
    /// Maps raw `STORAGE_BUS_TYPE` values to the project `BusType` enum.
    fn from(raw: u32) -> Self {
        match raw {
            1 => Self::Scsi,
            7 => Self::Usb,
            8 => Self::Sata,
            17 => Self::Nvme,
            _ => Self::Unknown,
        }
    }
}
```

**Variation:** `EncryptionMethod::from(0..=7) -> known variants; _ => Unknown` per the WMI table in CONTEXT.md `<canonical_refs>`.

**`DiskIdentity` field-extension shape — copy lines 112–138:**

```rust
// dlp-common/src/disk.rs:112-138
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DiskIdentity {
    /// Device instance ID (e.g., `PCIIDE\IDECHANNEL\4&1234&0&0`).
    pub instance_id: String,
    pub bus_type: BusType,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive_letter: Option<char>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub is_boot_disk: bool,
}
```

**Variations needed (D-08):**
- Add three trailing fields, all guarded by `#[serde(skip_serializing_if = "Option::is_none")]` to keep wire format compact and preserve Pitfall D's `None` vs `Some(Unknown)` disambiguation:
  ```rust
  #[serde(skip_serializing_if = "Option::is_none")]
  pub encryption_status: Option<EncryptionStatus>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub encryption_method: Option<EncryptionMethod>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub encryption_checked_at: Option<chrono::DateTime<chrono::Utc>>,
  ```
- The struct-level `#[serde(default)]` already covers backward-compat ingest of pre-Phase-34 records (verified by existing `test_disk_identity_deserialize_empty_object` at lines 718–727).

**Test pattern — copy `test_bus_type_*` and `test_disk_identity_*` (lines 653–744):**

```rust
// dlp-common/src/disk.rs:663-688
#[test]
fn test_bus_type_serde_round_trip() {
    for bt in [BusType::Unknown, BusType::Sata, BusType::Nvme, BusType::Usb, BusType::Scsi] {
        let json = serde_json::to_string(&bt).unwrap();
        let rt: BusType = serde_json::from_str(&json).unwrap();
        assert_eq!(bt, rt, "serde round-trip failed for {bt:?}");
    }
}

#[test]
fn test_bus_type_snake_case_serde() {
    assert_eq!(serde_json::to_string(&BusType::Sata).unwrap(), "\"sata\"");
    // ...
}
```

**Variations needed:**
- `test_encryption_status_serde` (round-trip all 4 variants).
- `test_encryption_method_from_raw` (0..=7 mapped, 99 -> Unknown).
- `test_disk_identity_backward_compat_no_encryption_fields` — deserialize a JSON record without the three new fields and assert all three are `None` (mirror line 718).

---

### 3. `dlp-common/src/lib.rs` (MODIFY — extend re-exports)

**Analog:** existing block at lines 21–23.
**Why:** D-19 adds `EncryptionStatus` and `EncryptionMethod` to the same crate's public surface; the existing `pub use disk::{...}` line is the literal target.

```rust
// dlp-common/src/lib.rs:21-23
pub use disk::{
    enumerate_fixed_disks, get_boot_drive_letter, is_usb_bridged, BusType, DiskError, DiskIdentity,
};
```

**Variation needed:** extend the brace list to include the new enums (alphabetic ordering matches existing style):

```rust
pub use disk::{
    enumerate_fixed_disks, get_boot_drive_letter, is_usb_bridged, BusType, DiskError, DiskIdentity,
    EncryptionMethod, EncryptionStatus,
};
```

---

### 4. `dlp-agent/src/config.rs` (MODIFY — add `[encryption]` section + clamp)

**Analog:** existing `heartbeat_interval_secs: Option<u64>` field on `AgentConfig` (lines 91–94) plus the `resolved_log_level` accessor (lines 240–254) and tests at lines 318–373.
**Why:** D-11 adds one TOML key `recheck_interval_secs` with bounds [300, 86400] and a `warn!` log on out-of-range — same shape as the existing `heartbeat_interval_secs: Option<u64>` plus the existing `resolved_log_level` warn-on-unknown pattern.

**Field shape — copy lines 91–99:**

```rust
// dlp-agent/src/config.rs:91-99
/// Heartbeat interval in seconds. When `None`, the agent uses its
/// compiled default (30 seconds). Populated by server config push.
#[serde(default)]
pub heartbeat_interval_secs: Option<u64>,

/// Whether offline event caching is enabled. When `None`, defaults
/// to `true`. Populated by server config push.
#[serde(default)]
pub offline_cache_enabled: Option<bool>,
```

**Variations needed (D-11):**
- Add a nested `EncryptionConfig` substruct (CONTEXT.md "Integration Points" calls for `pub encryption: EncryptionConfig`):
  ```rust
  #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
  pub struct EncryptionConfig {
      #[serde(default)]
      pub recheck_interval_secs: Option<u64>,
  }
  ```
- Add `#[serde(default)] pub encryption: EncryptionConfig` to `AgentConfig`.
- Add a `resolved_recheck_interval(&self) -> Duration` accessor that clamps (300, 86400) and `warn!`s on out-of-range — pattern below.

**Clamp + warn-on-out-of-range — copy `resolved_log_level` shape (lines 240–254):**

```rust
// dlp-agent/src/config.rs:240-254
pub fn resolved_log_level(&self) -> tracing::Level {
    match self
        .log_level
        .as_deref()
        .unwrap_or("trace")
        .to_ascii_lowercase()
        .as_str()
    {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    }
}
```

**Variation needed:**

```rust
const ENCRYPTION_RECHECK_DEFAULT_SECS: u64 = 21_600; // 6 hours
const ENCRYPTION_RECHECK_MIN_SECS: u64     = 300;     // 5 minutes
const ENCRYPTION_RECHECK_MAX_SECS: u64     = 86_400;  // 24 hours

pub fn resolved_recheck_interval(&self) -> std::time::Duration {
    let raw = self.encryption.recheck_interval_secs
        .unwrap_or(ENCRYPTION_RECHECK_DEFAULT_SECS);
    let clamped = raw.clamp(ENCRYPTION_RECHECK_MIN_SECS, ENCRYPTION_RECHECK_MAX_SECS);
    if clamped != raw {
        warn!(requested = raw, applied = clamped,
              "encryption.recheck_interval_secs out of range [{}, {}] -- clamped",
              ENCRYPTION_RECHECK_MIN_SECS, ENCRYPTION_RECHECK_MAX_SECS);
    }
    std::time::Duration::from_secs(clamped)
}
```

**Test shape — copy lines 367–373 + 449–474:**

```rust
// dlp-agent/src/config.rs:367-373
#[test]
fn test_agent_config_new_fields_deserialize() {
    let toml_str = "heartbeat_interval_secs = 60\noffline_cache_enabled = false\n";
    let config: AgentConfig = toml::from_str(toml_str).expect("deserialize");
    assert_eq!(config.heartbeat_interval_secs, Some(60u64));
    assert_eq!(config.offline_cache_enabled, Some(false));
}
```

**Variations needed:** `test_encryption_recheck_interval_clamp` (0 → 300, 999_999 → 86_400, 21_600 → 21_600), `test_encryption_section_absent_uses_default` (per RESEARCH §"Phase Requirements -> Test Map" rows 10–11).

---

### 5. `dlp-agent/src/detection/mod.rs` (MODIFY — register module + re-export)

**Analog:** existing barrel block at lines 8–14.
**Why:** identical mechanical addition.

```rust
// dlp-agent/src/detection/mod.rs:1-14
//! Exfiltration detection modules (Sprint 14, T-13–T-14).
//!
//! Monitors USB mass storage and outbound SMB connections.
//!
//! - [`usb`] — USB mass storage detection via `GetDriveTypeW` (T-13).
//! - [`network_share`] — SMB outbound connection whitelisting (T-14).

pub mod disk;
pub mod network_share;
pub mod usb;

pub use disk::{DiskEnumerator, get_disk_enumerator, set_disk_enumerator, spawn_disk_enumeration_task};
pub use network_share::{NetworkShareDetector, SmbMonitor, SmbShareEvent};
pub use usb::UsbDetector;
```

**Variations needed:**
- Add `pub mod encryption;` after `pub mod disk;`.
- Add `pub use encryption::{EncryptionChecker, get_encryption_checker, set_encryption_checker, spawn_encryption_check_task};` after the existing `disk::{...}` re-export.
- Update the module-level docstring with one bullet for the new module.

---

### 6. `dlp-agent/src/service.rs` (MODIFY — chain `spawn_encryption_check_task`)

**Analog:** existing block at lines 622–632 (verified by Grep above).
**Why:** Phase 34's startup verification runs immediately after Phase 33's enumeration completes (D-04, D-10).

```rust
// dlp-agent/src/service.rs:622-632
// ── Disk Enumeration (Phase 33) ───────────────────────────────────────
// Initialize the DiskEnumerator and spawn the background enumeration task.
// This runs after USB setup so both detectors are available for Phase 36.
let disk_enumerator = Arc::new(crate::detection::DiskEnumerator::new());
crate::detection::disk::set_disk_enumerator(Arc::clone(&disk_enumerator));
crate::detection::disk::spawn_disk_enumeration_task(
    tokio::runtime::Handle::current(),
    audit_ctx.clone(),
    None, // Phase 35 will pass the allowlist TOML path here
);
info!("disk enumeration task spawned");
```

**Variations needed:**
- Append a sibling block right after `info!("disk enumeration task spawned")`:
  ```rust
  // ── BitLocker Verification (Phase 34) ─────────────────────────────────
  // Initialize the EncryptionChecker and spawn the background check task.
  // The task waits on DiskEnumerator.is_ready() before its first scan
  // (D-04 — sequential, encryption depends on enumeration), then loops
  // every `recheck_interval` for periodic drift detection (D-10).
  let encryption_checker = Arc::new(crate::detection::EncryptionChecker::new());
  crate::detection::encryption::set_encryption_checker(Arc::clone(&encryption_checker));
  crate::detection::encryption::spawn_encryption_check_task(
      tokio::runtime::Handle::current(),
      audit_ctx.clone(),
      agent_config.resolved_recheck_interval(),
  );
  info!("encryption check task spawned");
  ```
- The task itself owns the "wait for `DiskEnumerator::is_ready()`" loop (poll the global `get_disk_enumerator()` with a small sleep) — this is the `EncryptionChecker` internal concern, not `service.rs`.

---

### 7. `dlp-agent/Cargo.toml` (MODIFY — add `wmi`, bump `windows`)

**Analog:** existing `windows = "0.58"` block at lines 36–68; existing per-line dependency entries at lines 17–84.
**Why:** D-21 (wmi) and D-22 (windows bump) are pure metadata edits in the same file.

```toml
# dlp-agent/Cargo.toml:36-68
windows = { version = "0.58", features = [
    "Win32_Foundation",
    # identity.rs: ConvertSidToStringSidW, ConvertStringSidToSidW (Authorization submodule)
    "Win32_Security",
    "Win32_Security_Authorization",
    # ... 28 more features ...
    "Win32_System_Registry",                       # already present (line 53)
    # ... clipboard / WNet / device-installation ...
] }
```

**Variations needed:**
- Bump `version = "0.58"` -> `version = "0.62"` on line 36 (D-22).
- The existing feature `Win32_System_Registry` (line 53) is already present — no addition needed.
- Add a new dependency line for wmi after the existing block (D-21 / D-21a — pin 0.14):
  ```toml
  # WMI for BitLocker queries (Phase 34 — Win32_EncryptableVolume in
  # ROOT\CIMV2\Security\MicrosoftVolumeEncryption). Pinned at 0.14 per D-21a;
  # planner may propose 0.18 at plan-acceptance time per RESEARCH §Open Questions §1.
  wmi = { version = "0.14", features = ["chrono"] }
  ```
- Place near the other Windows-adjacent deps (after `windows = {...}` block, before `bcrypt`).

---

### 8. `dlp-common/Cargo.toml` (MODIFY — bump `windows` 0.61 → 0.62)

**Analog:** existing `windows = "0.61"` block at lines 22–35.
**Why:** D-22 mandates workspace convergence on `windows = 0.62`.

```toml
# dlp-common/Cargo.toml:21-35
[target.'cfg(windows)'.dependencies]
windows = { version = "0.61", features = [
    "Win32_NetworkManagement_NetManagement",
    "Win32_NetworkManagement_Ndis",
    "Win32_NetworkManagement_IpHelper",
    "Win32_Networking_ActiveDirectory",
    "Win32_Networking_WinSock",
    "Win32_Foundation",
    "Win32_Devices_DeviceAndDriverInstallation",
    "Win32_System_Ioctl",
    "Win32_System_SystemInformation",
    "Win32_Storage_FileSystem",
    "Win32_System_IO",
    "Win32_Security",
] }
```

**Variation needed:** bump `version = "0.61"` -> `version = "0.62"` on line 22. No feature-flag changes required (RESEARCH §"Migration notes" verified each existing flag is stable across 0.58..0.62).

---

### 9. `dlp-agent/tests/encryption_integration.rs` (NEW)

**Analog:** `dlp-agent/tests/device_registry_cache.rs`.
**Why:** No existing integration test exercises a `parking_lot::RwLock`-backed singleton cache + lookup contract — this is the closest match. The Phase 33 detector logic has no `tests/disk_*.rs` file (verified by Glob — only `negative.rs`, `integration.rs`, `comprehensive.rs`, `device_registry_cache.rs`, `chrome_pipe.rs` exist).

**Test harness shape — copy lines 1–49:**

```rust
// dlp-agent/tests/device_registry_cache.rs:1-29
//! Integration tests for [`dlp_agent::device_registry::DeviceRegistryCache`] behavior.
//!
//! These tests verify the trust-tier lookup contract without starting the
//! Windows service or making any network calls. They run on all platforms
//! (the `DeviceRegistryCache` struct and its `trust_tier_for` / `seed_for_test`
//! methods are unconditionally compiled).

use dlp_agent::device_registry::DeviceRegistryCache;
use dlp_common::UsbTrustTier;

#[test]
fn test_empty_cache_returns_blocked() {
    // Arrange: empty cache (no seeded entries)
    let cache = DeviceRegistryCache::new();

    // Act + Assert: unknown device returns Blocked
    assert_eq!(
        cache.trust_tier_for("0951", "1666", "ABC"),
        UsbTrustTier::Blocked,
        "empty cache must return Blocked (default deny)"
    );
}
```

**Variations needed:**
- Use `dlp_agent::detection::EncryptionChecker` + `dlp_common::EncryptionStatus`.
- Test names per RESEARCH "Phase Requirements -> Test Map":
  - `test_empty_checker_status_lookup_returns_none`
  - `test_status_lookup_after_update`
  - `test_periodic_recheck_emits_on_change` (requires a mock `EncryptionBackend` trait — see RESEARCH §"Mockability tradeoffs")
  - `test_periodic_recheck_silent_when_unchanged`
  - `test_failure_yields_unknown_never_encrypted`
  - `test_unknown_disks_populate_justification`
  - `test_alert_only_on_initial_total_failure` (Pitfall E coverage)
- All tests must compile + run on non-Windows (no WMI/Registry calls in the test harness; all Win32 access is gated behind a `trait EncryptionBackend` or behind `#[cfg(windows)]` smoke tests).

---

## Shared Patterns

### A. `parking_lot::RwLock` interior + global `OnceLock<Arc<...>>` singleton

**Source:** `dlp-agent/src/detection/disk.rs:43-131`
**Apply to:** `EncryptionChecker` in `encryption.rs`.

```rust
// dlp-agent/src/detection/disk.rs:43-53 + 112-131
#[derive(Debug)]
pub struct DiskEnumerator {
    pub discovered_disks: RwLock<Vec<DiskIdentity>>,
    pub drive_letter_map: RwLock<HashMap<char, DiskIdentity>>,
    pub instance_id_map: RwLock<HashMap<String, DiskIdentity>>,
    pub enumeration_complete: RwLock<bool>,
}

static DISK_ENUMERATOR: OnceLock<Arc<DiskEnumerator>> = OnceLock::new();
pub fn set_disk_enumerator(enumerator: Arc<DiskEnumerator>) { let _ = DISK_ENUMERATOR.set(enumerator); }
#[must_use]
pub fn get_disk_enumerator() -> Option<Arc<DiskEnumerator>> { DISK_ENUMERATOR.get().cloned() }
```

### B. Audit emission via `EmitContext` + `emit_audit`

**Source:** `dlp-agent/src/audit_emitter.rs:225-281` + `dlp-agent/src/detection/disk.rs:239-279`
**Apply to:** every audit emission in `encryption.rs` (status-changed `DiskDiscovery` events; the all-disks-failed `Alert`).

```rust
// dlp-agent/src/audit_emitter.rs:225-238
#[derive(Debug, Clone)]
pub struct EmitContext {
    pub agent_id: String,
    pub session_id: u32,
    pub user_sid: String,
    pub user_name: String,
    pub machine_name: Option<String>,
}

// dlp-agent/src/audit_emitter.rs:269-281
pub fn emit_audit(ctx: &EmitContext, event: &mut AuditEvent) {
    event.agent_id.clone_from(&ctx.agent_id);
    event.session_id = ctx.session_id;
    if event.user_sid.is_empty() { event.user_sid.clone_from(&ctx.user_sid); }
    if event.user_name.is_empty() { event.user_name.clone_from(&ctx.user_name); }
    if let Err(e) = EMITTER.emit(event) { /* log + drop */ }
}
```

### C. Builder-chain for audit events

**Source:** `dlp-common/src/audit.rs:265-330`
**Apply to:** `emit_disk_discovery` (status-changed variant in encryption.rs uses `.with_justification(...)` and the existing `.with_discovered_disks(...)`).

```rust
// dlp-common/src/audit.rs:267-330
pub fn with_justification(mut self, justification: String) -> Self {
    self.justification = Some(justification);
    self
}

pub fn with_discovered_disks(mut self, disks: Option<Vec<DiskIdentity>>) -> Self {
    self.discovered_disks = disks;
    self
}
```

### D. `#[cfg(windows)]` module gate with non-Windows stubs

**Source:** `dlp-common/src/disk.rs:186-195` + `247-254`
**Apply to:** `dlp-agent/src/detection/encryption.rs` for the WMI / Registry primitives — non-Windows builds must compile and return `EncryptionStatus::Unknown` (mirrors `enumerate_fixed_disks` returning `Ok(Vec::new())` non-Windows).

```rust
// dlp-common/src/disk.rs:186-195
pub fn enumerate_fixed_disks() -> Result<Vec<DiskIdentity>, DiskError> {
    #[cfg(windows)]
    {
        enumerate_fixed_disks_windows()
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}
```

### E. `thiserror`-derived error enum mirroring `DiskError`

**Source:** `dlp-common/src/disk.rs:46-67`
**Apply to:** new `EncryptionError` in `encryption.rs` (variants: `ComInitFailed`, `WmiConnectionFailed`, `WmiQueryFailed`, `Timeout`, `RegistryOpenFailed`, `RegistryReadFailed`, `VolumeNotFound`, `TaskPanicked`).

```rust
// dlp-common/src/disk.rs:46-67
#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("WMI query failed: {0}")]
    WmiQueryFailed(String),
    #[error("SetupDi enumeration failed: {0}")]
    SetupDiFailed(String),
    #[error("IOCTL_STORAGE_QUERY_PROPERTY failed: {0}")]
    IoctlFailed(String),
    #[error("PnP tree walk failed: {0}")]
    PnpWalkFailed(String),
    #[error("failed to open disk device: {0}")]
    DeviceOpenFailed(String),
    #[error("invalid device instance ID")]
    InvalidInstanceId,
}
```

### F. Backward-compat deserialization test pattern

**Source:** `dlp-common/src/audit.rs:682-701` + `dlp-common/src/disk.rs:719-727`
**Apply to:** the new `test_disk_identity_backward_compat_no_encryption_fields` test in `dlp-common/src/disk.rs`.

```rust
// dlp-common/src/audit.rs:682-701
#[test]
fn test_audit_event_backward_compat_missing_discovered_disks() {
    let legacy = r#"{
        "timestamp": "2025-01-01T00:00:00Z",
        "event_type": "BLOCK",
        // ... no discovered_disks field ...
    }"#;
    let event: AuditEvent = serde_json::from_str(legacy).unwrap();
    assert!(event.discovered_disks.is_none());
}
```

---

## No Analog Found

None. Every Phase 34 file maps to a same-crate, same-role analog.

The only **structural novelty** Phase 34 introduces is:
1. `tokio::task::JoinSet` over `tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(...))` for per-disk WMI fan-out — RESEARCH.md §"DCOM / WMI in Tokio" supplies the canonical example (no in-codebase analog because Phase 33 enumerates synchronously inside one retry loop). Planner should treat the RESEARCH.md Pattern A code block (lines 322–358 of 34-RESEARCH.md) as the de facto analog.
2. `tokio::time::interval` periodic loop with cache-comparison change-detection — no in-codebase analog. Planner should treat the RESEARCH.md "Code Examples §3" block (lines 600–634) as the de facto analog. RESEARCH §Open Question §3 (jitter) is a planner-time decision.
3. WMI / `wmi-rs 0.14` connection setup with `set_proxy_blanket(AuthLevel::PktPrivacy)` — no in-codebase analog. Planner should treat RESEARCH.md "wmi-rs 0.14 Wire-up" §Connection construction + §Authentication (lines 100–143) as the de facto analog and centralize the connection construction in a single helper to prevent Pitfall F.
4. `windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey}` with the RAII `RegKey(HKEY)` Drop wrapper — no in-codebase analog. Planner should treat RESEARCH.md "Windows 0.62 Registry API" §"Recommended RAII wrapper pattern" (lines 226–280) as the de facto analog.

---

## Metadata

**Analog search scope:** `dlp-agent/src/detection/`, `dlp-agent/src/`, `dlp-common/src/`, `dlp-agent/tests/`, `dlp-agent/Cargo.toml`, `dlp-common/Cargo.toml`
**Files scanned:** 9 source files read in full + 4 grep/glob targeted searches
**Pattern extraction date:** 2026-05-02

---

## PATTERN MAPPING COMPLETE

**Phase:** 34 - bitlocker-verification
**Files classified:** 9
**Analogs found:** 9 / 9

### Coverage
- Files with exact analog: 8
- Files with role-match analog: 1 (`encryption_integration.rs` — closest is `device_registry_cache.rs`, a cache-lookup integration test rather than a spawn-task test, since no spawn-task integration test currently exists in the agent)
- Files with no analog: 0

### Key Patterns Identified
- Detector module = `parking_lot::RwLock` interior + global `OnceLock<Arc<...>>` singleton + `unsafe impl Send/Sync` + `spawn_X_task(handle, audit_ctx, …)` with retry-then-fail-closed (`DiskEnumerator` in `dlp-agent/src/detection/disk.rs`).
- Pure-data enums in `dlp-common::disk` carry `#[derive(..., Default)] + #[serde(rename_all = "snake_case")] + #[default] Unknown` and a `From<u32>` impl mapping raw Win32 values (`BusType` in `dlp-common/src/disk.rs:73-110`).
- Audit emission goes through `EmitContext` + `emit_audit(ctx, &mut event)` with builder-chain on `AuditEvent` (`dlp-agent/src/audit_emitter.rs:225-281`); reuse `EventType::DiskDiscovery` and `EventType::Alert` per D-24, no new variants.
- `AgentConfig` fields are `Option<T>` with `#[serde(default)]` and a `resolved_*()` accessor that applies defaults / clamps + `warn!` on out-of-range (`dlp-agent/src/config.rs:240-254`).
- Backward-compat ingest is guaranteed by `#[serde(default)]` at struct level + `#[serde(skip_serializing_if = "Option::is_none")]` per Option field, exercised by a "legacy JSON without new fields" deserialization test.
- `#[cfg(windows)]` Windows impl with non-Windows stub returning a safe default (`Ok(Vec::new())`, `None`, `false`) — `dlp-common/src/disk.rs:186-195`.

### File Created
`.planning/phases/34-bitlocker-verification/34-PATTERNS.md`

### Ready for Planning
Pattern mapping complete. Planner can now reference analog patterns in PLAN.md files.
