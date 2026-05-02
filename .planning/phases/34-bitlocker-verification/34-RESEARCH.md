# Phase 34 Research: BitLocker Verification

**Researched:** 2026-05-02
**Domain:** WMI BitLocker queries (`Win32_EncryptableVolume`), Windows Registry fallback, tokio + COM threading
**Confidence:** HIGH on wire-level APIs (verified against docs.rs and the wmi-rs README); MEDIUM on testability strategy (Win32 mocking has no perfect fit in Rust)
**Status of locked decisions:** Honored as written. CONTEXT.md D-21 pins `wmi = "0.14"` — see "Open Questions for Planner" for one upstream-version finding the planner should resolve before Wave 0.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CRYPT-01 | Agent can query BitLocker encryption status via WMI `Win32_EncryptableVolume` for each enumerated fixed disk. | Verified `WMIConnection::with_namespace_path("ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption", COMLibrary::new()?)` pattern below; wire-level wmi-rs `query::<T>()` returns `Vec<EncryptableVolume>` deserialized via serde. Status derivation table from CONTEXT.md (D-06) is implementable directly from `ProtectionStatus` + `ConversionStatus` fields. Per-disk join keyed via `DriveLetter` -> `DiskEnumerator.drive_letter_map`; instance-id-only disks (no drive letter) yield `EncryptionStatus::Unknown`. |
| CRYPT-02 | Unencrypted disks are flagged in the audit log with a warning; the admin decides allow/block via the allowlist (not hard-coded block). | The four-state enum (D-06) carries the warning signal; the existing `EventType::DiskDiscovery` audit pathway already routes to SIEM (verified in `dlp-common/src/audit.rs:62`). No new EventType is needed (D-24). The "admin decides via allowlist" half is satisfied by Phase 35; Phase 34 surfaces status only — it does NOT block. The Phase 36 enforcement code reads `DiskEnumerator.instance_id_map[id].encryption_status` but does not consume the status to make a block decision (CRYPT-02 explicitly forbids hard-coded block). |
</phase_requirements>

---

## Summary

Phase 34 layers a BitLocker verification stage on top of Phase 33's enumeration. The work is dominantly **integration glue**: the wmi-rs crate already provides ergonomic Rust wrappers around the WMI COM dance (`COMLibrary` + `WMIConnection::with_namespace_path` + `set_proxy_blanket(AuthLevel::PktPrivacy)` + `query::<T>()`), and the only novel Win32 surface is the Registry fallback (`RegOpenKeyExW` / `RegQueryValueExW` / `RegCloseKey`) which reads a single DWORD on the boot volume. The bulk of the planning work is shape-of-task, not technology selection.

The critical correctness invariant is **never produce a false-positive `Encrypted` reading**. WMI failure or namespace access denied must yield `EncryptionStatus::Unknown`, never the optimistic outcome. The four-state enum (Encrypted / Suspended / Unencrypted / Unknown) plus the per-disk justification carrying the failure reason gives the admin enough signal to allowlist with eyes open (CRYPT-02).

The research surfaced one finding the planner must resolve before Wave 0: **the wmi crate's current published version is `0.18.4` (Mar 2026), not `0.14` as locked in CONTEXT.md D-21**. The API surface used here (`with_namespace_path`, `set_proxy_blanket(AuthLevel::PktPrivacy)`, `query`) is identical across both versions, so this is a metadata question (deps audit / CVE posture / windows-crate compatibility), not a code-shape question. See "Open Questions for Planner" §1.

**Primary recommendation:** Build `EncryptionChecker` to mirror `DiskEnumerator` in shape (global `OnceLock<Arc<...>>`, `parking_lot::RwLock` interior, retry with exponential backoff, fail-closed audit on total failure). Run the per-disk WMI work inside `tokio::task::spawn_blocking` so each query gets its own thread for COM initialization; wrap the spawn-blocking handle in `tokio::time::timeout(Duration::from_secs(5), ...)` for the per-volume timeout (D-03). Use `JoinSet` only for fan-out coordination across disks, not as the timeout mechanism.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| BitLocker WMI query | dlp-agent (`detection/encryption.rs`) | — | Touches Win32 COM + WMI; must run in SYSTEM context; cannot live in `dlp-common` (D-19) which is pure-data. |
| Registry fallback (`HKLM\SYSTEM\...\BootStatus`) | dlp-agent (`detection/encryption.rs`) | — | Same rationale; the Registry call is a fallback to the WMI call and shares the encryption module's lifecycle. |
| `EncryptionStatus` / `EncryptionMethod` enums | dlp-common (`disk.rs`) | — | Pure data, consumed by server (Phase 37) and admin TUI (Phase 38) without dragging WMI/COM in (D-19). |
| Three new fields on `DiskIdentity` | dlp-common (`disk.rs`) | — | Audit wire format is shared via `dlp-common::AuditEvent.discovered_disks`. Adding `Option<...>` keeps the schema additive (D-08). |
| Periodic re-check scheduler | dlp-agent (`detection/encryption.rs`) | — | Tokio background task; cannot live anywhere else. |
| Mutating `DiskEnumerator` state on status change | dlp-agent (`detection/encryption.rs` writes via existing `RwLock`) | dlp-agent (`detection/disk.rs` exposes the locks) | D-20 — no API surface changes to `DiskEnumerator`; encryption module reaches into `discovered_disks`/`instance_id_map`/`drive_letter_map` writers. |
| Audit emission for status changes | dlp-agent (`audit_emitter.rs` reused) | — | Reuses `emit_audit` and the existing `EmitContext`; no new emitter functions required (D-24, D-25). |
| `[encryption]` TOML section | dlp-agent (`config.rs`) | — | Same crate as the rest of `AgentConfig`; clamp logic at load time. |

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `wmi` | `0.14` (per D-21) — but `0.18.4` is current; see Open Question §1 | WMI query layer for `Win32_EncryptableVolume` | Only actively maintained idiomatic Rust WMI wrapper; uses `windows` crate internally; serde-based deserialization; the README ships a verbatim BitLocker example. |
| `windows` | `0.62` (per D-22) | Registry APIs (`RegOpenKeyExW`, `RegQueryValueExW`, `RegCloseKey`) and `Win32_System_Registry` feature; aligns with `dlp-common` 0.61->0.62 across workspace. | Registry feature flag `Win32_System_Registry` is already enabled in `dlp-agent/Cargo.toml:53` (verified). Bumping 0.58->0.62 is necessary because `dlp-common` is at 0.61 and the workspace must converge. |
| `parking_lot` | workspace | Interior mutability for `EncryptionChecker.encryption_status_map` and reuse of `DiskEnumerator`'s existing locks | Mirrors Phase 33 `DiskEnumerator` pattern. |
| `tokio` | workspace | Async runtime; `JoinSet` for per-disk fan-out; `time::timeout` for the 5s per-volume cutoff; `task::spawn_blocking` for the COM-initialized worker thread | Already the agent's runtime. |
| `chrono` | `0.4` (already in `dlp-common/Cargo.toml:12`) | `DateTime<Utc>` for `encryption_checked_at` | Confirmed already present — D-23 satisfied without action. |
| `serde` + `serde_json` | workspace | Round-trip the WMI struct (PascalCase) and the new `DiskIdentity` Option fields | Already used. |
| `tracing` | workspace | Structured logging with `instance_id = %disk.instance_id`, `method = ...` fields per CONTEXT.md "discretion" guidance | Mandated by CLAUDE.md §9.1. |
| `thiserror` | workspace | New `EncryptionError` enum variants | Mandated by CLAUDE.md §9.4. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `tokio::task::JoinSet` | std-tokio | Concurrent per-disk WMI queries with bounded fan-out | One join handle per enumerated disk; collect results as they complete. |
| `tokio::time::sleep` / `tokio::time::interval` | std-tokio | 6-hour periodic re-check loop (D-10) | Already used in Phase 33 retry path. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `wmi` crate | Raw `windows::Win32::System::Wmi` | Rejected in STACK.md — ~200 lines of COM/VARIANT/SafeArray boilerplate vs. ~10 lines with wmi-rs. Locked. |
| `wmi` crate | Spawning `manage-bde.exe` and parsing text | Rejected — slow, fragile, requires text parsing, no programmatic guarantees. |
| `RegOpenKeyExW` raw | `winreg` crate | `winreg` is a thin wrapper but the workspace already uses `windows` crate's Registry submodule (`dlp-agent/Cargo.toml:53`). Adding a second registry crate is unnecessary. |
| `tokio::time::timeout` wrapping `spawn_blocking` | wmi-rs's own timeout API | wmi-rs 0.14 has no documented per-query timeout API (verified via docs.rs scan — only `filtered_notification` accepts a `Duration`). The blocking thread is sacrificial — it cannot be cancelled cleanly, but `tokio::time::timeout` lets the orchestrator move on. See "Pitfalls" §3. |

**Installation:**
```bash
# In dlp-agent/Cargo.toml only — dlp-common stays WMI-free per D-19.
cargo add wmi@0.14 --features chrono                # if D-21 lock holds
cargo add wmi@0.18 --features chrono                # if planner overrides D-21 — see Open Question §1
# Bump windows from 0.58 -> 0.62 in dlp-agent/Cargo.toml; add "Win32_System_Registry"
# is already in the feature list (line 53), so no new feature flag needed for the bump.
```

**Version verification (run before locking):**
```bash
# CITED: docs.rs and crates.io README, 2026-05-02
# wmi 0.14.5 — old but compatible API surface (with_namespace_path, set_proxy_blanket, query)
# wmi 0.18.4 — current (released 2026-03-27 per github releases page); same public API for the
#              three methods Phase 34 uses. windows-rs version compatibility differs internally.
# windows 0.62.2 — confirmed published, used in workspace dlp-common already
```

---

## wmi-rs 0.14 Wire-up

**[VERIFIED: docs.rs/wmi/0.14.5/wmi/connection/struct.WMIConnection.html, 2026-05-02]**

### Connection construction

The crate exposes a per-thread COM marker (`COMLibrary`) which the connection consumes. Two relevant constructors:

```rust
// Verified signatures from docs.rs.
impl COMLibrary {
    pub fn new() -> WMIResult<Self>;                    // CoInitialize + CoInitializeSecurity
    pub fn without_security() -> WMIResult<Self>;       // CoInitialize only — skip if security
                                                        // is already configured by another caller
    pub unsafe fn assume_initialized() -> Self;         // when COM is initialized externally
}

impl WMIConnection {
    pub fn new(com_lib: COMLibrary) -> WMIResult<Self>;
    pub fn with_namespace_path(
        namespace_path: &str,
        com_lib: COMLibrary,
    ) -> WMIResult<Self>;
}
```

**`COMLibrary` is `!Send + !Sync` and `Copy`.** It is per-thread. `CoUninitialize` is **not** called on drop (deliberate — see [microsoft/windows-rs#1169](https://github.com/microsoft/windows-rs/issues/1169)). Once a thread initializes COM via wmi-rs, COM stays initialized for that thread's lifetime.

### Authentication: PktPrivacy is mandatory

`MicrosoftVolumeEncryption` carries the `RequiresEncryption` qualifier — WMI rejects any query at lower auth levels with `ACCESS_DENIED`. The wmi-rs example wires this in one line:

```rust
// Verbatim from wmi-rs README (CITED: github.com/ohadravid/wmi-rs/blob/main/README.md).
use wmi::{AuthLevel, COMLibrary, WMIConnection};
use serde::Deserialize;

let com_lib = COMLibrary::new()?;
let wmi_con = WMIConnection::with_namespace_path(
    "ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption",
    com_lib,
)?;
wmi_con.set_proxy_blanket(AuthLevel::PktPrivacy)?;
```

**Note re D-02:** D-02 says "WMI connection uses `AuthLevel::PktPrivacy`." That is the wmi-rs `AuthLevel` enum variant, not a re-export from the `windows` crate. Import from `wmi::AuthLevel`.

### Struct-based query

```rust
// Verified shape from wmi-rs README BitLocker example.
#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_EncryptableVolume")]
#[serde(rename_all = "PascalCase")]
struct EncryptableVolume {
    device_id: String,                  // -> DeviceID
    drive_letter: Option<String>,       // -> DriveLetter (e.g. "C:" — note trailing colon)
    protection_status: Option<u32>,     // 0=Unprotected, 1=Protected, 2=Unknown
    conversion_status: Option<u32>,     // 0..=5 per CONTEXT.md status table
    encryption_method: Option<u32>,     // 0..=7 per D-07 mapping
}

let volumes: Vec<EncryptableVolume> = wmi_con.query()?;
```

**`DriveLetter` quirk:** WMI returns `"C:"` (with trailing colon, no backslash). The Phase 33 `DiskEnumerator.drive_letter_map` is keyed by `char`, not `String`. The encryption module must `s.chars().next()` and uppercase it before looking up the disk. This is a 2-line transform but easy to forget.

**Class name match:** `#[serde(rename = "Win32_EncryptableVolume")]` lets the crate infer the `SELECT * FROM Win32_EncryptableVolume` query automatically; the `query::<T>()` form needs no SQL string. CONTEXT.md "discretion" suggests an explicit `raw_query` with column projection — that is also valid (`wmi_con.raw_query("SELECT DeviceID, DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod FROM Win32_EncryptableVolume")`). Either works. Recommendation: use the typed `query()` form unless field-projection performance becomes an issue (it won't — there are at most a few volumes).

### Error taxonomy

`WMIError` (re-exported as `wmi::WMIError`) is non-exhaustive but the relevant variants in 0.14 include:
- `HResultError { hres: i32 }` — wraps `HRESULT` from WMI; the agent should pattern-match on `WBEM_E_ACCESS_DENIED` (0x80041003) and `WBEM_E_TIMED_OUT` (0x80043001) for retry decisions, but for Phase 34 these all collapse to "WMI failure -> Registry fallback -> Unknown."
- `SerdeError(serde::de::value::Error)` — struct deserialization failed; treat as fatal (programming error, not retry).
- `Other(String)` — catch-all.

**Recommendation:** Phase 34's `EncryptionError` enum should preserve the WMI error string in a `WmiQueryFailed(String)` variant (mirrors `DiskError::WmiQueryFailed` in `dlp-common/src/disk.rs:50`) and not try to discriminate transient vs. fatal at the wmi-rs layer. The retry schedule in CONTEXT.md "discretion" (100 ms, 500 ms — two retries) is per-disk and applies to any error.

### Timeouts

wmi-rs 0.14 has **no per-query timeout API**. The only timeout argument in the crate surface is on `filtered_notification(_, Some(Duration))` for event subscriptions (which Phase 34 doesn't use, per D-13).

D-03's "5-second per-volume timeout" is therefore implemented externally:

```rust
// Recommended pattern: wrap the blocking WMI call in tokio's timeout.
let result = tokio::time::timeout(
    Duration::from_secs(5),
    tokio::task::spawn_blocking(move || query_one_volume(drive_letter)),
).await;
```

See "DCOM / WMI in Tokio" below for why `spawn_blocking` is required, and "Pitfalls" §3 for the thread-leak caveat.

---

## Windows 0.62 Registry API

**[VERIFIED: microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/, 2026-05-02]**

`Win32_System_Registry` is already in `dlp-agent/Cargo.toml:53`, so no new feature flag is needed for the bump from 0.58 -> 0.62.

### Verified signatures

```rust
// All three are unsafe fn — wrap in a small safe RAII helper.
pub unsafe fn RegOpenKeyExW<P1>(
    hkey: HKEY,
    lpsubkey: P1,                       // &str must be UTF-16 wide; use windows::core::w!()
    uloptions: Option<u32>,             // typically None / 0
    samdesired: REG_SAM_FLAGS,          // KEY_READ for read-only access
    phkresult: *mut HKEY,
) -> WIN32_ERROR
where P1: Param<PCWSTR>;

pub unsafe fn RegQueryValueExW<P1>(
    hkey: HKEY,
    lpvaluename: P1,
    lpreserved: Option<*const u32>,
    lptype: Option<*mut REG_VALUE_TYPE>,
    lpdata: Option<*mut u8>,
    lpcbdata: Option<*mut u32>,
) -> WIN32_ERROR
where P1: Param<PCWSTR>;

pub unsafe fn RegCloseKey(hkey: HKEY) -> WIN32_ERROR;
```

`HKEY_LOCAL_MACHINE` is a constant of type `HKEY` (verified). `KEY_READ` is the `REG_SAM_FLAGS` to use for read-only fallback access.

### Recommended RAII wrapper pattern

```rust
// Source: distilled from windows-rs Win32::System::Registry samples; verified shape.
struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: HKEY came from a successful RegOpenKeyExW; RegCloseKey is safe to
        // call on any valid HKEY and we own the handle exclusively.
        unsafe { let _ = RegCloseKey(self.0); }
    }
}

fn read_bitlocker_boot_status() -> Result<u32, EncryptionError> {
    use windows::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, KEY_READ, RegOpenKeyExW, RegQueryValueExW,
        REG_DWORD, REG_VALUE_TYPE,
    };
    use windows::core::w;

    let mut hkey: windows::Win32::System::Registry::HKEY = Default::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            w!(r"SYSTEM\CurrentControlSet\Control\BitLockerStatus"),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if status.is_err() {
        return Err(EncryptionError::RegistryOpenFailed(format!("{status:?}")));
    }
    let _key = RegKey(hkey);  // RAII close

    let mut value: u32 = 0;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    let mut value_type = REG_VALUE_TYPE(0);
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            w!("BootStatus"),
            None,
            Some(&mut value_type),
            Some((&mut value as *mut u32) as *mut u8),
            Some(&mut size),
        )
    };
    if status.is_err() || value_type != REG_DWORD {
        return Err(EncryptionError::RegistryReadFailed(format!("{status:?}")));
    }
    Ok(value)
}
```

### Migration notes (windows 0.58 -> 0.62)

The `windows` crate breaks metadata between minor versions but the **public function signatures for stable Win32 areas are preserved**. Concrete risks for this workspace's existing usage:

| Existing area | Risk in 0.58 -> 0.62 | Verification |
|---------------|----------------------|--------------|
| `Win32_System_Ioctl` (Phase 33's `IOCTL_STORAGE_QUERY_PROPERTY`) | LOW — the descriptor types and IOCTL constants are stable Win32. | Run `cargo check -p dlp-common` after bump; Phase 33 verification report logged this as a known-stable area. |
| `Win32_Devices_DeviceAndDriverInstallation` (`SetupDi*`, `CM_*`) | LOW — used heavily in Phase 31/33; STATE.md notes a regression rumor on 0.58 specifically that 0.62 fixes. | `cargo check -p dlp-agent` after bump. |
| `Win32_Storage_FileSystem` (`GetDriveTypeW`, `CreateFileW`, `GetLogicalDrives`) | LOW — most stable area of the crate. | `cargo test -p dlp-common` covers this. |
| `Win32_System_Registry` | LOW — the three functions Phase 34 uses are unchanged across 0.58..0.62. New usage; no migration. | None — net-new code. |
| `Win32_Security` / `Win32_Security_Authorization` | LOW — `GetNamedSecurityInfoW`, `ConvertSidToStringSidW` signatures stable. | Existing audit_emitter tests cover this. |
| `windows::core::PCWSTR`, `PCSTR`, `HSTRING` | LOW — these are workspace primitives that have been stable since 0.51. | Compile error if regressed. |
| `windows::core::w!()` macro | NEW USAGE — verify available in 0.62 (it is, since 0.51). | Compile-time check. |

**Recommended migration sequence:** bump `windows` to 0.62 in `dlp-agent/Cargo.toml` as the **first** atomic task in the Phase 34 plan, then run `cargo check --workspace` and `cargo test --workspace` before adding any encryption code. If a regression surfaces, it must be fixed inside that single task — Phase 34's encryption code must not chase a moving target.

---

## DCOM / WMI in Tokio

**[VERIFIED: docs.rs/wmi/0.14.5/wmi/connection/struct.COMLibrary.html and tokio task::spawn_blocking docs, 2026-05-02]**

### The threading constraint

- `wmi::COMLibrary` is `!Send + !Sync` per its API surface. It cannot be moved between threads.
- COM must be initialized **per thread** that uses WMI (`CoInitializeEx`).
- The wmi-rs docs explicitly recommend `thread_local!` storage for the `COMLibrary` instance:

> "should be treated as a singleton per thread … `COM_LIB.with(|com| *com)` (it's `Copy`)"

- `tokio` runtime workers are reused across many tasks and may move tasks between threads at await points. Using `WMIConnection` directly inside an async task — with no `spawn_blocking` — is undefined behavior the moment the task moves to a thread that has not initialized COM.

### Two valid patterns

#### Pattern A — `spawn_blocking` per query (RECOMMENDED for Phase 34)

Tokio's blocking thread pool gives each `spawn_blocking` invocation a dedicated thread. We pay the COM-init cost per query (typically << 1 ms for a local connection that already has COM initialized — `CoInitializeEx` is cheap on subsequent calls in the same thread), and we get clean per-disk timeout semantics.

```rust
// Recommended Phase 34 wire-up.
async fn check_one_disk(
    drive_letter: char,
    timeout: Duration,
) -> Result<EncryptionStatus, EncryptionError> {
    let result = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || -> Result<EncryptionStatus, EncryptionError> {
            // Per-thread COM init — wmi-rs handles the duplicate-init case via HRESULT::S_FALSE.
            let com = wmi::COMLibrary::new()
                .map_err(|e| EncryptionError::ComInitFailed(e.to_string()))?;
            let conn = wmi::WMIConnection::with_namespace_path(
                r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption",
                com,
            ).map_err(|e| EncryptionError::WmiConnectionFailed(e.to_string()))?;
            conn.set_proxy_blanket(wmi::AuthLevel::PktPrivacy)
                .map_err(|e| EncryptionError::WmiConnectionFailed(e.to_string()))?;

            let volumes: Vec<EncryptableVolume> = conn.query()
                .map_err(|e| EncryptionError::WmiQueryFailed(e.to_string()))?;

            // Filter to the matching DriveLetter; map ProtectionStatus + ConversionStatus
            // to EncryptionStatus per CONTEXT.md table.
            volumes
                .iter()
                .find(|v| v.drive_letter.as_deref().map(parse_drive_letter) == Some(Some(drive_letter)))
                .map(derive_encryption_status)
                .ok_or(EncryptionError::VolumeNotFound)
        }),
    ).await;

    match result {
        Ok(Ok(Ok(status))) => Ok(status),
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(join_err)) => Err(EncryptionError::TaskPanicked(join_err.to_string())),
        Err(_elapsed) => Err(EncryptionError::Timeout),
    }
}
```

#### Pattern B — Dedicated WMI thread + channel (alternative, NOT recommended)

A long-lived dedicated thread with `thread_local!` `COMLibrary`, fed work via `mpsc::channel`. Slightly more efficient because COM and the WMI connection are amortized across queries. But: more code, harder to test, and timeout semantics are awkward (the work item must be cancellable, which the WMI call isn't).

**Why Pattern A wins for Phase 34:** at most a handful of disks per check, every 6 hours. The amortization saving is in the microsecond range. Pattern A is simpler, testable, and matches the existing `Phase 33` shape (which uses `spawn_blocking` implicitly via the synchronous `enumerate_fixed_disks` called inside an async retry loop).

### JoinSet idioms — fan-out across disks

```rust
// Distilled from tokio docs; standard fan-out pattern.
use tokio::task::JoinSet;

async fn check_all_disks(
    disks: Vec<DiskIdentity>,
    per_disk_timeout: Duration,
) -> HashMap<String, EncryptionStatus> {
    let mut set: JoinSet<(String, Result<EncryptionStatus, EncryptionError>)> = JoinSet::new();

    for disk in disks {
        let instance_id = disk.instance_id.clone();
        let drive_letter = disk.drive_letter;
        set.spawn(async move {
            let status = match drive_letter {
                Some(letter) => check_one_disk(letter, per_disk_timeout).await
                    .unwrap_or_else(|_| EncryptionStatus::Unknown),
                // Per CONTEXT.md: a disk with no drive letter has no Win32_EncryptableVolume
                // row; status is Unknown (cannot verify). Could also be Unencrypted under
                // the D-06 "no row for the volume == not provisioned" rule — but we can't
                // distinguish "WMI succeeded and returned no row" from "WMI failed silently"
                // here, so prefer Unknown for the no-drive-letter case.
                None => EncryptionStatus::Unknown,
            };
            (instance_id, Ok(status))
        });
    }

    let mut out = HashMap::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((id, Ok(status))) = joined {
            out.insert(id, status);
        }
        // JoinError or inner Err: skip; Unknown is the implicit default.
    }
    out
}
```

**Critical:** if `check_one_disk` is wrapped in `spawn_blocking`, the **outer** `set.spawn` still produces a future, which yields control to the runtime cleanly. Do **not** call the synchronous WMI work directly inside `set.spawn`'s closure — that blocks a tokio worker.

---

## Validation Architecture

`workflow.nyquist_validation` is not configured in this workspace (no `.planning/config.json` setting found via grep — the section is included by default).

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` + Rust built-in `#[test]` (and `#[tokio::test]` for async) — no external test runner |
| Config file | none — Cargo conventions only |
| Quick run command | `cargo test -p dlp-agent --lib detection::encryption -- --nocapture` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CRYPT-01 | `EncryptableVolume` deserializes correctly from a representative JSON-shaped payload (rename rules, PascalCase, Option fields). | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_encryptable_volume_serde` | Wave 0 |
| CRYPT-01 | `derive_encryption_status` maps every documented `(ProtectionStatus, ConversionStatus)` pair to the correct `EncryptionStatus` (truth table from CONTEXT.md). | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_derive_encryption_status_truth_table` | Wave 0 |
| CRYPT-01 | `EncryptionMethod::from_u32` covers all 8 documented values plus the `Unknown` catch-all. | unit | `cargo test -p dlp-common --lib disk::tests::test_encryption_method_from_raw` | Wave 0 |
| CRYPT-01 | `EncryptionStatus` and `EncryptionMethod` round-trip through serde JSON in snake_case. | unit | `cargo test -p dlp-common --lib disk::tests::test_encryption_status_serde` | Wave 0 |
| CRYPT-01 | `DiskIdentity` with the three new `Option` fields round-trips through serde JSON; pre-Phase-34 records (without the fields) deserialize successfully (additive schema). | unit | `cargo test -p dlp-common --lib disk::tests::test_disk_identity_backward_compat_no_encryption_fields` | Wave 0 |
| CRYPT-01 | `EncryptionChecker::new()` produces empty maps; `is_ready` is `false`. | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_encryption_checker_default` | Wave 0 |
| CRYPT-01 | `EncryptionChecker.status_for_instance_id` returns the cached value after a simulated update. | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_status_lookup_after_update` | Wave 0 |
| CRYPT-01 | Periodic re-check loop: when status changes between two synthetic samples, a fresh `DiskDiscovery` event is emitted with the `"encryption status changed"` justification (D-25). | unit (with mocked emit) | `cargo test -p dlp-agent --lib detection::encryption::tests::test_periodic_recheck_emits_on_change` | Wave 0 |
| CRYPT-01 | Periodic re-check: when status is unchanged, **no** new audit event is emitted; only `encryption_checked_at` updates (D-12). | unit (with mocked emit / spy on emit_audit) | `cargo test -p dlp-agent --lib detection::encryption::tests::test_periodic_recheck_silent_when_unchanged` | Wave 0 |
| CRYPT-01 | `[encryption]` TOML section: `recheck_interval_secs = 0` clamps to 300; `recheck_interval_secs = 999999` clamps to 86400; `recheck_interval_secs = 21600` passes through unchanged; logs a `warn!` on out-of-range. | unit | `cargo test -p dlp-agent --lib config::tests::test_encryption_recheck_interval_clamp` | Wave 0 |
| CRYPT-01 | `[encryption]` section absent: defaults to 21600 (6 h), no warning. | unit | `cargo test -p dlp-agent --lib config::tests::test_encryption_section_absent_uses_default` | Wave 0 |
| CRYPT-01 | `parse_drive_letter("C:")` -> `Some('C')`; `parse_drive_letter("E:")` -> `Some('E')`; `parse_drive_letter("")` -> `None` (the `DriveLetter` quirk fix). | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_parse_drive_letter` | Wave 0 |
| CRYPT-01 | (Windows-only smoke test) Calling `wmi::COMLibrary::new()` succeeds in a `spawn_blocking` context. Does NOT assert any specific BitLocker state — just that the COM/WMI plumbing initializes. | unit `#[cfg(windows)]` | `cargo test -p dlp-agent --lib detection::encryption::tests::test_wmi_smoke_windows -- --ignored` | Wave 0 (mark `#[ignore]` to skip in CI without admin) |
| CRYPT-02 | `EncryptionStatus::Unknown` is the result when the WMI call returns an error AND the Registry fallback also returns an error. NEVER `Encrypted` on failure (D-14). | unit (with injected WMI/Registry stubs returning Err) | `cargo test -p dlp-agent --lib detection::encryption::tests::test_failure_yields_unknown_never_encrypted` | Wave 0 |
| CRYPT-02 | When at least one disk lands in `Unknown`, the aggregated `DiskDiscovery` audit event sets a `justification` with `"<instance_id>: <reason>"` lines (D-15). | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_unknown_disks_populate_justification` | Wave 0 |
| CRYPT-02 | When the **initial** startup verification fails for **all** disks, exactly one `EventType::Alert` event is emitted (T4 / DENY); a subsequent periodic-poll failure emits no Alert (D-16). | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_alert_only_on_initial_total_failure` | Wave 0 |
| CRYPT-02 | The audit-event JSON shape matches the locked schema in CONTEXT.md `<specifics>` (`encryption_status`, `encryption_method`, `encryption_checked_at` fields per disk, snake_case). | unit | `cargo test -p dlp-agent --lib detection::encryption::tests::test_audit_event_shape_matches_specifics` | Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-agent --lib detection::encryption && cargo test -p dlp-common --lib disk` (~ 5 s)
- **Per wave merge:** `cargo test --workspace` (~ 30-60 s based on Phase 33 numbers: 217 + 101 tests)
- **Phase gate:** Full suite green AND `cargo clippy --workspace -- -D warnings` AND `cargo fmt --check` before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `dlp-agent/src/detection/encryption.rs` — does not exist yet; create with module-level doc comment and the test list above (RED before GREEN).
- [ ] `dlp-agent/src/detection/mod.rs` — add `pub mod encryption;` and the re-exports.
- [ ] `dlp-common/src/disk.rs` — add the two new enums + tests for them; add the three `Option` fields to `DiskIdentity` + a backward-compat deserialization test (mirrors the existing `test_audit_event_backward_compat_missing_discovered_disks` pattern at `audit.rs:682`).
- [ ] `dlp-common/src/lib.rs` — extend the existing `pub use disk::{...}` block (already at lines 21-23).
- [ ] `dlp-agent/src/config.rs` — add `EncryptionConfig` substruct + clamp tests; the existing test scaffolding at `config.rs:273` is the template.
- [ ] `dlp-agent/Cargo.toml` — bump `windows` 0.58 -> 0.62 (line 36); add `wmi` dep with `chrono` feature; add `Win32_System_Registry` already present (line 53 — no change needed).

### Mockability tradeoffs

The WMI call and the Registry call cannot easily be mocked at the wmi-rs / windows-crate boundary in Rust — neither crate exposes a trait abstraction. Three viable strategies:

| Strategy | Pros | Cons | Recommendation |
|----------|------|------|----------------|
| **Trait the inner call** — define `trait EncryptionBackend { fn query_volumes() -> ...; fn read_registry_boot_status() -> ...; }` and inject a `MockEncryptionBackend` for unit tests. | Pure-Rust, deterministic, fast, covers the orchestration logic 100%. | Requires the production code to go through a `Box<dyn EncryptionBackend>` indirection — minor performance cost (irrelevant here). | **Adopt this.** The orchestration logic (status derivation truth table, change detection, justification building, all the failure-mode branches) is where the bugs live; that logic is mockable. The actual COM/WMI/Registry primitives are thin wrappers verified separately by the `#[cfg(windows)]` smoke test. |
| Integration test on a real Windows VM (BitLocker enabled / disabled / suspended / unprovisioned). | Highest fidelity. | Cannot run in CI without provisioning Windows VMs with admin + BitLocker manipulation; coverage is ad-hoc; slow. | Defer to **human verification** (UAT items in 34-VERIFICATION.md, mirroring the Phase 33 pattern). |
| Snapshot-test a captured `wmi::query::<EncryptableVolume>` JSON output. | Captures the exact wire shape. | wmi-rs deserializes from `IWbemClassWrapper`, not from JSON; the snapshot would be a serde-rebuilt fixture and proves nothing about the COM layer. | Skip — the unit test on `EncryptableVolume` derive (CRYPT-01 row 1 above) covers serde; nothing else needs a fixture. |

---

## Pitfalls (Phase-specific, beyond what PITFALLS.md already covers)

PITFALLS.md already covers BitLocker API reliability (§3), false negatives on suspended state, multi-method consensus, and WMI timeout. Pitfalls below are NEW for Phase 34's specific shape.

### Pitfall A: COM mis-init in tokio without `spawn_blocking`

**What goes wrong:** Calling `wmi::COMLibrary::new()` directly inside an `async fn` body works on the first call (the runtime worker that picked up the task happens to have COM uninitialized), then mysteriously fails on a subsequent call when the runtime moves the next task to a different worker.
**Root cause:** `COMLibrary` is `!Send` and tied to the calling thread; tokio workers are not stable across await points.
**Detection:** sporadic `RPC_E_CHANGED_MODE` (HRESULT 0x80010106) or `CO_E_NOTINITIALIZED` (0x800401F0) errors that don't reproduce locally.
**Avoid:** every WMI call must run inside `tokio::task::spawn_blocking` or on a dedicated `std::thread`. Treat this as a phase-level invariant; the planner should make it a verification step.

### Pitfall B: `tokio::time::timeout` does not cancel the blocking thread

**What goes wrong:** A WMI call hangs (e.g., corrupted WMI repository, deadlocked DCOM proxy). `tokio::time::timeout(Duration::from_secs(5), spawn_blocking(...))` returns `Err(Elapsed)` after 5 s — but the blocking thread is still wedged inside `DeviceIoControl` / `IWbemServices::ExecQuery` and stays parked until DCOM's own internal timeout (~ 60 s default) fires.
**Root cause:** Rust has no preemptive thread cancellation. `spawn_blocking` does not cancel.
**Consequence:** the tokio blocking pool can fill up with hung threads if WMI repeatedly hangs. Default pool size is 512 threads — a 6-hour periodic re-check on a wedged system bleeds threads at most once per 6 h, so the pool will not exhaust in practice. But the per-thread memory cost (~ 8 MB stack per thread) is real.
**Avoid:** accept the leak (correct for Phase 34's cadence). Add a `tracing::warn!` log when timeout fires so the operator can see the wedge happening. Do NOT try to add a cancellation token — wmi-rs has no API for it. The 5 s outer timeout is the contract; the inner thread leak is acknowledged debt.
**Defensive bound:** the planner should verify in code that the periodic re-check **never** fans out to more than `disks.len()` concurrent `spawn_blocking` calls (i.e., no nested fan-out, no recursion). With < 32 disks per machine, this is comfortable headroom.

### Pitfall C: `DriveLetter` PascalCase trap

**What goes wrong:** WMI returns `DriveLetter` as `"C:"` (with colon, no backslash, no padding). Naive code does `letter.parse::<char>()?` and gets a parse error, falls through to "no drive letter," fails to find the disk, returns `Unknown`. The bug is silent — every disk shows `Unknown`, the admin assumes BitLocker is broken.
**Root cause:** the WMI shape is `String`, not `char`. CONTEXT.md `<specifics>` shows the deserialized `drive_letter: Option<String>` correctly, but the join key in `DiskEnumerator.drive_letter_map` is `char`.
**Avoid:** centralize the string-to-char transform in one helper (`parse_drive_letter("C:") -> Some('C')`) with a unit test (CRYPT-01 row 12 above). The transform must `.chars().next().filter(|c| c.is_ascii_alphabetic()).map(|c| c.to_ascii_uppercase())`.

### Pitfall D: D-08 backward-compat trap — `Option<EncryptionStatus>` vs `EncryptionStatus::Unknown`

**What goes wrong:** D-06 defines `EncryptionStatus::Unknown` as the failure signal. D-08 says `encryption_status: Option<EncryptionStatus>`. So there are TWO ways to express "we don't know": `None` (Phase 34 hasn't run yet for this record — pre-upgrade server-side row) and `Some(Unknown)` (Phase 34 ran and could not determine). Code that conflates these (`status.unwrap_or(Unknown)`) loses the signal and an admin investigating an audit feed cannot tell "the agent hasn't checked yet" from "the agent checked and gave up."
**Root cause:** two-level optionality; the disambiguation is correct per CONTEXT.md but easy to lose.
**Avoid:** never collapse `Option<EncryptionStatus>` -> `EncryptionStatus`. Comparison and pattern-matching code should be explicit about both arms. Add a unit test that asserts a `None` and a `Some(Unknown)` serialize to **different** JSON (`"encryption_status":null` is suppressed by `#[serde(skip_serializing_if = "Option::is_none")]` -> the field is absent vs. `"encryption_status":"unknown"` — the field is present).

### Pitfall E: First-poll vs periodic-poll Alert semantics (D-16)

**What goes wrong:** The "single Alert on all-disks-failed at startup only" rule is implemented by tracking `is_first_check: bool` in the `EncryptionChecker`. If the first check has 5 disks all `Unknown`, an `Alert` fires. If the planner forgets to **flip the flag to false on the very next iteration regardless of outcome**, a second Alert can fire on the next periodic poll if it also fails everywhere.
**Root cause:** state-machine bug — the flag must be cleared after the first attempt, success or failure.
**Avoid:** the flag is `is_first_check` not `has_succeeded_once`. The transition is "ran the check once, period." Test: simulate two consecutive total-failure cycles and assert `emit_audit` is called exactly once with `EventType::Alert`.

### Pitfall F: Assuming `set_proxy_blanket` survives `WMIConnection` rebuild

**What goes wrong:** Code creates a `WMIConnection`, calls `set_proxy_blanket(PktPrivacy)`, then drops it; on the next iteration, code creates a fresh connection and forgets the `set_proxy_blanket` call. The fresh connection defaults to a lower auth level and `query()` returns `WBEM_E_ACCESS_DENIED`.
**Root cause:** `set_proxy_blanket` mutates the connection, not a global. New connection = new proxy blanket = default level.
**Avoid:** wrap the connection construction in a single helper (`fn open_bitlocker_connection(com: COMLibrary) -> WMIResult<WMIConnection>`) that always calls `set_proxy_blanket` before returning. Make the helper the only call-site that constructs `WMIConnection` for this namespace.

---

## Project Constraints (from CLAUDE.md)

These constraints from the project's CLAUDE.md must be honored by Phase 34 plans (verified mandatory in §9):

| Constraint | Phase 34 implication |
|------------|----------------------|
| Use `cargo` for project management | Standard. |
| Use `serde` + `serde_json` | Already on stack — `EncryptableVolume` derives `Deserialize`. |
| Use `tracing` for structured logs | All `info!`/`warn!`/`debug!` in `encryption.rs` must use `tracing::*`, not `log::*` and not `println!`. |
| Use `thiserror` for error types | New `EncryptionError` enum is `#[derive(thiserror::Error)]`. |
| **No `.unwrap()` in library code** | All `Result`/`Option` access in `encryption.rs` must be `?`, `.ok_or(...)`, or `.unwrap_or(...)`. The `#[cfg(test)]` test functions are exempt. |
| Use `Result<T, E>` for fallible ops; propagate with `?` | Standard — applies throughout. |
| Doc comments on all public items | `EncryptionChecker`, `EncryptionStatus`, `EncryptionMethod`, `spawn_encryption_check_task`, `set_encryption_checker`, `get_encryption_checker`, all public fields and methods. |
| 4-space indentation, no tabs, no emojis | Standard. |
| Mock external dependencies in tests | Drives the trait-based `EncryptionBackend` recommendation in Validation Architecture above. |
| `parking_lot::RwLock` for shared state | Already in CONTEXT.md. |
| `#[cfg(windows)]` modules with non-Windows stubs | Mirror `dlp-common/src/disk.rs` lines 187-194 pattern. |
| `cargo clippy -- -D warnings` must pass | Standard pre-commit gate. |
| `cargo fmt --check` must pass | Standard pre-commit gate. |
| `sonar-scanner` quality gate | Pre-push gate per §9.16 — out of scope for this research, but the planner's "phase gate" task should include it. |
| Never log secrets or PII | `tracing::info!` may log `instance_id`, `drive_letter`, `model`, `bus_type`, `encryption_method`, `encryption_status`. Do NOT log `serial` (potential PII / identifier on some disks) at INFO level — debug only. |

---

## Runtime State Inventory

Phase 34 is additive (new module, new TOML section, new fields on existing struct). It is NOT a rename / refactor / migration phase. **No state migration required.**

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — `agent-config.toml` may already exist on disk from Phase 33 era, but adding a new optional `[encryption]` section is read-tolerant (default applied if absent — verified in `config.rs:285` test pattern). Existing `discovered_disks` audit records pre-Phase-34 deserialize via the additive `Option<...>` fields per the existing backward-compat test pattern at `audit.rs:682` and the new test added in Wave 0 above. | None |
| Live service config | None — agent reads its own TOML; no remote service holds Phase 34 state. | None |
| OS-registered state | None — Phase 34 does not register Windows services, scheduled tasks, or device notifications. | None |
| Secrets / env vars | None — no new secrets, no SOPS keys, no env vars. | None |
| Build artifacts | None — adding deps to `Cargo.toml` triggers a normal rebuild; no cached artifacts to clean. After the `windows` 0.58 -> 0.62 bump, `cargo clean -p dlp-agent` may be wise to flush stale codegen, but it is a hygiene step, not a correctness requirement. | Optional `cargo clean -p dlp-agent` after the `windows` bump |

---

## Code Examples

Patterns verified against docs.rs and the wmi-rs README.

### Example 1: Open the BitLocker WMI connection (one-shot)

```rust
// Source: distilled from wmi-rs/README.md BitLocker example (CITED above) and
// docs.rs/wmi/0.14.5/wmi/connection/struct.WMIConnection.html.
fn open_bitlocker_connection() -> Result<wmi::WMIConnection, EncryptionError> {
    let com = wmi::COMLibrary::new()
        .map_err(|e| EncryptionError::ComInitFailed(e.to_string()))?;
    let conn = wmi::WMIConnection::with_namespace_path(
        r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption",
        com,
    ).map_err(|e| EncryptionError::WmiConnectionFailed(e.to_string()))?;
    conn.set_proxy_blanket(wmi::AuthLevel::PktPrivacy)
        .map_err(|e| EncryptionError::WmiConnectionFailed(e.to_string()))?;
    Ok(conn)
}
```

### Example 2: Status derivation truth table

```rust
// Source: derived from CONTEXT.md status table in <specifics>; pure logic, no external API.
fn derive_encryption_status(
    protection_status: Option<u32>,
    conversion_status: Option<u32>,
) -> EncryptionStatus {
    match (protection_status, conversion_status) {
        (Some(1), Some(1)) => EncryptionStatus::Encrypted,
        (Some(0), Some(1)) => EncryptionStatus::Suspended,
        (Some(0), Some(0)) => EncryptionStatus::Unencrypted,
        (Some(0), Some(2)) => EncryptionStatus::Unencrypted,  // encrypting in progress
        (Some(0), Some(4)) => EncryptionStatus::Unencrypted,  // encryption paused
        (Some(0), Some(3)) => EncryptionStatus::Unencrypted,  // decrypting in progress
        (Some(0), Some(5)) => EncryptionStatus::Unencrypted,  // decryption paused
        (Some(2), _)        => EncryptionStatus::Unknown,
        // Defensive fallback: any unrecognized combination -> Unknown, never Encrypted (D-14).
        _                   => EncryptionStatus::Unknown,
    }
}
```

### Example 3: Periodic re-check loop with change detection

```rust
// Source: distilled from CONTEXT.md D-10..D-12 plus tokio interval idioms.
async fn periodic_recheck_loop(
    interval: Duration,
    audit_ctx: EmitContext,
    enumerator: Arc<DiskEnumerator>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;  // consume the immediate tick — startup check ran separately.

    loop {
        ticker.tick().await;
        let disks = enumerator.all_disks();
        let new_statuses = check_all_disks(disks.clone(), Duration::from_secs(5)).await;

        let mut changed = Vec::new();
        for disk in &disks {
            let old = disk.encryption_status;
            let new = new_statuses.get(&disk.instance_id).copied();
            if old != new.map(Some).flatten().map(|s| Some(s)).flatten().or(old) {
                // simplified: compare Option<EncryptionStatus>; record (instance_id, old, new)
                // for each transition.
                changed.push((disk.instance_id.clone(), old, new));
            }
            // Update encryption_checked_at unconditionally (D-12); update status only if changed.
            // Use the existing DiskEnumerator RwLock writers per D-20.
        }

        if !changed.is_empty() {
            // Emit DiskDiscovery with justification "encryption status changed: <transitions>"
            // per D-25.
        }
    }
}
```

(The pseudocode above intentionally elides exact mutation-through-RwLock details — those belong in PLAN.md per D-20.)

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Spawn `manage-bde.exe` and parse text output | `wmi-rs` + `Win32_EncryptableVolume` | wmi-rs 0.10 (~2022) made BitLocker queries trivial | Phase 34 takes the modern path (locked in CONTEXT.md). |
| Raw `IWbemServices` + COM via `windows` crate | `wmi-rs` typed `query::<T>()` | wmi-rs 0.12+ (typed serde queries) | ~10 lines vs. ~200; locked. |
| `winapi` crate for Registry | `windows` crate `Win32_System_Registry` | `winapi` is unmaintained since 2020; `windows` is the official binding | Project already on `windows` crate; trivial. |
| Polling Event Log for BitLocker-API IDs 768/769 (suspension/resumption) | Periodic 6 h poll of `Win32_EncryptableVolume` | Phase 34 chose poll over event-log subscription (D-13) — defer event log to v0.7.1 | Acknowledged tradeoff. |

**Deprecated / outdated for this domain:**
- `Win32_BitLockerVolume` (NOT a real class — common docs-search confusion). The correct class is `Win32_EncryptableVolume`.
- `manage-bde.exe -status` text parsing — fragile, slow, no programmatic guarantees.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The 6-hour periodic re-check uses `tokio::time::interval` ticking at exactly the configured interval; there is no jitter. | Periodic re-check loop | Multiple agents on the same fleet would synchronize their re-checks at the top of each 6-h boundary, creating a thundering herd against the WMI service on the local box. **Mitigation:** add a `+/- 5 minute` random jitter on the interval. The planner should consider adding this; CONTEXT.md does not require it. **Confidence: low — recommend the planner ask the user before locking the no-jitter shape.** |
| A2 | `wmi::COMLibrary::new()` is safe to call repeatedly on the same thread — subsequent calls succeed (or return `S_FALSE`) and do not double-init. | DCOM / WMI in Tokio §Pattern A | If the WMI crate panics on duplicate-init within `spawn_blocking` (where the blocking thread can be reused), every other WMI call would fail. **Mitigation:** the docs explicitly say `CoUninitialize` is never called and the `COMLibrary::new()` doc string says it is safe per-thread; tokio's blocking pool reuses threads within a process, so duplicate init is the expected case. **Confidence: high but unverified in our specific codebase — Wave 0 smoke test (the `test_wmi_smoke_windows` row in the validation table) explicitly covers this.** |
| A3 | The `BootStatus` Registry value at `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus` is a `REG_DWORD` and exists on every BitLocker-aware Windows version (Win 10+). | Windows 0.62 Registry API | If the value is absent on some SKUs (Home, LTSC variants), the Registry fallback returns "key not found" -> `Unknown` -> harmless. The fallback is best-effort by design (D-01). **Confidence: medium — sourced from PITFALLS.md §3 secondary citation; not verified against MSDN. Recommend the planner accept this as-is given the fallback's role.** |
| A4 | `EncryptionStatus` and `EncryptionMethod` enums use `#[derive(Default)]` with `Unknown` as the default variant (mirrors `BusType::default() = Unknown`). | Pattern across both enums | If the planner sets a different default (e.g. derives `Default` automatically without `#[default]`), serialization on a freshly-defaulted `DiskIdentity` would be inconsistent. **Mitigation:** explicit `#[default]` annotation on `Unknown`. Trivially testable. **Confidence: high.** |

---

## Open Questions for Planner

### 1. wmi crate version: 0.14 (locked) vs 0.18 (current)

CONTEXT.md D-21 locks `wmi = "0.14"`. The latest published version as of 2026-05-02 is `wmi = "0.18.4"` (released 2026-03-27 per the GitHub releases page). The public API surface used by Phase 34 (`COMLibrary::new`, `WMIConnection::with_namespace_path(name, com)`, `set_proxy_blanket(AuthLevel::PktPrivacy)`, `query::<T>()`) is **identical** across both versions per spot-checks of docs.rs.

**The version skew is not an API risk.** It is a **dependency hygiene** question:
- `wmi 0.18` uses `windows = "0.62"` internally — exact match for D-22's bump target.
- `wmi 0.14` likely uses an older `windows` (probably 0.51-0.54) internally; cargo will resolve this but the workspace will pull two `windows` major versions, increasing build time and potentially producing duplicate symbol bloat.
- Security: nothing flagged in the wmi changelog, but staying current is the standard posture.

**What we know:** the API works on both versions — the BitLocker README example pins 0.18 today.
**What's unclear:** whether D-21's "0.14" was a researched lock or a transcription drift from STACK.md (which itself says "wmi-rs = '0.14'" — note both the crate-name typo and the version).
**Recommendation:** the planner should **propose `wmi = "0.18"` to the user** during plan acceptance, citing dependency-graph cleanliness and matching `windows = 0.62`. If the user prefers stability, fall back to `0.14`. Either way, the code is the same.

### 2. WMI/Registry detection method on the wire (D-25 vs CONTEXT.md "discretion")

CONTEXT.md "discretion" recommends NOT recording which method (WMI primary vs. Registry fallback) produced a given `EncryptionStatus`. The justification field per D-15 already carries failure reasons. But the planner may want to record method-of-resolution for forensic / debugging reasons — at least at `tracing::debug!` level, which is local-only. **Recommendation:** confirm with user. Default-yes for `tracing::debug!`; default-no for the audit-event wire format.

### 3. Re-check interval jitter (Assumption A1)

`tokio::time::interval` fires deterministically — fleet-wide synchronization at the top of each 6 h is plausible. Adding `+/- 300 s` jitter (5 minutes) costs nothing and avoids the thundering herd. **Recommendation:** the planner should add it to the plan and flag it as discretionary; if the user dislikes it, remove.

### 4. Drive-letter-less disks (no `Win32_EncryptableVolume` row possible)

A fixed disk with no drive letter (mount-point only, raw volume, etc.) cannot be queried by `Win32_EncryptableVolume.DriveLetter`. Phase 33 enumerates such disks (D-05 of Phase 33 — "all fixed disks regardless of drive letter"). The CONTEXT.md status table in `<specifics>` says "no row for the volume == not provisioned" -> `Unencrypted`, but for a no-drive-letter disk the lookup fails — should it map to `Unknown` (cannot determine) or `Unencrypted` (no row found)?
**Recommendation (and what the JoinSet example above implements):** `Unknown`. A disk we cannot query cannot be honestly labeled `Unencrypted` — the admin needs the visibility that something is unverifiable. Confirm with user; this is one line of code either way.

### 5. WMI call inside `spawn_blocking` — blocking pool sizing

Tokio's default blocking pool is 512 threads. Phase 34 fans out at most ~32 disks per check, every 6 h. No sizing change is needed. **No action — flagging only so the planner can confirm.**

---

## Sources

### Primary (HIGH confidence)
- [docs.rs/wmi/0.14.5/wmi/connection/struct.WMIConnection.html](https://docs.rs/wmi/0.14.5/wmi/connection/struct.WMIConnection.html) — `with_namespace_path` and `new` signatures, query methods
- [docs.rs/wmi/0.14.5/wmi/connection/struct.COMLibrary.html](https://docs.rs/wmi/0.14.5/wmi/connection/struct.COMLibrary.html) — COM threading model, `!Send`/`!Sync`, `Copy`, no `CoUninitialize` on drop
- [github.com/ohadravid/wmi-rs/blob/main/README.md](https://github.com/ohadravid/wmi-rs/blob/main/README.md) — verbatim BitLocker / Win32_EncryptableVolume example
- [microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegOpenKeyExW.html](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegOpenKeyExW.html) — verified signature
- [microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegQueryValueExW.html](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegQueryValueExW.html) — verified signature
- [microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegCloseKey.html](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Registry/fn.RegCloseKey.html) — verified signature
- [learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume) — `Win32_EncryptableVolume` class and field semantics
- [learn.microsoft.com/en-us/windows/win32/wmisdk/requiring-an-encrypted-connection-to-a-namespace](https://learn.microsoft.com/en-us/windows/win32/wmisdk/requiring-an-encrypted-connection-to-a-namespace) — `RequiresEncryption` qualifier, why PktPrivacy is mandatory
- `dlp-common/src/disk.rs` — Phase 33 `DiskIdentity`, `BusType`, `DiskError`, enumeration shape
- `dlp-common/src/audit.rs` — `EventType::DiskDiscovery`, `discovered_disks` field, `with_justification` builder, backward-compat test patterns
- `dlp-agent/src/detection/disk.rs` — `DiskEnumerator` shape, retry pattern, audit emission helpers
- `dlp-agent/src/service.rs:611-632` — exact spawn point for the encryption check task
- `dlp-agent/src/audit_emitter.rs` — `EmitContext`, `emit_audit`
- `dlp-agent/Cargo.toml:36-68` — current `windows` 0.58 features (line 53 already includes `Win32_System_Registry`)
- `.planning/phases/34-bitlocker-verification/34-CONTEXT.md` — locked decisions D-01 through D-25
- `.planning/research/STACK.md` — wmi-rs / windows version recommendations
- `.planning/research/PITFALLS.md` — pre-existing pitfalls (1-13)
- `CLAUDE.md §9` — Rust coding standards

### Secondary (MEDIUM confidence)
- [github.com/ohadravid/wmi-rs/releases](https://github.com/ohadravid/wmi-rs/releases) — version timeline (latest 0.18.4, 2026-03-27)
- [learn.microsoft.com/en-us/windows/win32/wmisdk/securing-a-remote-wmi-connection](https://learn.microsoft.com/en-us/windows/win32/wmisdk/securing-a-remote-wmi-connection) — auth-level semantics
- `wutils.com` BitLocker class reference — confirms field names

### Tertiary (LOW confidence — flagged for validation)
- Default tokio blocking pool size (512 threads) — sourced from training, used only as a defensive bound in Pitfall B; not load-bearing.

---

## Metadata

**Confidence breakdown:**
- wmi-rs API surface: HIGH — verified against docs.rs and the README; the BitLocker example is reproduced verbatim.
- Windows Registry API: HIGH — three function signatures verified directly from docs-rs.
- COM threading model: HIGH — `!Send`/`!Sync` and per-thread semantics quoted from official wmi-rs docs.
- 0.58 -> 0.62 migration: MEDIUM — verified for the specific feature flags this workspace uses; full surface not exhaustively diffed.
- wmi 0.14 vs 0.18 API parity: MEDIUM — spot-checked the three methods Phase 34 uses; not exhaustive.
- Validation strategy: MEDIUM — trait-injection mocking is standard but the runtime smoke test is `#[ignore]`-gated and depends on admin privileges in CI.
- Mocking ergonomics: MEDIUM — mocking the wmi-rs / windows-rs boundary is awkward in Rust; recommendation is the trait-abstraction approach which is well-known but not enforced by tooling.

**Research date:** 2026-05-02
**Valid until:** 2026-06-01 (30 days — the wmi crate's release cadence is irregular but historically averages ~1 minor version per quarter; the windows crate's metadata bumps are the larger drift risk)

---

## RESEARCH COMPLETE
