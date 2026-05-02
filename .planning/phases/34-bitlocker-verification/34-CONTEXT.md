# Phase 34: BitLocker Verification - Context

**Gathered:** 2026-05-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Agent verifies BitLocker encryption status for every fixed disk enumerated by Phase 33 and surfaces that status in audit events. The encryption check feeds Phase 35 (allowlist persistence — the registered disk record carries the encryption snapshot) and Phase 37 (server-side registry — has an `encrypted` column already in the schema). Phase 36 enforcement does **not** block on encryption status directly; CRYPT-02 requires the admin to make that call via the allowlist.

**In scope:**
- Query BitLocker status for every fixed disk produced by Phase 33's `enumerate_fixed_disks()`
- Store the result on the existing `DiskIdentity` struct (extension, not replacement)
- Emit encryption status as part of the `DiskDiscovery` audit event Phase 33 already established
- Re-verify periodically to detect drift if a user disables BitLocker post-install
- Handle WMI/SYSTEM-context failure modes gracefully (no false-positive "encrypted" reading)

**Out of scope:**
- Allowlist persistence to TOML (Phase 35)
- Runtime I/O blocking based on registration / encryption (Phase 36)
- Server-side disk registry & admin API (Phase 37)
- Admin TUI for disk registry (Phase 38)
- Hard-coded "block unencrypted disks" enforcement — CRYPT-02 explicitly forbids this; the admin decides via allowlist
- SED/Opal self-encrypting drive detection (deferred CRYPT-F1)
- Third-party FDE detection (VeraCrypt, McAfee — deferred CRYPT-F2)
- Non-Windows platforms (Windows-only per PROJECT.md)

</domain>

<decisions>
## Implementation Decisions

### Detection Method
- **D-01:** Detection uses **WMI as the primary method, with a Registry fallback on WMI failure**.
  - Primary: `wmi-rs` query against `ROOT\CIMV2\Security\MicrosoftVolumeEncryption` for `Win32_EncryptableVolume`. Read `ProtectionStatus` and `ConversionStatus`; combine to derive the four-state status.
  - Fallback: read `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus\BootStatus` (boot volume only) when WMI returns an error or times out. Used to corroborate or recover; never to override a successful WMI reading.
  - **NOT** part of Phase 34: `FSCTL_QUERY_FVE_STATE` (FVE API) — undocumented and listed as quaternary fallback in PITFALLS.md. Defer until WMI+Registry proves insufficient in field testing.
- **D-02:** WMI connection uses `AuthLevel::PktPrivacy` (required for the `MicrosoftVolumeEncryption` namespace; lower levels return `ACCESS_DENIED` even from SYSTEM context).
- **D-03:** Per-volume WMI query timeout is **5 seconds**. Default `wmi-rs` / DCOM timeout is ~60 s and PITFALLS.md flags this as too long for startup-path code. Timeout exceeded -> treat as WMI failure -> Registry fallback -> Unknown.
- **D-04:** BitLocker check runs **after** disk enumeration completes — it consumes the `Vec<DiskIdentity>` produced by Phase 33's `spawn_disk_enumeration_task`. Sequential, not parallel: Phase 34 has no work to do without enumerated disks. The check itself iterates disks in parallel via `tokio::task::JoinSet` so a single hung volume cannot stall the whole verification.

### Encryption Status Data Model
- **D-05:** Encryption fields are added to the **existing `dlp-common::DiskIdentity`** struct as `Option<...>` fields. This continues Phase 33's precedent (`is_boot_disk` is also a runtime-discovered field on the identity struct) and lets one record flow through audit -> allowlist (Phase 35) -> server registry (Phase 37) without per-consumer joins.
- **D-06:** New `EncryptionStatus` enum lives in `dlp-common/src/disk.rs` (alongside `BusType`):
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum EncryptionStatus {
      /// ProtectionStatus == 1 AND ConversionStatus == 1 (active key + fully encrypted).
      Encrypted,
      /// ProtectionStatus == 0 AND ConversionStatus == 1 (data is ciphertext on disk
      /// but key protectors are temporarily disabled, e.g. `manage-bde -protectors -disable`).
      Suspended,
      /// ConversionStatus indicates not-fully-encrypted, or no Win32_EncryptableVolume row.
      Unencrypted,
      /// Verification could not complete (WMI failure + Registry fallback failed, timeout,
      /// access denied). Distinct from Unencrypted so admin can investigate before allowlisting.
      Unknown,
  }
  ```
- **D-07:** New `EncryptionMethod` enum in `dlp-common/src/disk.rs`, mapping the WMI `EncryptionMethod` field:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum EncryptionMethod {
      None,           // 0
      Aes128Diffuser, // 1 (legacy, Windows 7)
      Aes256Diffuser, // 2 (legacy, Windows 7)
      Aes128,         // 3
      Aes256,         // 4
      Hardware,       // 5 (eDrive / hardware encryption)
      XtsAes128,      // 6 (Windows 10+)
      XtsAes256,      // 7 (Windows 10+)
      Unknown,        // any other / null
  }
  ```
- **D-08:** Three new fields on `DiskIdentity` (all `Option<...>` so existing serialized records remain readable):
  ```rust
  pub struct DiskIdentity {
      // ... existing Phase 33 fields ...
      pub encryption_status: Option<EncryptionStatus>,
      pub encryption_method: Option<EncryptionMethod>,
      pub encryption_checked_at: Option<chrono::DateTime<chrono::Utc>>,
  }
  ```
  - `encryption_status: None` means "Phase 34 has not run yet" (e.g. server-side record from before upgrade). `Some(EncryptionStatus::Unknown)` means "Phase 34 ran and could not determine status."
  - `encryption_checked_at` lets Phase 35 / 37 detect stale records.
- **D-09:** No changes to the `DiskDiscovery` `EventType` variant or `discovered_disks` field — they already serialize `DiskIdentity`, so adding fields is purely additive on the wire.

### Re-Verification Policy
- **D-10:** Verification runs at **two cadences**:
  1. **At startup**, immediately after Phase 33 enumeration completes successfully.
  2. **Every 6 hours** thereafter, in a background tokio task, while the agent is running.
- **D-11:** The 6-hour interval is **configurable** via a new `agent-config.toml` key:
  ```toml
  [encryption]
  recheck_interval_secs = 21600   # 6h default; min 300, max 86400
  ```
  Out-of-range values are clamped with a `warn!` log line (do not refuse to start).
- **D-12:** Periodic re-check **does not** emit a fresh `DiskDiscovery` event on every poll. It compares each disk's new `encryption_status` against the cached value in `DiskEnumerator`:
  - **Status changed** (e.g. `Encrypted` -> `Suspended`, `Unencrypted` -> `Encrypted`): update the cache, emit a fresh `DiskDiscovery` event flagged with a new `with_justification("encryption status changed: ...")` for SIEM correlation.
  - **Status unchanged**: silently update `encryption_checked_at` in the cache only.
- **D-13:** Event log subscription (BitLocker-API IDs 768 / 769) is **NOT** in scope for Phase 34. The 6-hour periodic poll satisfies CRYPT-02's "encryption status is available for admin review." Add event-log reactivity in v0.7.1 if drift detection latency becomes an issue.

### WMI Failure Handling
- **D-14:** A failed BitLocker check (WMI error + Registry fallback also fails) yields `EncryptionStatus::Unknown` — **never** `Encrypted` and **never** silently `Unencrypted`. CRYPT-02 mandates "admin decides via allowlist," so the labeling must be honest about uncertainty rather than guessing.
- **D-15:** When at least one disk lands in `Unknown`, the aggregated `DiskDiscovery` audit event sets a `justification` describing the failure modes encountered (one line per failed disk: `instance_id: <reason>`). This gives the admin actionable diagnosis when they review the audit feed.
- **D-16:** Repeated failures are **not** themselves an `Alert` event during steady-state operation — `Unknown` already carries the signal, and a separate `Alert` per poll cycle would flood SIEM. **Exception:** if the **initial** startup verification fails for **all** disks, emit a single `EventType::Alert` event (T4 / DENY) at boot to make the failure visible in real time. Subsequent periodic-poll failures stay quiet (already represented by `Unknown` in the next `DiskDiscovery`).
- **D-17:** Phase 34 does **not** modify Phase 33's enumeration fail-closed semantics. If enumeration itself fails, encryption verification never runs — the existing `disk://enumeration-failed` Alert path covers that case.

### Module Location
- **D-18:** Encryption verification logic lives in **`dlp-agent/src/detection/encryption.rs`** as a sibling to `disk.rs`. Public surface:
  - `pub struct EncryptionChecker` — the WMI/Registry orchestrator (analogous to `DiskEnumerator`).
  - `pub fn spawn_encryption_check_task(handle: tokio::runtime::Handle, ctx: EmitContext, recheck_interval: Duration)` — spawns the chained startup-then-periodic task.
- **D-19:** The pure-data items (`EncryptionStatus` enum, `EncryptionMethod` enum, the three new `DiskIdentity` fields) live in **`dlp-common/src/disk.rs`** so server (Phase 37) and admin TUI (Phase 38) can consume them without dragging WMI in.
- **D-20:** No changes to Phase 33's `DiskEnumerator`. The `EncryptionChecker` mutates `DiskEnumerator.discovered_disks` / `instance_id_map` / `drive_letter_map` in place via the existing `RwLock` writers when status changes. Phase 36 readers see fresh values on the next read.

### Crate Dependencies
- **D-21:** Add `wmi = "0.14"` to `dlp-agent/Cargo.toml` (with the `chrono` feature for timestamp deserialization). Keep `dlp-common` free of WMI — it stays a pure-data crate.
- **D-22:** Bump `windows = "0.58"` to `windows = "0.62"` in `dlp-agent/Cargo.toml` so it aligns with `dlp-common` (which is already on 0.61). Use 0.62 across the workspace; STACK.md and STATE.md both flag the version skew as a latent risk. Verify the existing `Win32_System_Ioctl`, `Win32_System_Registry` features still resolve under 0.62. **The bump is part of Phase 34 scope** — required for `windows::Win32::System::Registry::*` access used in the Registry fallback.
- **D-23:** Add `chrono` to `dlp-common` if not already present (needed for `encryption_checked_at: Option<DateTime<Utc>>`). Already used by `dlp-common::audit::AuditEvent` for timestamps, so likely already a dependency — confirm during planning.

### Audit Surface
- **D-24:** No new `EventType` variants. Reuse `EventType::DiskDiscovery` for normal periodic / startup verification (encryption status fields ride on `DiskIdentity`). Reuse `EventType::Alert` only for the all-disks-failed-at-startup case (D-16).
- **D-25:** When a periodic re-check fires *and* status changes, the resulting `DiskDiscovery` event sets `justification = Some("encryption status changed: ...")`. SIEM rules can filter on `event_type = DISK_DISCOVERY AND justification LIKE 'encryption status changed%'` to catch drift events.

### Resolved Pre-Planning Clarifications (2026-05-02, after RESEARCH.md)

- **D-21a (amends D-21):** Pin `wmi = "0.14"` is intentional. Rationale: minimize churn in Phase 34's scope; the published API at 0.14.x is sufficient for `Win32_EncryptableVolume` reads + `PktPrivacy` auth. A future maintenance phase can bump to 0.18.x once we have integration test coverage to catch breakage. Planner records this rationale in the plan that adds the dependency.
- **D-16a (amends D-16):** "Initial startup verification fails for all disks → emit one `Alert`" fires on **every agent cold-start**. No persisted "first observed" state file is introduced in Phase 34. Trade-off accepted: if WMI is repeatedly down across reboots, the agent re-emits the Alert each cold-start. Re-evaluate if SIEM noise becomes a problem in field testing.
- **D-01a (amends D-01):** Registry fallback fires **only on namespace-unavailable / namespace-not-found** errors from WMI (e.g., `WMI_NOT_AVAILABLE`, `WBEM_E_INVALID_NAMESPACE`). It does **NOT** fire on per-volume timeouts or transient WMI errors — those yield `EncryptionStatus::Unknown` directly. Registry is a recovery path for missing/non-installed BitLocker namespaces, not a corroboration mechanism for healthy WMI returning slow.

### Claude's Discretion
- Exact WMI query string for `Win32_EncryptableVolume` (recommended: `SELECT DeviceID, DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod FROM Win32_EncryptableVolume`)
- Whether the `EncryptionChecker` exposes a global `OnceLock<Arc<...>>` like `DiskEnumerator` (recommended: yes, mirrors the existing pattern; needed for the periodic task and for Phase 36 to read state)
- Exponential backoff schedule for transient WMI errors within a single poll cycle (recommended: 100 ms, 500 ms — two retries before giving up on a disk)
- Whether to short-circuit the BitLocker check for `BusType::Usb` removable enclosures (recommended: no, still verify; some USB-bridged enclosures support BitLocker To Go and admin may want to allowlist them as encrypted)
- Whether to record the WMI/Registry method that produced a result in the audit event (recommended: no, keep wire format compact; tracing logs can record the method for debugging)
- Whether `encryption_checked_at` is set to the time of the last *successful* check or the time of the last *attempted* check (recommended: time of last attempt — lets admin see "we tried at T but got Unknown" rather than a silently-stale timestamp)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements and Roadmap
- `.planning/ROADMAP.md` — Phase 34 goal, success criteria, depends-on Phase 33
- `.planning/REQUIREMENTS.md` — CRYPT-01, CRYPT-02 requirement definitions; deferred CRYPT-F1, CRYPT-F2
- `.planning/PROJECT.md` — Architecture, tech stack, key design decisions

### Prior Phase Context (patterns and proven approaches)
- `.planning/phases/33-disk-enumeration/33-CONTEXT.md` — `DiskIdentity` schema, `BusType` enum, `is_boot_disk` precedent, async background-task pattern, fail-closed semantics, retry schedule
- `.planning/phases/33-disk-enumeration/33-VERIFICATION.md` — Known limitations of `query_bus_type_ioctl` and `find_drive_letter_for_instance_id` (sequential heuristic) — encryption check must use the canonical `instance_id` for keying, not assume per-PhysicalDrive ordering
- `.planning/phases/24-device-registry-db-admin-api/` — Pattern for shared `dlp-common` types consumed by both agent and server
- `.planning/research/STACK.md` — `wmi-rs = 0.14` + windows 0.58 → 0.62 bump; recommended `EncryptableVolume` DTO shape; ProtectionStatus / EncryptionMethod value tables
- `.planning/research/PITFALLS.md` — Multi-method consensus rationale; suspended-state semantics; periodic re-verification rationale; WMI timeout (5 s, not default 60 s); fail-closed vs Unknown labelling

### Key Source Files (read before touching)
- `dlp-common/src/disk.rs` — `DiskIdentity`, `BusType`, `DiskError`. Add `EncryptionStatus`, `EncryptionMethod`, three new `Option<...>` fields here.
- `dlp-common/src/audit.rs` — `AuditEvent`, `EventType::DiskDiscovery` already routes to SIEM; `discovered_disks: Option<Vec<DiskIdentity>>` field; `with_justification` builder. No additions needed except possibly a new `with_encryption_check_method` builder if we keep the method off the wire (we don't, per D-25).
- `dlp-common/src/lib.rs` — Re-export new enums (`pub use disk::{EncryptionStatus, EncryptionMethod}`)
- `dlp-common/Cargo.toml` — Confirm `chrono` is already there; if not, add it.
- `dlp-agent/src/detection/disk.rs` — `DiskEnumerator` (mutate via existing `RwLock` writers from the new module), `spawn_disk_enumeration_task` (Phase 34 chains after this completes)
- `dlp-agent/src/detection/mod.rs` — Add `pub mod encryption; pub use encryption::EncryptionChecker;`
- `dlp-agent/src/service.rs` — Service startup; spawn `EncryptionChecker` task immediately after `spawn_disk_enumeration_task` completes its first successful enumeration. Pass `Handle::current()`, `audit_ctx`, `agent_config.encryption.recheck_interval_secs` (with clamp + default).
- `dlp-agent/src/audit_emitter.rs` — `EmitContext`, `emit_audit`. No new emitter functions; reuse `emit_disk_discovery` (or a near-copy that includes the "status changed" justification — exact API shape is Claude's discretion in planning).
- `dlp-agent/src/config.rs` — `AgentConfig` TOML struct. Add `pub encryption: EncryptionConfig` with one field (`recheck_interval_secs: Option<u64>`).
- `dlp-agent/Cargo.toml` — Add `wmi = "0.14"` (with `chrono` feature). Bump `windows` to `0.62`. Verify all existing feature flags still resolve.

### Windows API References
- `Win32_EncryptableVolume` WMI class — namespace `ROOT\CIMV2\Security\MicrosoftVolumeEncryption`. Required `AuthLevel::PktPrivacy`.
- `ProtectionStatus` values — 0=Unprotected, 1=Protected, 2=Unknown
- `ConversionStatus` values — 0=FullyDecrypted, 1=FullyEncrypted, 2=EncryptionInProgress, 3=DecryptionInProgress, 4=EncryptionPaused, 5=DecryptionPaused
- `EncryptionMethod` values — 0=None, 1=AES_128_DIFFUSER, 2=AES_256_DIFFUSER, 3=AES_128, 4=AES_256, 5=HARDWARE_ENCRYPTION, 6=XTS_AES_128, 7=XTS_AES_256
- Registry fallback path — `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus\BootStatus` (DWORD: 0 = unencrypted boot, 1 = encrypted boot). Boot volume only — does not give per-disk status, used as last-resort sanity check for the boot disk.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DiskEnumerator` (`dlp-agent/src/detection/disk.rs:44`) — Established pattern: `parking_lot::RwLock` fields, global `OnceLock<Arc<...>>`, async spawn, retry with exponential backoff, fail-closed audit emission. `EncryptionChecker` should mirror this pattern.
- `spawn_disk_enumeration_task` (`dlp-agent/src/detection/disk.rs:151`) — Demonstrates audit emission via `EmitContext`, retry schedule (`[200ms, 1s, 4s]`), `tokio::time::sleep` between retries, handling of "all retries exhausted -> fail-closed" path. Encryption checker reuses the same retry shape per disk for transient WMI errors but with shorter delays (D-21 sub-decision).
- `set_disk_enumerator` / `get_disk_enumerator` (`dlp-agent/src/detection/disk.rs:123`) — Global static pattern; `EncryptionChecker` will follow the same shape.
- `emit_disk_discovery` (`dlp-agent/src/detection/disk.rs:239`) — Reused verbatim from Phase 34's perspective; the disks vector now carries encryption fields automatically.
- `EmitContext` (`dlp-agent/src/audit_emitter.rs`) — Pass-through to encryption module; no new context fields needed.
- `AuditEvent::with_justification` (`dlp-common/src/audit.rs`) — Used for D-15 (failure description) and D-25 (status-change marker).

### Established Patterns
- `#[cfg(windows)]` modules in `dlp-common`, with non-Windows stubs returning empty/placeholder values (Phase 32/33 pattern)
- `parking_lot::RwLock` for shared in-memory disk state
- `tokio::task::JoinSet` for fan-out parallel work (used elsewhere in the agent for batched checks)
- `tracing::{info, warn, error, debug}` with structured fields (e.g., `instance_id = %disk.instance_id`)
- `OnceLock<Arc<_>>` for service-scope singletons
- `serde(rename_all = "snake_case")` on enums for TOML / JSON consistency

### Integration Points
- `dlp-agent/src/service.rs::run_loop()` — Currently spawns `spawn_disk_enumeration_task` at line 622-632. After Phase 34, also spawns `spawn_encryption_check_task` (or chains it inside the disk enumeration task). The simplest design is a `JoinHandle` returned by `spawn_disk_enumeration_task` that the encryption task awaits; alternatively, the encryption task polls `DiskEnumerator.is_ready()` until true. **Decision deferred to planning** — both shapes work.
- `dlp-agent/src/detection/mod.rs` — Add `pub mod encryption; pub use encryption::{EncryptionChecker, set_encryption_checker, get_encryption_checker};`
- `dlp-common/src/lib.rs` — Add `EncryptionStatus`, `EncryptionMethod` to the existing `pub use disk::{...}` line.
- `dlp-agent/src/config.rs` — Add the new `[encryption]` section parser; defaults applied at load time, not at use site.

### Dependency Notes
- `wmi-rs = 0.14` is **not currently** in either `dlp-agent` or `dlp-common`. Phase 34 introduces it, scoped to `dlp-agent`.
- `windows` crate version skew (`dlp-common = "0.61"`, `dlp-agent = "0.58"`) is corrected as part of Phase 34 (D-22). This is the first phase to require Win32 Registry APIs in `dlp-agent`, which is a clean trigger for the bump.
- `chrono` is already used in `dlp-common::audit` for `timestamp: DateTime<Utc>`, so no new dependency for `encryption_checked_at`.

</code_context>

<specifics>
## Specific Requirements

### EncryptionChecker public surface (target shape)
```rust
// dlp-agent/src/detection/encryption.rs

pub struct EncryptionChecker {
    pub encryption_status_map: parking_lot::RwLock<HashMap<String, EncryptionStatus>>,
    pub last_check_at: parking_lot::RwLock<Option<DateTime<Utc>>>,
    pub check_complete: parking_lot::RwLock<bool>,
}

impl EncryptionChecker {
    pub fn new() -> Self;
    pub fn is_ready(&self) -> bool;
    pub fn status_for_instance_id(&self, instance_id: &str) -> Option<EncryptionStatus>;
}

pub fn set_encryption_checker(checker: Arc<EncryptionChecker>);
pub fn get_encryption_checker() -> Option<Arc<EncryptionChecker>>;

pub fn spawn_encryption_check_task(
    runtime_handle: tokio::runtime::Handle,
    audit_ctx: crate::audit_emitter::EmitContext,
    recheck_interval: Duration,
);
```

### Audit event shape (DiskDiscovery, post-Phase-34)
```json
{
  "timestamp": "2026-05-02T12:00:00Z",
  "event_type": "DISK_DISCOVERY",
  "agent_id": "WORKSTATION01",
  "discovered_disks": [
    {
      "instance_id": "PCIIDE\\IDECHANNEL\\4&1234",
      "bus_type": "sata",
      "model": "WDC WD10EZEX-00BN5A0",
      "drive_letter": "C",
      "is_boot_disk": true,
      "encryption_status": "encrypted",
      "encryption_method": "xts_aes_256",
      "encryption_checked_at": "2026-05-02T12:00:00Z"
    },
    {
      "instance_id": "USB\\VID_1234&PID_5678",
      "bus_type": "usb",
      "model": "USB External Drive",
      "drive_letter": "E",
      "is_boot_disk": false,
      "encryption_status": "unknown",
      "encryption_method": null,
      "encryption_checked_at": "2026-05-02T12:00:00Z"
    }
  ],
  "justification": "encryption status changed: PCIIDE\\IDECHANNEL\\4&1234 suspended -> encrypted"
}
```

### agent-config.toml addition
```toml
[encryption]
# Re-check BitLocker status every N seconds. Default 21600 (6 hours).
# Clamped to [300, 86400] at load time.
recheck_interval_secs = 21600
```

### EncryptionChecker WMI query (target string)
```sql
SELECT DeviceID, DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod
FROM Win32_EncryptableVolume
```

### Status derivation table (WMI primary)
| ProtectionStatus | ConversionStatus | -> EncryptionStatus |
|------------------|-------------------|---------------------|
| 1 | 1 | Encrypted |
| 0 | 1 | Suspended |
| 0 | 0 | Unencrypted |
| 0 | 2 (encrypting) | Unencrypted (not yet ciphertext) |
| 0 | 4 (paused while encrypting) | Unencrypted |
| 0 | 3 (decrypting) | Unencrypted (in transit) |
| 0 | 5 (paused while decrypting) | Unencrypted |
| 2 (Unknown) | any | Unknown |
| (no row for the volume) | — | Unencrypted (no Win32_EncryptableVolume record == BitLocker not provisioned) |
| (WMI error / timeout, Registry fallback also fails) | — | Unknown |

</specifics>

<deferred>
## Deferred Ideas

- **Event log subscription (BitLocker-API IDs 768/769)** — would give sub-second drift detection; deferred to v0.7.1 if 6-hour periodic poll proves insufficient in field testing.
- **`FSCTL_QUERY_FVE_STATE` quaternary fallback** — undocumented FVE API; deferred until WMI+Registry combination proves insufficient in field testing.
- **Per-disk encryption-policy override** (e.g., `agent-config.toml` `[encryption.policy]` to mark certain disks as "must be encrypted to be allowlisted") — out of scope; CRYPT-02 explicitly leaves this decision to the admin via the allowlist UI.
- **Skip BitLocker check on `BusType::Usb` removable disks** — recommended **against** (some USB enclosures support BitLocker To Go); revisit if USB BitLocker queries prove flaky.
- **Recording the WMI/Registry detection method on the wire** — kept off the audit event for compactness; debugging logs only. Revisit if SIEM rules need to disambiguate.
- **SED/Opal self-encrypting drive detection (CRYPT-F1)** — deferred to v0.7.1+.
- **Third-party FDE detection — VeraCrypt, McAfee (CRYPT-F2)** — deferred to v0.7.1+.
- **Configurable failure posture (`on_check_failure = strict|audit_only|disabled`)** — considered during discussion; rejected because the four-state model with `Unknown` already gives admin enough information to apply policy via the allowlist (CRYPT-02), and a separate config knob would add a test-matrix dimension without changing observable behavior.

</deferred>

---

*Phase: 34-bitlocker-verification*
*Context gathered: 2026-05-02*
