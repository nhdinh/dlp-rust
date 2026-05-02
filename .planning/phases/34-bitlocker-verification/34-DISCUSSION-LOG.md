# Phase 34: BitLocker Verification - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md -- this log preserves the alternatives considered.

**Date:** 2026-05-02
**Phase:** 34-bitlocker-verification
**Areas discussed:** Detection method, Data model placement, Re-verification policy, WMI failure handling

---

## Detection Method

| Option | Description | Selected |
|--------|-------------|----------|
| WMI-only | Single source via `Win32_EncryptableVolume`; trusts WMI fully | |
| WMI + Registry fallback | Try WMI; on failure read `HKLM\SYSTEM\...\BitLockerStatus\BootStatus` | ✓ (Recommended) |
| Multi-method consensus | Run WMI + Registry in parallel; require agreement before "Encrypted" | |
| Full chain (WMI + Reg + FVE) | Add `FSCTL_QUERY_FVE_STATE` quaternary; FVE API undocumented | |

**User's choice:** "pickup all recommended options for me"
**Notes:** User accepted the recommended path. Rationale: false-positive "Encrypted" is dangerous (lets unencrypted disk slip into allowlist), false-negative is benign (just an audit warning). WMI primary captures the common case; Registry fallback covers WMI-in-SYSTEM-context flakiness flagged in STATE.md without dragging in undocumented FVE API.

---

## Suspended State Semantics (sub-question of Detection Method)

| Option | Description | Selected |
|--------|-------------|----------|
| Three-state model (Encrypted / Suspended / Unencrypted) | Suspended is a distinct status; admin TUI can show it | ✓ (Recommended; later extended to four-state with Unknown) |
| Treat suspended as encrypted | Two-state; data-at-rest is ciphertext | |
| Treat suspended as unencrypted | Two-state; protection is off | |

**User's choice:** Three-state model
**Notes:** Most informative for compliance audits; lets admin decide via allowlist (per CRYPT-02). Later extended to four states (adding `Unknown`) when WMI failure handling was discussed.

---

## Data Model Placement

| Option | Description | Selected |
|--------|-------------|----------|
| Extend `DiskIdentity` with encryption fields | Single struct flows through audit / allowlist / registry; matches `is_boot_disk` precedent | ✓ (Recommended) |
| Separate `EncryptionStatus` struct | Audit gains parallel field; cleanest separation but every consumer joins | |
| Agent-local only, denormalize at boundaries | Nothing in `dlp-common`; server registry has its own column | |

**User's choice:** Extend `DiskIdentity`
**Notes:** Follows the Phase 33 precedent where `is_boot_disk` (a runtime-discovered, mutable property) lives on the identity struct. Adding `Option<...>` fields keeps the schema change additive — old serialized records remain readable.

---

## Re-Verification Policy

| Option | Description | Selected |
|--------|-------------|----------|
| Startup-only, defer drift to v0.7.1 | Smallest scope | |
| Startup + 6h periodic poll, emit-on-change | Pragmatic drift coverage; configurable interval | ✓ (Recommended) |
| Startup + event log listener (IDs 768/769) | Reactive but adds Win32 event-log subscription | |
| Periodic + event log | Maximum coverage; doubles failure modes | |

**User's choice:** Startup + periodic background poll
**Notes:** Six-hour interval is a reasonable trade-off between catching post-install BitLocker disablement (PITFALLS.md flagged scenario) and avoiding SIEM noise. Configurable via `agent-config.toml`. Status changes emit a fresh `DiskDiscovery` audit event; unchanged status updates only the cache `encryption_checked_at`. Event-log subscription is parked in deferred ideas.

---

## WMI Failure Handling

| Option | Description | Selected |
|--------|-------------|----------|
| Four-state with `Unknown` | Distinct status for "could not check"; admin TUI shows it | ✓ (Recommended) |
| Conservative collapse (force `Unencrypted` on failure) | Three-state model; loses uncertainty signal | |
| Configurable failure posture | `agent-config.toml` knob; adds test-matrix dimension | |

**User's choice:** Four-state model with `Unknown`
**Notes:** Honors CRYPT-02 verbatim — admin sees `Unknown` and decides via allowlist rather than us silently labeling. Audit event sets a `justification` describing the failure mode (timeout, COM error, deserialization, etc.) for diagnostic value. Avoids per-poll Alert spam: only the all-disks-failed-at-startup case escalates to `EventType::Alert`.

---

## Cross-Cutting Decisions Captured

These were not raised as separate gray areas but were locked in CONTEXT.md based on prior research and the locked decisions above:

| Topic | Decision | Rationale |
|-------|----------|-----------|
| WMI crate | `wmi-rs = 0.14` added to `dlp-agent` only | Recommended in `.planning/research/STACK.md`; `dlp-common` stays pure-data |
| `windows` crate version skew | Bump `dlp-agent` from 0.58 to 0.62 to align with `dlp-common` (already 0.61) | Phase 34 is the first phase to need Win32 Registry APIs in `dlp-agent`, clean trigger for the bump; STACK.md and STATE.md flag the skew |
| WMI auth level | `AuthLevel::PktPrivacy` | Required for `MicrosoftVolumeEncryption` namespace (lower levels return `ACCESS_DENIED` even from SYSTEM) |
| Per-volume WMI timeout | 5 s | Default ~60 s flagged as too long for startup path in PITFALLS.md |
| BitLocker check ordering vs Phase 33 | Sequential (after enumeration); per-volume work parallel via `JoinSet` | Phase 34 has no work without enumerated disks; one hung volume must not stall the rest |
| Module location | `dlp-agent/src/detection/encryption.rs` | Sibling to `disk.rs`; mirrors Phase 33 module shape |
| Audit event variant | Reuse `EventType::DiskDiscovery` (no new variants); reuse `EventType::Alert` for all-disks-failed-at-startup | Encryption fields ride on `DiskIdentity`; SIEM filters can isolate drift events via `justification LIKE 'encryption status changed%'` |

---

## Deferred Ideas

- BitLocker-API event log listener (IDs 768/769) — v0.7.1 if 6-hour poll proves insufficient
- `FSCTL_QUERY_FVE_STATE` quaternary fallback — v0.7.1 if WMI+Registry combination proves insufficient
- Skip-BitLocker-check for USB removable disks — rejected; some USB enclosures support BitLocker To Go
- Per-disk encryption-policy override (`[encryption.policy]` table) — out of scope; CRYPT-02 leaves this to admin via allowlist
- Recording detection method (WMI vs Registry) on the wire — debugging-only; not on audit event
- Configurable failure posture (`on_check_failure = strict|audit_only|disabled`) — rejected because four-state `Unknown` already gives admin enough signal
- SED/Opal detection (CRYPT-F1) — already deferred in REQUIREMENTS.md
- Third-party FDE detection (CRYPT-F2) — already deferred in REQUIREMENTS.md
