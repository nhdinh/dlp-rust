# Phase 33: Disk Enumeration - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md -- this log preserves the alternatives considered.

**Date:** 2026-04-30
**Phase:** 33-disk-enumeration
**Areas discussed:** Enumeration trigger, Disk identity data model, USB-bridged detection strategy, Boot disk handling

---

## Enumeration Trigger

| Option | Description | Selected |
|--------|-------------|----------|
| Install-time MSI custom action | One-shot at deployment | |
| First agent startup | Captures whenever agent first runs | ✓ |
| Both -- install-time + first-startup fallback | Robust across methods | |
| You decide | Claude picks | |

**User's choice:** First agent startup
**Notes:** User selected first agent startup as the primary enumeration trigger. Remaining sub-questions in this area were delegated to Claude's discretion.

---

## Enumeration Trigger -- Sub-questions (Claude's Discretion)

| Question | Claude's Decision | Rationale |
|----------|-------------------|-----------|
| New disks post-startup? | WM_DEVICECHANGE listener on GUID_DEVINTERFACE_DISK | Reuses existing Phase 23/31 notification architecture |
| Enumeration failure? | Retry 3x with backoff, then fail closed | Secure-by-default posture per CLAUDE.md principles |
| Disks without drive letters? | Enumerate all, only allowlist with letters | Complete inventory without over-blocking |
| Sync or async? | Async background task with fast sync path | Balances startup time with completeness |
| Audit event format? | One aggregated event per discovery | Consistent with existing audit patterns |
| Restart behavior? | Preserve existing, append new | Preserves admin edits from Phase 37 |
| Module location? | Standalone dlp-common/src/disk.rs | Reusable across crates, follows Phase 32 pattern |

---

## Disk Identity Data Model

| Option | Description | Selected |
|--------|-------------|----------|
| New DiskIdentity struct | Clean separation from USB | ✓ (Claude's discretion) |
| Extend DeviceIdentity | Reuse existing type | |
| Generic enum with variants | USB/Disk unified | |
| You decide | Claude picks | |

**User's choice:** "you decide all the answers from now on" -- delegated to Claude
**Notes:** User explicitly delegated all remaining decisions to Claude after Q1 in this area.

---

## USB-Bridged Detection Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| IOCTL primary / PnP fallback | Direct API first | ✓ (Claude's discretion) |
| PnP primary / IOCTL validation | Proven approach first | |
| Both parallel | Cross-check | |
| You decide | Claude picks | |

**User's choice:** Claude's discretion
**Notes:** IOCTL_STORAGE_QUERY_PROPERTY as primary (efficient, direct), PnP tree walk as fallback (proven in Phase 31, handles exotic bridges).

---

## Boot Disk Handling

| Option | Description | Selected |
|--------|-------------|----------|
| Exclude from enumeration | Safest | |
| Enumerate and auto-allowlist | Visible in audit, cannot block | ✓ (Claude's discretion) |
| Include -- admin must allowlist | Explicit control | |
| You decide | Claude picks | |

**User's choice:** Claude's discretion
**Notes:** Boot disk is enumerated (AUDIT-01 requires all disks), marked with `is_boot_disk: true`, and auto-allowlisted. Phase 36 enforcement will skip blocking boot disks.

---

## Claude's Discretion

All decisions from the "Disk identity data model", "USB-bridged detection strategy", and "Boot disk handling" areas were made by Claude based on:
- Codebase patterns (Phase 32 dlp-common/src/usb.rs module pattern)
- Security best practices (fail closed, secure-by-default)
- Prior phase learnings (PnP tree walk proven in Phase 31)
- Project principles (Least Privilege, Defense in Depth)

---

## Deferred Ideas

None -- all ideas raised stayed within Phase 33 scope. Deferred capabilities (per-trust tiers, mount-time blocking, grace period, SED detection) are already documented in REQUIREMENTS.md v0.7.1+ backlog.
