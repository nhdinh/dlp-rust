# Phase 43: USB Enforcement Fix — PnP Disable Actually Works - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-07
**Phase:** 43-USB Enforcement Fix — PnP Disable Actually Works
**Areas discussed:** Hard failure semantics, Startup scan resolution, (none) serial handling, Description matching precision

---

## Hard Failure Semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Hard error | Return Err even when DACL succeeds. Any PnP failure is a bug that must be fixed and surfaced loudly. | |
| Warning only | Keep current behavior: return Ok with warning. DACL is sufficient as defense-in-depth. | |
| Retry then error | Retry PnP disable up to N times with backoff, then fail hard if all retries exhaust. | |
| Admin-configurable | Let dlp-admin choose via dlp-server config. Default: "Warning only". | ✓ |

**User's choice:** Admin-configurable — let dlp-admin select the option when dlp-server is running. Default is "Warning only".
**Notes:** User wants all three options in code. Config stored in operator config (SQLite), set via admin API/TUI. Agent polls config on normal refresh interval.

---

## Startup Scan Resolution

| Option | Description | Selected |
|--------|-------------|----------|
| Volume GUID resolution | Query volume GUID for each drive letter, construct dbcc_name-like path, use primary resolution. | |
| VID/PID/serial fallback | Keep current fallback-only approach. | |
| Admin-configurable | Let dlp-admin choose. Default: current option (VID/PID/serial fallback). | ✓ |

**User's choice:** Admin-configurable — add all options in code. dlp-admin sets option for dlp-server. Default is current option.
**Notes:** Same pattern as hard failure semantics — SQLite operator config, admin API/TUI, agent polling.

---

## (none) Serial Handling

| Option | Description | Selected |
|--------|-------------|----------|
| Always Blocked | Treat (none) serial as always Blocked tier. Simple but may block legitimate devices. | |
| Port-based disambiguation | Use USB hub port number to distinguish identical VID+PID devices. Complex. | |
| Admin-configurable | Let dlp-admin set policy. Default: always-block for safety. | ✓ |

**User's choice:** Admin-configurable
**Notes:** Same config pattern as other areas.

---

## Description Matching Precision

| Option | Description | Selected |
|--------|-------------|----------|
| Interface path exact match | Use exact dbcc_name device interface path for SetupDi matching. | ✓ (hot-plug) |
| VID+PID+serial+port | Add USB hub port number to matching criteria. | |
| Admin-configurable | Let dlp-admin choose matching strategy. | |

**User's choice:** Interface path exact match for hot-plug path; keep VID/PID/serial fallback for startup scan.
**Notes:** This is a code change, not runtime-configurable. The user explicitly chose this hybrid approach after I explained the tradeoffs.

---

## Claude's Discretion

None — user made explicit choices for all areas.

## Deferred Ideas

- Mount-time blocking (DISK-F1) — Phase 44
- Grace period / quarantine (DISK-F2) — Phase 45
- Replacing `notify`-based file watcher with actual I/O interception — out of scope for v0.8.1
- USB hub topology query for port-based disambiguation — deferred unless admin selects that policy
