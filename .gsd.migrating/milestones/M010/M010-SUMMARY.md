---
id: M010
title: "v0.7.1 Operational Hardening"
status: complete
completed_at: 2026-05-08T05:52:30.213Z
key_decisions:
  - AGENT-UNKNOWN sentinel with remediation path for all unresolvable identity
  - Per-user device registry with most-restrictive tier merge on conflict
  - wmi 0.18+ upgrade eliminates raw CoSetProxyBlanket FFI
  - Operational hardening: structured traces, config validation, graceful shutdown
key_files:
  - dlp-common/src/audit.rs
  - dlp-server/src/db.rs
  - dlp-agent/src/detection/encryption.rs
  - dlp-agent/src/service.rs
lessons_learned:
  - Audit schema guarantees require server-side validation as hard gate
  - Per-user registry needs SID-based evaluation, not username
  - wmi crate upgrade preserves behavior while eliminating FFI
  - Graceful shutdown must cancel tasks, flush buffers, restore DACLs, unregister notifications
---

# M010: v0.7.1 Operational Hardening

**v0.7.1 Operational Hardening shipped with AGENT-UNKNOWN remediation, per-user registry, WMI upgrade, and hardening bundle.**

## What Happened

v0.7.1 closed gaps in audit schema, added per-user device registry, upgraded WMI crate, and hardened operational behavior. All 7 requirements validated.

## Success Criteria Results

- AGENT-UNKNOWN remediation working — PASS (S01)
- Per-user device registry working — PASS (S02)
- WMI crate upgraded — PASS (S03)
- Operational hardening bundle delivered — PASS (S04)
- All 7 requirements validated — PASS (coverage audit)

## Definition of Done Results

All slices complete with verification evidence. All 7 requirements validated. Cross-slice integration verified. Milestone audit passed.

## Requirement Outcomes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| AUDIT-05 | validated | S01: AGENT-UNKNOWN sentinel and metric counters |
| USB-06 | validated | S02: Per-user registry with SID evaluation |
| TECH-01 | validated | S03: wmi 0.18+ with no raw FFI |
| OP-01 | validated | S04: Disk IOCTL error resilience |
| OP-02 | validated | S04: Structured USB traces |
| OP-03 | validated | S04: Config TOML validation |
| OP-04 | validated | S04: Graceful shutdown within 10s |

## Deviations

None.

## Follow-ups

None.
