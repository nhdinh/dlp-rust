# Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-28
**Phase:** 55-Monitor-Only / Audit-Only Per-Policy Enforcement Mode
**Areas discussed:** DACL Tripwire in Monitor Mode, Global Audit Toggle, Alert Suppression in Audit Mode, Bypass Alerts in Monitor Mode

---

## DACL Tripwire in Monitor Mode

| Option | Description | Selected |
|--------|-------------|----------|
| Always active | Deny ACEs written regardless of policy mode; defense-in-depth trumps audit mode | |
| Follows policy mode | No Deny ACE in Audit mode; only Block/AuditAndBlock get Deny ACEs | ✓ |
| Separate system toggle | Dedicated `tripwire_active` config flag independent of policy mode | |

**User's choice:** "Looks good — use these" (accepted Claude's recommendation for all four areas)
**Notes:** Tripwire follows policy mode makes monitor mode truly non-blocking, allowing operators to observe real-world behavior for tuning. Defense-in-depth preserved for Block/AuditAndBlock policies. Explicitly deferred from Phase 52 context.

---

## Global Audit Toggle

| Option | Description | Selected |
|--------|-------------|----------|
| System-wide toggle only | One global flip; no per-policy granularity | |
| Per-policy only | Maximum granularity; operator edits each policy | |
| Both | Global toggle with per-policy override | ✓ |

**User's choice:** "Looks good — use these" (accepted Claude's recommendation)
**Notes:** `global_enforcement_mode` config field (Audit | Block | PerPolicy, default PerPolicy) overrides all per-policy modes when not PerPolicy. Lives in server-side operator config and syncs via existing `policy_sync`. This is the industry-standard pattern (Forcepoint, Symantec DLP, Microsoft Purview).

---

## Alert Suppression in Audit Mode

| Option | Description | Selected |
|--------|-------------|----------|
| Suppress alerts | Only SIEM audit events; no alert router | |
| Keep alerts | Alerts + audit events both fire | |
| Downgrade to info | SIEM gets full event; alert router receives info severity | ✓ |

**User's choice:** "Looks good — use these" (accepted Claude's recommendation)
**Notes:** Downgrading to info provides visibility without pager fatigue during monitoring. `DenyWithAlert` policies in Audit mode still emit audit events but alert router treats them as info-level. Pure suppression would mean operators lose visibility into policy violations.

---

## Bypass Alerts in Monitor Mode

| Option | Description | Selected |
|--------|-------------|----------|
| Full severity | Bypass alerts at mapped severity regardless of mode | ✓ |
| Capped severity | Reduced to warn/info in monitor mode | |
| Suppressed | No bypass alerts during monitor mode | |

**User's choice:** "Looks good — use these" (accepted Claude's recommendation)
**Notes:** Bypass is a real security event (syscall bypass, hook unloaded), not a policy-mode artifact. In correctly-functioning Audit mode, the hook journal shows ALLOW so no bypass alert is generated anyway. A bypass alert appearing during Audit mode indicates real evasion.

---

## Claude's Discretion

User explicitly asked for Claude's recommendations across all four gray areas and accepted them without modification. All four decisions were made by Claude and confirmed by the user.

## Deferred Ideas

- Policy-level scheduling (time-based mode switching) — noted for operational efficiency phase
- Gradual rollout by percentage or user group — noted for pilot expansion phase
- Automatic mode escalation based on violation count — noted for post-v1.0
- Dedicated admin TUI screen for global enforcement mode — unnecessary; config form field sufficient
