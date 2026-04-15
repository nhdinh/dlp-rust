# Phase 11: Implement /evaluate Endpoint — Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-16
**Phase:** 11-policy-engine-separation
**Areas discussed:** Phase goal re-evaluation, Default decision semantics, PolicyStore loading model

---

## Area: Phase Goal Re-evaluation

| Option | Description | Selected |
|--------|-------------|----------|
| Split dlp-server into dlp-policy-engine binary | Architectural split per original roadmap | |
| Implement /evaluate endpoint inside dlp-server | Resurrect dead policy_api.rs, implement PolicyStore | ✓ |

**User's choice:** Replace Phase 11 (Policy Engine Separation) with "Implement /evaluate endpoint"
**Notes:** User explicitly stated: "i dont want to separate dlpserver and policyengine". The original
R-03 architectural split is off the table indefinitely.

---

## Area: Default Decision Semantics (when no policy matches)

| Option | Description | Selected |
|--------|-------------|----------|
| Default-deny | DENY for all resources when no policy matches | |
| Tiered default | ALLOW for T1/T2, DENY for T3/T4 | ✓ |
| Default-allow | ALLOW for all resources when no policy matches | |

**User's choice:** Tiered default — fail-closed for sensitive (T3/T4), fail-open for non-sensitive (T1/T2)
**Notes:** Aligns with "default deny for sensitive data" principle. `EvaluateResponse::default_deny()`
and `default_allow()` already exist in `dlp-common` — PolicyStore calls the right one per resource tier.

---

## Area: PolicyStore Policy Loading Model

| Option | Description | Selected |
|--------|-------------|----------|
| Read from DB on every /evaluate request | Simpler — always fresh, but DB call on hot path | |
| Read from DB at startup only | Fast eval, but admin changes require server restart | |
| Read + cache with refresh + immediate invalidation on write | Middle ground — periodic refresh + invalidation on admin mutations | ✓ |

**User's choice:** Read + cache with refresh (5-minute default interval, immediate invalidation on admin write)
**Notes:** Startup-only loading was rejected because it means admin policy changes don't take effect until
server restart. Per-request DB reads were rejected because it's a hot path and adds latency. The chosen
approach keeps the eval path lock-free (in-memory `Vec`) while ensuring admin mutations take effect
immediately via `invalidate()`.

---

## Claude's Discretion

- Cache refresh interval: 5 minutes (default) — planner can make this configurable via env var
- PolicyStore internals: `RwLock<Vec<Policy>>` vs interior mutability pattern — planner decides
- `spawn_blocking` usage for startup load: planner decides sync vs async initialization

## Deferred Ideas

- **R-03 Policy Engine Separation:** Not wanted. Deferred indefinitely.
- **Multi-replica policy sync:** Requires an engine side to push to; deferred until/unless split revisited.
- **AD LDAP integration (R-05):** Not discussed in Phase 11 scope. Subject groups will use placeholders
  until Phase 7 provides real AD data. Evaluation works with whatever groups are present.