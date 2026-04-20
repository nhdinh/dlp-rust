# Phase 20: Operator Expansion - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-21
**Phase:** 20-operator-expansion
**Areas discussed:** Classification `gt`/`lt` semantics, MemberOf `contains` semantics, Enum-only attributes (`eq`/`ne`)

---

## Classification `gt`/`lt` Semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Ordinal position (T1=1, T2=2, T3=3, T4=4) | Tier number comparison: `gt T2` matches T3 or T4. Fast, deterministic, no AD lookup. | ✓ |
| Tier-level string labels | Compare "Restricted" > "Confidential" etc. via string ordering | |

**User's choice:** Asked for decisions to be made on their behalf.
**Notes:** Classification has no `PartialOrd` derive. Ordinal comparison uses a local helper function in `policy_store.rs`, not a derive on the shared `dlp-common` enum.

---

## MemberOf `contains` Semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Substring on SID | `contains "S-1-5-21"` matches any SID containing that substring. Deterministic, no AD round-trip. | ✓ |
| AD group name lookup | Resolve SID to display name, then match on name. Requires AD async lookup in render path. | |
| Display name substring | Match on group display name in the SID list. Mixed approach — confusing. | |

**User's choice:** Asked for decisions to be made on their behalf.
**Notes:** SIDs are the canonical identifier throughout the ABAC system. Substring match is the pragmatic choice for v0.5.0.

---

## Enum-Only Attributes (`eq`/`ne`)

| Option | Description | Selected |
|--------|-------------|----------|
| Add `ne` to `operators_for()` lists | No evaluator changes — `compare_op` already handles `"neq"`. Display labels: "equals", "not equals". | ✓ |
| Defer `ne` to future phase | Leave these three attributes at `eq`-only. Rejected — inconsistent UX. | |

**User's choice:** Asked for decisions to be made on their behalf.
**Notes:** `ne` is the natural complement to `eq` for enum attributes. Adding it is a one-line change per attribute in `operators_for()`.

---

## Deferred Ideas

- **AD group name resolution for MemberOf display** — deferred to future phase. AD async lookup in render path is out of scope for v0.5.0.
- **Group name `contains`** — deferred with the above.
