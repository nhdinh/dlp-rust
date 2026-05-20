# Phase 59: Label Service - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-20
**Phase:** 59-label-service
**Areas discussed:** Schema completeness, Inheritance strictness, Audit guarantees, Review-derived fixes, TUI compile blockers
**Mode:** `--auto` (autonomous selection, review-feedback-driven update)

---

## Schema Completeness

| Option | Description | Selected |
|--------|-------------|----------|
| Single `labels` table | Existing `labels` table with `find_parent_label()` covers all requirements; `label_paths`/`label_inheritance` tables are unnecessary normalization | ✓ |
| Add `label_paths` + `label_inheritance` tables | Roadmap success criteria mentions these tables; would require schema migration | |
| Defer table decision | Leave schema ambiguous for planning to resolve | |

**Auto-selected:** Single `labels` table is sufficient. The `find_parent_label()` query walks the filesystem directory tree; `parent_label_id` FK handles explicit label hierarchy. Additional tables add complexity without benefit for Phase 59.
**Notes:** Updated D-20. Roadmap success criterion should be adjusted to reflect this. Reviewer concern (HIGH) addressed.

---

## Inheritance Strictness

| Option | Description | Selected |
|--------|-------------|----------|
| Stricter tier wins | Effective tier = max(explicit tier, inherited parent tier) by strictness order | ✓ |
| Exact match always wins | Explicit label overrides parent regardless of tier (could weaken security) | |
| Parent always wins | Folder label always overrides child explicit label | |

**Auto-selected:** Stricter tier wins. Tier strictness order: UnclassifiedBlocked > T4 > T3 > T2 > T1. Prevents an explicit T2 child from weakening a T3 folder label.
**Notes:** Updated D-07 and D-07b. Added tests for "explicit lower tier under stricter parent folder" and "explicit stricter child under lower parent folder" to Plan 59-01. Reviewer concern (HIGH) addressed.

---

## Audit Guarantees

| Option | Description | Selected |
|--------|-------------|----------|
| Transactional audit | Audit emission is part of UnitOfWork; failure rolls back mutation | ✓ |
| Best-effort audit | Emit audit after commit; mutation succeeds even if audit fails | |
| Separate audit queue | Async queue for audit events; eventual consistency | |

**Auto-selected:** Transactional audit. If audit insertion fails, the transaction rolls back. This satisfies the requirement that "all mutations emit audit events."
**Notes:** Updated D-14. Removed "best-effort" language. `with_mutation()` helper must include audit emission inside the transaction. Reviewer concern (HIGH) addressed.

---

## Review-Derived Fixes (Auto-Resolved)

| Fix | Severity | Decision |
|-----|----------|----------|
| ResolvedTier import location | HIGH | Import from `crate::label_service` (not `dlp_common::label`). Updated D-19. |
| Recursive enum variant | HIGH | `LabelDetail` uses `Box<Screen>` for caller. Updated D-13b. |
| LabelService None fallback | MEDIUM | Fail-closed (deny/T4) when `label_aware_enabled` is true but `LabelService` is None. Updated D-11b. |
| Cache stores only Tier | MEDIUM | Cache stores `CacheEntry { tier, source, parent_path }` to preserve source semantics. Updated D-08. |
| In-memory filter after pagination | MEDIUM | Move `tier` and `owner_sid` filters into repository SQL before pagination. Updated D-21. |
| Form flow contradiction | MEDIUM | Use `Screen::LabelForm` consistently; remove InputPurpose from must-haves. Updated D-13. |
| ABAC override audit | MEDIUM | Classification overrides emit persisted audit events (not just `tracing::info!`). Updated D-14. |

---

## Claude's Discretion

None — all areas were auto-resolved from review feedback.

## Deferred Ideas

No new deferred ideas. Existing deferred items (NTFS ADS, sidecar metadata, automatic expiry, scanner-driven labels, T4 digital signature) remain unchanged.

---

*Auto-mode discussion log generated: 2026-05-20*
*Review feedback source: `.planning/phases/59-label-service/059-REVIEWS.md` (Cycle 3, 2026-05-13)*
