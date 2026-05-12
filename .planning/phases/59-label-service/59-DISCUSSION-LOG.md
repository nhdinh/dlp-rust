# Phase 59: Label Service - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-12
**Phase:** 59-Label Service
**Areas discussed:** dlp-Common Types, Admin API Design, Folder Inheritance Resolution, Label-Aware ABAC Integration, Admin TUI Screen, Metadata Layers, State Machine
**Mode:** `--auto --analyze --text` (autonomous selection, trade-off tables logged, plain-text rendering)

---

## dlp-Common Types

**Trade-off analysis:**

| Approach | Pros | Cons |
|----------|------|------|
| Extend `Classification` enum with `UnclassifiedBlocked` | Single type everywhere, no conversions | Breaking change to v0.10.0-stable enum; `UnclassifiedBlocked` doesn't fit the four-tier sensitivity model |
| Create separate `Tier` enum in `label.rs` | Keeps `Classification` stable; `UnclassifiedBlocked` is label-domain-specific | Requires conversion impls between `Classification` and `Tier` |
| Use raw strings everywhere | No new types needed | Loses type safety; CHECK constraints only at DB layer |

**Recommended:** Separate `Tier` enum in `label.rs` — `Classification` is v0.10.0-critical and must not change. Conversion methods bridge the gap.

**[auto] Selected:** "Separate `Tier` enum in `label.rs`" (recommended default)

---

## Admin API Design

**Trade-off analysis:**

| Approach | Pros | Cons |
|----------|------|------|
| Custom payload structs per endpoint | Fine-grained validation, clear Swagger docs | More boilerplate, diverges from existing disk_registry pattern |
| Reuse dlp-common `Label` type directly | Less code, consistent with device_registry pattern | Slightly less validation at compile time (runtime checks needed) |
| GraphQL-style single endpoint | Flexible queries | Overkill for 7 endpoints; no existing GraphQL infrastructure |

**Recommended:** Reuse dlp-common `Label` type with runtime validation — follows the established `device_registry` / `disk_registry` pattern in `admin_api.rs`.

**[auto] Selected:** "Reuse dlp-common `Label` type with runtime validation" (recommended default)

---

## Folder Inheritance Resolution

**Trade-off analysis:**

| Approach | Pros | Cons |
|----------|------|------|
| Resolve at API time (store inherited tier in DB) | Fast reads, simple queries | Stale on folder rename/move; requires cascading updates |
| Resolve at enforcement time (walk tree on each eval) | Always accurate; no cascade logic | Slower; requires caching to avoid repeated DB walks |
| Hybrid: store + background refresh | Best of both worlds | Complex; over-engineered for pilot phase |

**Recommended:** Resolve at enforcement time with a 30-second TTL cache — accuracy is more important than speed for pilot; `find_parent_label` already implements the walk.

**[auto] Selected:** "Resolve at enforcement time with 30s TTL cache" (recommended default)

---

## Label-Aware ABAC Integration

**Trade-off analysis:**

| Approach | Pros | Cons |
|----------|------|------|
| Always-on label override | Simple, no config needed | Breaking change: unlabeled resources become blocked |
| Gated by `system_kv` flag (default off) | Safe rollout; operators opt in | Requires explicit enablement step |
| Per-policy toggle | Granular control | Complex UI; overkill for pilot |

**Recommended:** Gated by `system_kv` flag (`label_aware_evaluation_enabled`, default off) — safe rollout is critical for pilot deployment.

**[auto] Selected:** "Gated by `system_kv` flag (default off)" (recommended default)

---

## Admin TUI Screen

**Trade-off analysis:**

| Approach | Pros | Cons |
|----------|------|------|
| Config-form pattern (like `SiemConfig`) | Consistent with settings screens | Poor fit for tabular data; label list needs scrollable table |
| PolicyList pattern (scrollable table) | Proven for list+CRUD; matches label management needs | Need two separate screens (list + review queue) |
| Single unified screen with tabs | Less code | More complex navigation; no existing tab pattern in TUI |

**Recommended:** Two screens: `LabelList` (PolicyList pattern) for management, `LabelReviewQueue` (simpler list with action keys) for Data Owner workflow.

**[auto] Selected:** "Two screens: LabelList + LabelReviewQueue" (recommended default)

---

## Metadata Layers (LABEL-06)

**Trade-off analysis:**

| Approach | Pros | Cons |
|----------|------|------|
| Implement NTFS ADS + sidecar in Phase 59 | Full requirement coverage | Significant scope expansion; ADS requires Win32 APIs; sidecar needs file watcher |
| Defer to Phase 60+ | Keeps Phase 59 focused; central DB is sufficient for pilot | LABEL-06 not fully satisfied in this phase |

**Recommended:** Defer NTFS ADS and sidecar to Phase 60+ — central DB is the pilot SOT. Label-06 is partially satisfied (central DB layer implemented).

**[auto] Selected:** "Defer NTFS ADS and sidecar to Phase 60+" (recommended default)

---

## State Machine (LABEL-03)

**Trade-off analysis:**

| Approach | Pros | Cons |
|----------|------|------|
| Full automatic expiry with cron/background task | Complete state machine | Requires scheduler infrastructure; overkill for pilot |
| Manual/admin-driven expiry only | Simple; no background task | Operator must manually expire labels |
| Hybrid: manual now, automatic later | Pragmatic; defers complexity | Slightly inconsistent UX |

**Recommended:** Manual/admin-driven expiry in Phase 59; automatic TTL-based expiry deferred to Phase 61 (Approval Workflow Engine).

**[auto] Selected:** "Manual/admin-driven expiry in Phase 59" (recommended default)

---

## Claude's Discretion

- All areas were auto-resolved via `--auto` mode. No user input was provided.
- Recommendations based on: existing codebase patterns, v0.10.0 stability requirements, pilot-first deployment constraints.

## Deferred Ideas

- NTFS ADS metadata layer — Phase 60+
- Sidecar metadata files — Phase 60+
- Automatic label expiry based on TTL — Phase 61
- Scanner-driven temporary labels — Phase 65
- Data Owner digital signature for T4 — Phase 61
