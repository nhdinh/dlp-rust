---
phase: 59-label-service
plan: 01
subsystem: label-service
tags: [label-service, resolved-tier, strictness, cache, db-schema]
dependency_graph:
  requires: []
  provides: [LABEL-01, LABEL-02, LABEL-05]
  affects: [dlp-server/src/label_service.rs, dlp-common/src/label.rs, dlp-server/src/db/repositories/labels.rs]
tech_stack:
  added: []
  patterns: [ResolvedTier enum, CacheEntry metadata, strictness comparison]
key_files:
  created: []
  modified:
    - dlp-server/src/label_service.rs
    - dlp-common/src/label.rs
    - dlp-server/src/db/repositories/labels.rs
    - dlp-server/src/policy_store.rs
decisions:
  - "ResolvedTier lives in dlp-server (not dlp-common) per D-19 and review concern #4"
  - "resolve_tier returns ResolvedTier directly (not Result) — DB errors become LookupFailed (fail-closed)"
  - "Strictness comparison: explicit tier wins if stricter or equal; parent wins only if stricter (D-07b)"
  - "Cache stores full CacheEntry {tier, source, parent_path, inserted} not just Tier"
metrics:
  duration_minutes: ~55
  completed_date: 2026-05-21
  tests_added: 13
  tests_total_passing: 659 (467 dlp-server + 192 dlp-common)
---

# Phase 59 Plan 01: LabelService Fix — ResolvedTier + Strictness + Cache Metadata Summary

**One-liner:** Added ResolvedTier enum with source metadata, implemented strictest-tier-wins folder inheritance, and upgraded LabelCache to store full resolution provenance.

## What Was Built

### 1. DB Index Verification (Task 1)
- Added `test_labels_indexes_exist`: queries `sqlite_master` to verify all 6 indexes on `labels` table
  - `idx_labels_path`, `idx_labels_tier`, `idx_labels_state`, `idx_labels_owner`, `idx_labels_parent`, `idx_labels_department`
- Added `test_labels_parent_fk_constraint`: verifies `parent_label_id REFERENCES labels(id) ON DELETE SET NULL` behavior
- Schema in `init_tables()` already correct; no DDL changes needed

### 2. Tier Strictness + ResolvedTier Enum (Task 2)
- **`dlp-common/src/label.rs`:**
  - Added `Tier::strictness_rank() -> u8`: returns 1..5 (UnclassifiedBlocked = 5, strictest)
  - Added `Tier::is_stricter_than(&self, other: &Tier) -> bool`
- **`dlp-server/src/label_service.rs`:**
  - Added `ResolvedTier` enum with `Exact(Tier)`, `Inherited { tier, parent_path }`, `Fallback`, `LookupFailed`
  - Added `ResolvedTier::tier()`, `source()`, `is_inherited()` methods
  - Added `ResolutionSource` enum for cache metadata
  - Added `CacheEntry` struct: `{ tier, source, parent_path, inserted }`
  - Updated `LabelCache` to store `CacheEntry` (was `(Tier, Instant)`)
  - Added `LabelCache::get_tier()` convenience method

### 3. Strictness-Aware resolve_tier (Task 3)
- Changed `resolve_tier` return type from `rusqlite::Result<Tier>` to `ResolvedTier`
- **New resolution logic:**
  1. Check cache for `CacheEntry`
  2. Query BOTH exact match AND parent label (always, not conditionally)
  3. If both exist: compare strictness using `Tier::strictness_rank()`
     - Explicit >= parent strictness: `ResolvedTier::Exact`
     - Parent > explicit strictness: `ResolvedTier::Inherited`
  4. If only exact: `ResolvedTier::Exact`
  5. If only parent: `ResolvedTier::Inherited`
  6. If neither: `ResolvedTier::Fallback`
  7. On DB error: `ResolvedTier::LookupFailed` (fail-closed, no panic)
- Cache stores full `CacheEntry` with correct `ResolutionSource` and `parent_path`
- Updated `policy_store.rs` caller to work with new return type

## Test Coverage

| Test | File | What It Verifies |
|------|------|-----------------|
| `test_labels_indexes_exist` | labels.rs | All 6 indexes present on labels table |
| `test_labels_parent_fk_constraint` | labels.rs | ON DELETE SET NULL behavior |
| `test_tier_strictness_rank` | label.rs | Rank values 1..5 |
| `test_tier_is_stricter_than` | label.rs | Comparison logic |
| `test_resolved_tier_exact` | label_service.rs | Exact variant behavior |
| `test_resolved_tier_inherited` | label_service.rs | Inherited variant with parent_path |
| `test_resolved_tier_fallback` | label_service.rs | Fallback returns UnclassifiedBlocked |
| `test_resolved_tier_lookup_failed` | label_service.rs | LookupFailed returns UnclassifiedBlocked |
| `test_cache_entry_round_trip` | label_service.rs | CacheEntry stores/retrieves metadata |
| `test_label_cache_get_tier` | label_service.rs | get_tier convenience method |
| `test_label_cache_entry_expires` | label_service.rs | TTL expiration works |
| `test_resolve_tier_explicit_lower_under_stricter_parent` | label_service.rs | T2 child under T4 parent -> Inherited T4 |
| `test_resolve_tier_explicit_stricter_under_lower_parent` | label_service.rs | T4 child under T2 parent -> Exact T4 |
| `test_resolve_tier_equal_strictness` | label_service.rs | T3 child under T3 parent -> Exact T3 |
| `test_resolve_tier_no_explicit_inherited_only` | label_service.rs | No explicit, T3 parent -> Inherited T3 |
| `test_resolve_tier_cache_preserves_source_metadata` | label_service.rs | Cache hit preserves source string |
| (6 existing tests updated) | label_service.rs | exact_match, parent_folder, fallback, cache_hit, invalidate, ttl |

## Deviations from Plan

None — plan executed exactly as written.

## Commits

| Hash | Type | Description |
|------|------|-------------|
| f914b83 | test(59-01) | verify DB indexes and FK constraint on labels table |
| 272c6e2 | feat(59-01) | add Tier::strictness_rank and Tier::is_stricter_than |
| 8d9948a | feat(59-01) | add ResolvedTier enum, ResolutionSource, CacheEntry, update LabelCache |
| b95e727 | feat(59-01) | fix resolve_tier with strictness comparison, return ResolvedTier |

## Self-Check: PASSED

- [x] All created/modified files exist
- [x] All commits exist in git log
- [x] `cargo test -p dlp-server` passes: 467 passed, 0 failed
- [x] `cargo test -p dlp-common` passes: 192 passed, 0 failed
- [x] `cargo clippy -p dlp-server -p dlp-common -- -D warnings` clean
- [x] `cargo fmt --check` passes
