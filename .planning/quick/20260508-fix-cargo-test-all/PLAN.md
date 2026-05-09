---
slug: fix-cargo-test-all
description: Fix errors and warnings from cargo test --all
---

# Fix cargo test --all Errors

## Issues Found

1. **Flaky test**: `detection::disk::tests::test_on_disk_arrival_skips_unregistered_disk` in dlp-agent fails when run with other tests due to missing `disk_grace_period_seconds` reset (test isolation bug).

2. **Warnings**:
   - Unused doc comment on macro invocation in `dlp-agent/src/chrome/handler.rs:55`
   - Deprecated `trust_tier_for` calls in `dlp-agent/src/device_registry.rs` tests (lines 443, 455, 467, 489, 490)
   - Deprecated `trust_tier_for` calls in `dlp-agent/tests/device_registry_cache.rs` (lines 25, 45, 66)
   - Unused import `Screen` in `dlp-e2e/examples/debug_tui.rs:2`

## Fixes

1. Add `*enumerator.disk_grace_period_seconds.write() = 0;` to the failing disk test.
2. Update deprecated `trust_tier_for` calls to `trust_tier_for_with_sid` with appropriate SID.
3. Remove unused doc comment or move it inside the macro.
4. Remove unused `Screen` import.
