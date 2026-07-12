# Deferred Items — Phase 58.10 Plan 02

Out-of-scope discoveries made during execution. NOT fixed (scope boundary: only
auto-fix issues directly caused by this plan's changes).

## 1. Pre-existing rustfmt diff in dlp-hook-dll/src/trampolines.rs

- **Found during:** Task 3 verification (`cargo fmt --check -p dlp-hook-dll`)
- **Location:** `dlp-hook-dll/src/trampolines.rs:378` (a `debug_log(&format!(...))`
  call that rustfmt wants to re-wrap across multiple lines)
- **Why out of scope:** This plan (58.10-02) touches ONLY the three
  `classification_cache.rs` files (dlp-common, dlp-agent, dlp-hook-dll). It does
  NOT modify `trampolines.rs` — that is Plan 58.10-03's file (Wave 2). The fmt
  diff pre-dates this plan (it is in the working tree independent of my changes;
  all three of my files pass `rustfmt --check` cleanly with exit 0).
- **Recommendation:** Fix in Plan 58.10-03 (which edits trampolines.rs) or as a
  standalone `cargo fmt` hygiene commit. Not a blocker for this plan.
