---
slug: fix-uat-benchmark-warmup
description: Fix Uat-Benchmark.ps1 so the cargo warm-up build no longer always fails
created: 2026-06-21
---

# Fix Uat-Benchmark.ps1 warm-up build failure

## Problem
`scripts/Uat-Benchmark.ps1` invokes `Invoke-CargoBuildWarmup`, which calls
`Measure-CargoBuild -CleanFirst`. The warm-up build is reported to *always* fail,
blocking CRIT-04 benchmarking.

## Steps
1. Reproduce the warm-up build manually (clone ripgrep if needed, run the same
   `cargo clean` + `cargo build --workspace --release --target-dir ...` sequence).
2. Capture the exact error output and identify the root cause.
3. Patch `scripts/Uat-Benchmark.ps1` to resolve the failure.
4. Re-run the warm-up command to confirm it succeeds.
5. Update `SUMMARY.md` and `STATE.md`.
6. Commit and push.

## Success criteria
- `Measure-CargoBuild -CleanFirst` (or the equivalent command line) completes
  successfully on a clean isolated target directory.
- `Uat-Benchmark.ps1` no longer aborts during warm-up.
