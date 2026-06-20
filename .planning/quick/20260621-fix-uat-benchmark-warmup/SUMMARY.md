---
status: complete
completed: 2026-06-21
---

# Summary: Fix Uat-Benchmark.ps1 warm-up build failure

## Root cause
The script sets `$ErrorActionPreference = 'Stop'`. Cargo writes informational
messages (e.g. progress, cache stats) to stderr, and the script captured stderr
with `2>&1`. Under `Stop`, those stderr lines became terminating errors before
the `$LASTEXITCODE` check could run, so the warm-up build always appeared to fail.

## Fix
Added `Invoke-CargoBuildCommand` helper in `scripts/Uat-Benchmark.ps1` that:
- temporarily sets `$ErrorActionPreference = 'Continue'` while running cargo,
- captures stdout and stderr,
- converts captured output to plain strings,
- returns the real exit code.

`Measure-CargoBuild` now calls this helper for `cargo clean` and `cargo build`,
checking `ExitCode` instead of `$LASTEXITCODE` directly.

## Verification
Ran the equivalent warm-up command (`cargo clean --target-dir ...` followed by
`cargo build --workspace --release --target-dir ...`) with strict mode and error
action stop. Before the fix it terminated on stderr; after the fix it completed
successfully in ~20 seconds.

## Files changed
- `scripts/Uat-Benchmark.ps1`
