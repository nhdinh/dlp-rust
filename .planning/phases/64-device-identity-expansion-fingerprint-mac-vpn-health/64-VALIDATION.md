---
phase: 64-device-identity-expansion-fingerprint-mac-vpn-health
status: planned
generated: "2026-06-06"
---

# Phase 64 Validation Strategy

## Dimension Coverage

| Dimension | Coverage | Evidence |
|-----------|----------|----------|
| 1. Correctness | Plan tests for serde round-trips, fingerprint determinism, MAC validation | Unit tests in dlp-common and dlp-agent |
| 2. Edge Cases | Empty MAC list, registry read failure, non-Windows stubs | Test stubs and fallback paths |
| 3. Integration | Heartbeat payload round-trip, ABAC condition evaluation | Integration tests in dlp-server |
| 4. Performance | Fingerprint computation is O(n log n) due to MAC sorting; heartbeat adds small JSON payload | Benchmark not required — negligible overhead |
| 5. Security | Registry write to HKLM requires admin; fingerprint tampering changes hash | Threat model in PLAN.md |
| 6. Concurrency | Health status transitions use AtomicU8/Mutex | Single-owner transition function |
| 7. Regression | USB DeviceIdentity unchanged; existing heartbeat tests pass | Backward compat tests |
| 8. Dependencies | No new external crates — all from existing workspace | Cargo.toml audit |

## Test Commands

```bash
# Per-plan verification
cargo test -p dlp-common --lib
cargo test -p dlp-agent --lib
cargo test -p dlp-server --lib

# Full workspace
cargo test --workspace

# Quality gates
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

## Acceptance Criteria

- [ ] All DEVICE-01 through DEVICE-05 requirements have passing tests
- [ ] No compiler warnings (`-D warnings`)
- [ ] Clippy clean
- [ ] Existing tests still pass (regression check)
