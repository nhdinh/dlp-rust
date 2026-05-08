# S04: UAT & Regression Validation — UAT

**Milestone:** M008
**Written:** 2026-05-08T05:35:04.289Z

### UAT: Regression Validation

1. Re-register SanDisk with full 128-char serial
2. Set trust tier to ReadOnly — verify reads allowed, writes blocked
3. Set trust tier to FullAccess — verify all I/O allowed
4. Run cargo test --workspace — verify all tests pass
5. Run cargo clippy --workspace -- -D warnings — verify clean
6. Run cargo fmt -- --check — verify clean
