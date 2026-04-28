# Phase 30 Validation Architecture

**Phase:** 30 - Automated UAT Infrastructure
**Date:** 2026-04-28

---

## Test Framework

| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `tokio::test` (async) |
| Config file | None — tests are self-contained |
| Quick run command | `cargo test -p dlp-e2e` |
| Full suite command | `cargo test --workspace` |
| Clippy check | `cargo clippy --workspace -- -D warnings` |
| Format check | `cargo fmt --check` |

---

## Phase Requirements to Test Map

| Deferred UAT Item | Source Phase | Test Type | Automated Command | File (planned) |
|-------------------|-------------|-----------|-------------------|----------------|
| Agent TOML write-back | Phase 6 | Integration (spawn binary) | `cargo test -p dlp-e2e --test agent_toml_writeback` | `dlp-e2e/tests/agent_toml_writeback.rs` |
| Zero-warning build | Phase 6 | CI lint | `cargo clippy --workspace -- -D warnings` | `.github/workflows/build.yml` |
| Hot-reload verification | Phase 4 | Integration (in-process) | `cargo test -p dlp-e2e --test hot_reload_config` | `dlp-e2e/tests/hot_reload_config.rs` |
| Release-mode smoke | Phase 24 | Integration (release binary) | `cargo test -p dlp-e2e --test release_smoke -- --ignored` | `dlp-e2e/tests/release_smoke.rs` |
| TUI Device Registry | Phase 28 | Headless TUI | `cargo test -p dlp-e2e --test tui_device_registry` | `dlp-e2e/tests/tui_device_registry.rs` |
| TUI Managed Origins | Phase 28 | Headless TUI | `cargo test -p dlp-e2e --test tui_managed_origins` | `dlp-e2e/tests/tui_managed_origins.rs` |
| TUI Conditions Builder | Phase 28 | Headless TUI | `cargo test -p dlp-e2e --test tui_conditions_builder` | `dlp-e2e/tests/tui_conditions_builder.rs` |
| USB write-protection | Phase 28 | PowerShell (manual) | `powershell -File scripts/Uat-UsbBlock.ps1` | `scripts/Uat-UsbBlock.ps1` |

---

## Sampling Rate

- **Per task commit:** `cargo test -p dlp-e2e --test <relevant_test>`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full workspace test green + clippy zero warnings + SonarQube quality gate

---

## Wave 0 Gaps (pre-execution)

- [ ] `dlp-e2e/Cargo.toml` — new workspace member crate
- [ ] `dlp-e2e/src/lib.rs` — shared test helpers (mock server builder, JWT minting)
- [ ] `dlp-e2e/tests/tui_device_registry.rs` — TUI headless test
- [ ] `dlp-e2e/tests/tui_managed_origins.rs` — TUI headless test
- [ ] `dlp-e2e/tests/tui_conditions_builder.rs` — TUI headless test
- [ ] `dlp-e2e/tests/agent_toml_writeback.rs` — full stack test
- [ ] `dlp-e2e/tests/hot_reload_config.rs` — hot-reload test
- [ ] `dlp-e2e/tests/release_smoke.rs` — release-mode smoke test
- [ ] `scripts/Uat-UsbBlock.ps1` — USB hardware verification script
- [ ] `.github/workflows/nightly.yml` — nightly release-mode CI workflow
- [ ] Root `Cargo.toml` — add `dlp-e2e` to workspace members

---

## Nyquist Compliance

| Dimension | Status |
|-----------|--------|
| 1. Goal Clarity | PASS |
| 2. Success Criteria Coverage | PASS |
| 3. Research Coverage | PASS |
| 4. Task Granularity | PASS |
| 5. Dependency Graph | PASS |
| 6. Risk Assessment | PASS |
| 7. Resource Requirements | PASS |
| 8. Automated Verification | PASS |
| 9. Cross-Plan Contracts | PASS |
| 10. CLAUDE.md Compliance | PASS |
| 11. Research Resolution | PASS |
| 12. Pattern Compliance | SKIPPED (no PATTERNS.md) |
