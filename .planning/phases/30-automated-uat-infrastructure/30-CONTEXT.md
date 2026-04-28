# Phase 30: Automated UAT Infrastructure - Context

**Gathered:** 2026-04-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Build automated verification scripts and test harnesses to replace deferred human UAT checkpoints from Phases 4, 6, 24, and 28. No new product capabilities — only automation of existing functionality.

Requirements validated: APP-04, BRW-02, USB-01..04 (via automated verification of deferred UAT)

### Deferred UAT Items Being Automated

| Phase | Deferred Item | Automation Approach |
|-------|--------------|---------------------|
| Phase 6 | Agent TOML write-back test | Rust integration test (full stack) |
| Phase 6 | Zero-warning workspace build | `cargo build --workspace -D warnings` in CI |
| Phase 4 | SMTP email delivery | Skip — config acceptance sufficient |
| Phase 4 | Webhook POST delivery | Skip — config acceptance sufficient |
| Phase 4 | Hot-reload verification | Rust integration test (all config types) |
| Phase 24 | Release-mode build + smoke | Nightly CI with separate target-release |
| Phase 28 | TUI screen flows | Headless crossterm event injection (dlp-e2e crate) |
| Phase 28 | USB write-protection | Two-tier: unit tests + real hardware PowerShell script |

</domain>

<decisions>
## Implementation Decisions

### Test Harness Architecture

- **D-01:** Mixed approach — Rust integration tests for API-layer verification (device registry, managed origins, hot-reload), PowerShell scripts for process-orchestration and Windows-native tests (USB hardware, service lifecycle).
- **D-02:** Rust tests live in a dedicated `dlp-e2e` crate (new). Keeps dlp-admin-cli, dlp-agent, and dlp-server crates clean of cross-process test dependencies.
- **D-03:** PowerShell scripts live under `scripts/Uat-*.ps1`. These are local-only manual tests, not run in CI.

### USB Write-Protection Verification

- **D-04:** Two-tier verification:
  - **Unit-test tier** — `UsbEnforcer::check()` logic with seeded registry cache (blocked/read_only/full_access). `set_disk_read_only()` tested with mock Win32 device handle.
  - **Real-hardware tier** — PowerShell script (`scripts/Uat-UsbBlock.ps1`) for local execution with physical USB device.
- **D-05:** PowerShell script behavior:
  - Auto-detects removable USB drives via WMI (`Win32_DiskDrive`), prompts user to select one interactively.
  - Registers device via admin API (`POST /admin/device-registry`) for full-stack verification.
  - Verifies both `blocked` (writes return ERROR_WRITE_PROTECT) and `read_only` (reads allowed, writes denied) tiers.
  - Full cleanup after test: removes registry entry via `DELETE /admin/device-registry/{id}` and clears `DISK_ATTRIBUTE_READ_ONLY` via `IOCTL_DISK_SET_DISK_ATTRIBUTES`.
  - Plain-text color-coded PASS/FAIL console output. No structured report format.
- **D-06:** Real-hardware script is local-only, marked `@Manual`, not run in CI. Documented as required UAT step before release.

### TUI Test Harness

- **D-07:** Headless crossterm event injection using `ratatui::backend::TestBackend`. Inject `KeyEvent` sequences into the `App` event loop and assert on state + render.
- **D-08:** Scope: all three Phase 28 TUI screens:
  1. Device Registry (list, register, delete)
  2. Managed Origins (list, add, remove)
  3. App-Identity Conditions Builder (SourceApplication / DestinationApplication picker)
- **D-09:** Verification level: both state assertions (internal `App` state after key sequence) and render assertions (`TestBackend::buffer()` for key rendering moments).
- **D-10:** HTTP dependency: real mock axum server spun up in-process, same pattern as existing dlp-server integration tests.
- **D-11:** Test crate: dedicated `dlp-e2e` crate. Runs with `cargo test -p dlp-e2e`.

### CI Integration

- **D-12:** Add `cargo test --workspace` job to `.github/workflows/build.yml`.
- **D-13:** Runner: `windows-latest` (required for Windows-only project with Win32 APIs).
- **D-14:** Target directory: use default `target/` in CI. The `CARGO_TARGET_DIR=target-test` workaround is for local dev only (elevated process lock issue).
- **D-15:** Release-mode build: separate nightly scheduled workflow, not on every PR. Uses `target-release` directory to avoid conflicts with debug builds.

### Phase 6 — Agent TOML Write-Back

- **D-16:** Rust integration test using `std::process::Command` to spawn dlp-server + dlp-agent.
- **D-17:** Test environment: both temp directory (default, no admin rights) and real `C:\ProgramData\DLP\` (optional, ignored by default, runs in CI with admin).
- **D-18:** DB seeding: via admin API with JWT (`POST /admin/config`). Exercises full stack.
- **D-19:** Verification: full round-trip exact values. Seed DB with specific config, wait for agent poll, assert TOML contains exact values.
- **D-20:** Timing: fast-poll mode. Seed DB with `heartbeat_interval_secs = 1` so agent polls within 1-2 seconds.
- **D-21:** Zero-warning build: `cargo build --workspace` with `-D warnings` (or `cargo clippy -- -D warnings`). Fail on any warning.

### Phase 24 — Release-Mode Build + Smoke

- **D-22:** Nightly CI only (scheduled workflow, not on every PR/push).
- **D-23:** Target directory: `target-release` (separate from debug `target/`).
- **D-24:** Smoke test: run full integration tests (`device_registry_integration.rs`, `managed_origins_integration.rs`) against release binary.

### Phase 4 — SMTP, Webhook, Hot-Reload

- **D-25:** SMTP delivery verification: **skip**. Config acceptance tests already verify SMTP config is persisted. Email delivery is an external dependency.
- **D-26:** Webhook delivery verification: **skip**. Same rationale as SMTP.
- **D-27:** Hot-reload verification: Rust integration test covering all config types (SIEM, alerts, agent config, operator config). Seed DB with new config, trigger hot-reload, assert behavior changes.

### Claude's Discretion

- Exact structure of `dlp-e2e` crate (whether it uses workspace member or standalone).
- Whether to use `tokio::process::Command` or `std::process::Command` for process spawning in Rust tests.
- Exact KeyEvent sequence for each TUI screen test.
- Whether the hot-reload test uses a single combined test or separate tests per config type.
- Format and location of nightly CI workflow file (`.github/workflows/nightly.yml` or separate job in `build.yml`).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — APP-04, BRW-02, USB-01..04 requirement definitions
- `.planning/ROADMAP.md` §Phase 30 — 5 success criteria
- `.planning/STATE.md` §Deferred Items — Phase 4, 6, 24 deferred UAT items

### Prior Phase Context (patterns and prior decisions)
- `.planning/phases/28-admin-tui-screens/28-CONTEXT.md` — TUI screen patterns, ratatui conventions, Device Registry / Managed Origins / Conditions Builder flows
- `.planning/phases/24-device-registry-db-admin-api/24-CONTEXT.md` — Device registry API shape, upsert-on-conflict pattern
- `.planning/phases/26-abac-enforcement-convergence/26-CONTEXT.md` — `UsbEnforcer::check()`, `UsbBlockResult`, `AppField`

### Key Source Files (read before touching)
- `dlp-admin-cli/src/app.rs` — `Screen` enum, `ConditionAttribute` enum, `ConditionsBuilder` variant
- `dlp-admin-cli/src/screens/dispatch.rs` — `operators_for()`, `value_count_for()`, event handling
- `dlp-admin-cli/src/screens/render.rs` — all `Screen` render arms
- `dlp-agent/src/detection/usb.rs` — `UsbDetector`, `set_disk_read_only()`, `IOCTL_DISK_SET_DISK_ATTRIBUTES`
- `dlp-agent/src/usb_enforcer.rs` — `UsbEnforcer::check()`, `UsbBlockResult`
- `dlp-agent/src/config.rs` — `AgentConfig`, `AgentConfig::load()`, `AgentConfig::save()`
- `dlp-agent/src/service.rs` — config poll loop, background task spawning
- `dlp-server/src/admin_api.rs` — admin API routes, JWT middleware, `AppState`
- `dlp-server/src/db/mod.rs` — schema initialization
- `dlp-server/tests/device_registry_integration.rs` — existing integration test pattern
- `dlp-server/tests/managed_origins_integration.rs` — existing integration test pattern
- `dlp-agent/tests/comprehensive.rs` — mock axum server pattern, `EngineClient` tests
- `.github/workflows/build.yml` — existing CI workflow

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `TestBackend` from `ratatui::backend::TestBackend` — for headless TUI tests
- `crossterm::event::KeyEvent` — inject into `App::handle_event()` for headless tests
- Mock axum server pattern from `comprehensive.rs` — `start_engine_with_json_response()` helper
- `DeviceRegistryIntegration` tests — template for dlp-e2e tests
- `ManagedOriginsIntegration` tests — template for dlp-e2e tests
- `AgentConfig::load()` / `AgentConfig::save()` — already exist for TOML round-trip
- PowerShell service management scripts (`scripts/Manage-DlpAgentService.ps1`) — template for UAT scripts

### Established Patterns
- Integration tests spawn mock axum servers inline using `tokio::net::TcpListener` on port 0
- `CARGO_TARGET_DIR=target-test` for local dev to bypass locked binary (CI uses default target)
- DB seeding in tests: direct SQLite or via admin API (both patterns exist)
- Agent background tasks: `tokio::spawn(async move { loop { ... tokio::time::sleep(interval).await; } })`
- `#[cfg(test)]` modules for test code; `#[cfg(windows)]` for Windows-specific tests
- `#[ignore]` for tests requiring admin rights or physical hardware

### Integration Points
- `dlp-e2e` crate (new) depends on `dlp-admin-cli`, `dlp-agent`, `dlp-server`, `dlp-common`
- TUI tests inject events into `App::handle_event()` and inspect `App.screen` state
- USB unit tests mock `CreateFileW`/`DeviceIoControl` via trait or conditional compilation
- PowerShell scripts call admin API with JWT (same auth as dlp-admin-cli TUI)
- CI workflow `.github/workflows/build.yml` needs new job for `cargo test --workspace`
- Nightly workflow (new) for release-mode build + smoke tests

</code_context>

<specifics>
## Specific Ideas

- USB real-hardware script should auto-detect removable drives via `Get-WmiObject Win32_DiskDrive` and present a numbered menu. User selects drive by number.
- TUI headless tests should verify at least one render assertion per screen: DeviceList shows `[BLOCKED]` tag, ManagedOriginList shows origin string, ConditionsBuilder shows `SourceApplication`/`DestinationApplication` in Step 1 picker.
- Fast-poll mode for TOML write-back: seed `heartbeat_interval_secs = 1` in `agent_config` row so agent polls within 1-2 seconds. Test should complete in <5 seconds.
- Zero-warning build: use `RUSTFLAGS='-D warnings'` env var in CI, not `#![deny(warnings)]` in source (per CLAUDE.md §9.15).
- Nightly release-mode workflow should use `CARGO_TARGET_DIR=target-release cargo build --release` to avoid debug/release conflicts.
- Hot-reload test should verify at least one config type per subsystem: SIEM (Splunk HEC URL change), alerts (SMTP server change), agent config (monitored_paths change), operator config (rate limit change).

</specifics>

<deferred>
## Deferred Ideas

- **TCP notification / server-push for immediate agent polling** — User requested signal/notify mechanism for immediate agent config refresh. This is a new capability requiring server→agent push channel. Belongs in a future phase (post-Phase 29) or as a v0.7.x hardening item.
- **Structured test report format (NUnit/JUnit XML)** — User chose plain-text output for USB script. Structured format can be revisited if USB script is promoted to CI test lab.
- **VHD/virtual-disk simulation for USB testing in CI** — Real hardware is the only way to verify actual kernel-level IOCTL behavior. VHD simulation could be explored as a CI-only alternative but is not a Phase 30 priority.
- **Full release-mode tests on every PR** — User chose nightly only. Can be promoted to PR-gate if release build time improves or if caching (sccache) is added.

### Reviewed Todos (not folded)
None — Phase 30 is a new infrastructure phase with no prior todo items.

</deferred>

---

*Phase: 30-automated-uat-infrastructure*
*Context gathered: 2026-04-28*
