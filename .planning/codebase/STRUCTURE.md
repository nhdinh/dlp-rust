# STRUCTURE

## Top-level directory layout

- `Cargo.toml` / `Cargo.lock` — workspace manifest and lockfile
- `dlp-common/` — shared library crate (types, policy/context contracts, common logic)
- `dlp-server/` — central management/policy engine server crate
- `dlp-agent/` — endpoint Windows Service enforcement crate
- `dlp-user-ui/` — endpoint user-session UI crate
- `dlp-admin-cli/` — administrator terminal UI crate
- `dlp-hook-dll/` — hook DLL crate (`cdylib`) for interception/injection paths
- `dlp-e2e/` — end-to-end/integration harness crate spanning components
- `docs/` — architecture, security, configuration, testing, and operational documentation
- `scripts/` — PowerShell operational scripts (component/service lifecycle, UAT helpers)
- `installer/` — installer assets and build script (WiX + PowerShell)
- `.github/workflows/` — CI workflow definitions (`build.yml`, `nightly.yml`)

(Additional project management/system directories like `.gsd/`, `.planning/`, `.beads/` are present but are not product runtime code.)

## Source code organization by crate

## `dlp-server/src/`
- `main.rs` — server startup/bootstrap, config parsing, DB init, background tasks, router serve
- `lib.rs` — shared state and top-level module exports
- `admin_api.rs` — primary REST route composition and handlers
- `admin_auth.rs` — auth/JWT/admin credential logic
- `policy_store.rs`, `policy_sync.rs` — policy cache/sync logic
- `agent_registry.rs` — agent heartbeat/registry lifecycle
- `audit_store.rs`, `exception_store.rs` — audit/exception persistence APIs
- `siem_connector.rs`, `alert_router.rs` — outbound integrations
- `rate_limiter.rs` — request throttling integration
- `db/` — DB layer
  - `db/repositories/` — repository modules per table/domain

## `dlp-agent/src/`
Representative module groups visible in tree/file list:
- Service lifecycle: `main.rs`, `service.rs`
- Policy client/offline behavior: `engine_client.rs`, `offline.rs`, `server_client.rs`
- Enforcement modules: `cloud_enforcer.rs`, `disk_enforcer.rs`, `print_enforcer.rs`, `share_link_enforcer.rs`, `usb_enforcer.rs`
- Device/session/identity: `device_controller.rs`, `device_registry.rs`, `identity.rs`, `session_identity.rs`, `session_monitor.rs`
- Hook/IPC plumbing: `hook_injector.rs`, `hook_ipc.rs`, `ipc/` and interception-related modules
- Detection/watchers: `health_monitor.rs`, print and platform watcher modules
- Platform-specific support: `wfp_manager.rs`, `wfp_ffi.rs`, Windows interop-heavy files

Subdirectories observed:
- `src/chrome/`
- `src/clipboard/`
- `src/detection/`
- `src/interception/`
- `src/ipc/`

## `dlp-user-ui/src/`
- UI/dialog and notification logic
- IPC-facing modules and desktop interaction boundaries
- Observed dirs: `detection/`, `dialogs/`, `ipc/`

## `dlp-admin-cli/src/`
- `main.rs` — CLI entry + pre-TUI connection/auth flow
- `app.rs`, `engine.rs`, `client.rs`, `login.rs`, `tui.rs` — application state, API client, login bootstrap, terminal runtime
- `screens/` — screen-level rendering and event handling modules

## `dlp-common/src/`
- Shared policy and identity/domain structures (`abac.rs`, `classification.rs`, `audit.rs`, etc.)
- Shared integration/client helpers (`ad_client.rs`, endpoint and USB/disk-related shared contracts)

## `dlp-hook-dll/src/`
- `lib.rs` entrypoint for DLL export behavior
- Hook/client integration units (`pipe_client.rs`, `hook.def`, debug test module)

## Test organization

## Crate-local tests
- Server integration tests under `dlp-server/tests/`
- Agent tests under `dlp-agent/tests/` (integration/comprehensive/negative/etc.)
- Common crate tests under `dlp-common/tests/`
- E2E-focused tests under `dlp-e2e/tests/`

## Dedicated E2E crate
- `dlp-e2e/` links against core crates and provides cross-component scenarios
- Includes `examples/` for debugging (e.g., `debug_tui.rs`)

## Build scripts and generated-code entry points
- Build scripts (`build.rs`) in `dlp-agent/`, `dlp-user-ui/`, `dlp-hook-dll/`
- Agent proto schema in `dlp-agent/proto/content_analysis.proto` indicates generated code path via build-time prost setup

## Configuration and operations files

## Product/runtime configuration surfaces
- CLI/server connection defaults and flags in crate entrypoints (`main.rs` files)
- DB path / bind / log-level options in server CLI flags
- Registry and Windows-specific config hooks referenced by admin CLI and runtime modules

## Project/ops configuration
- `.cargo/config.toml` — cargo behavior configuration
- `.github/workflows/*.yml` — CI pipelines
- `scripts/*.ps1` — local deployment/service management and UAT scripts
- `installer/DLPAgent.wxs` + `installer/build.ps1` — installer packaging config
- `docs/*.md` — canonical documentation for architecture/security/testing/ops

## Practical navigation map

For implementation work, most changes cluster in:
1. `dlp-agent/src/*` for endpoint enforcement behavior
2. `dlp-server/src/*` and `dlp-server/src/db/repositories/*` for policy/admin/data plane behavior
3. `dlp-common/src/*` when contracts/types change across components
4. `dlp-admin-cli/src/screens/*` and related files for operator UX

For verification work, start with the crate-local `tests/` folder, then `dlp-e2e/tests/` for cross-component behavior.
