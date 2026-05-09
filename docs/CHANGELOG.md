# Changelog

All notable changes to the DLP-RUST system are documented in this file.

---

## [v0.9.0] — M017 — 2026-05-09

### Added

#### Phase 8 — Cloud Channel Enforcement
- **WFP egress blocking** (`dlp-agent/src/wfp_ffi.rs`, `wfp_manager.rs`): Windows Filtering Platform FFI bindings and `WfpManager` that installs a DLP sublayer and adds per-PID TCP/443 egress block filters (`FWP_ACTION_BLOCK` on `FWPM_LAYER_ALE_AUTH_CONNECT_V4`) when cloud upload is denied.
- **IAT hook DLL injection** (`dlp-agent/src/hook_injector.rs`, `hook_ipc.rs`): `HookInjector` uses `CreateRemoteThread` + `LoadLibraryW` to inject the hook DLL into monitored processes. Supports both x64 and x86 targets with architecture checking. Hook requests are routed to the agent via named pipe IPC (`HookRequest` / `HookResponse`).
- **CloudEnforcer** (`dlp-agent/src/cloud/`): Wires `HookInjector` and `WfpManager` together; evaluates the new `CLOUD_UPLOAD` ABAC action per intercepted upload attempt.
- **ShareLinkEnforcer** (`dlp-agent/src/clipboard/`): Detects cloud share-link URL patterns in clipboard copy events; evaluates the `SHARE_LINK` ABAC action; clears clipboard on DENY.
- **`CLOUD_UPLOAD` and `SHARE_LINK` ABAC actions** (`dlp-common/src/abac.rs`): Two new `Action` variants added to the ABAC enum.
- **Cloud config DB table and API** (`dlp-server/src/db/`): `cloud_config` single-row table with `cloud_hook_enabled` boolean; managed via `GET/PUT /admin/cloud-config`.
- **CloudConfig admin screen** (`dlp-admin-cli/src/screens/cloud_config.rs`): TUI screen to toggle `cloud_hook_enabled`, accessible from Main Menu.
- **Sync-client process watcher** (`dlp-agent/src/service.rs`): Background thread monitors cloud sync client processes (OneDrive, Dropbox, Google Drive) for injection and enforcement.

#### Phase 9 — Print Spooler Enforcement
- **PrintWatcher** (`dlp-agent/src/print_watcher.rs`): Spooler watcher thread using `FindFirstPrinterChangeNotification`; fires on `PRINTER_CHANGE_ADD_JOB`; classifies content and enforces ABAC policy.
- **PrintJobInfo** (`dlp-agent/src/print_job_info.rs`): Safe RAII wrappers around `OpenPrinterW`, `GetJobW`, and `SetJobW` for querying and cancelling print jobs. `PrinterHandle` auto-closes via `Drop`.
- **XPS parser** (`dlp-agent/src/print_xps_parser.rs`): Reads XPS spool files as ZIP archives, parses `.fpage` XML, and extracts `Glyphs` `UnicodeString` attributes up to a configurable page limit.
- **`PRINT` ABAC action** (`dlp-common/src/abac.rs`): New `Action::PRINT` variant.
- **Print config DB table and API** (`dlp-server/src/db/`): `print_config` single-row table with `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`, `print_max_pages`; managed via `GET/PUT /admin/print-config`.
- **PrintConfig admin screen** (`dlp-admin-cli/src/screens/print_config.rs`): TUI screen to configure all four print enforcement fields.
- **`AgentConfigPayload` extension** (`dlp-common/src/config.rs`): Cloud and print config fields added to the payload pushed from server to agents on heartbeat.
- **PrintEnforcer wired into service lifecycle** (`dlp-agent/src/service.rs`): Print watcher started/stopped with the agent service.

### Changed
- **TESTING.md** — cloud and print test modules updated from "Phase 9 stubs" to implemented: `cloud_tc` (TC-30–36) and `print_tc` (TC-50–54).
- **Database schema** — two new config tables (`cloud_config`, `print_config`) added to `db.rs` schema initialisation.
- **Admin CLI Main Menu** — two new entries: CloudConfig and PrintConfig.

---

## [v0.8.1] — 2026-04-30

### Added
- Milestone v0.8.1 completion: UAT/regression validation phase (Phase 46) complete.
- Full workspace `cargo test --all` passing with no warnings.

---

## [v0.8.0] — Prior to v0.8.1

Covers Phases 1–7: foundation, process protection, file interception, production hardening, central management, config push, and Active Directory LDAP integration.

See git history for detailed change records.
