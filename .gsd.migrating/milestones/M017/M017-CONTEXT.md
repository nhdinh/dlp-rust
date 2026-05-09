---
depends_on: []
---

# M017: v0.9.0 Cloud & Print Exfiltration Prevention

**Gathered:** 2026-05-08
**Status:** Ready for planning

## Project Description

M017 closes the two largest remaining exfiltration channels in the DLP system: cloud sync and print. As of v0.8.1, the system prevents USB, disk, clipboard, and drag-and-drop exfiltration — but files copied to OneDrive/Dropbox/Google Drive/Box sync folders print without interception. This milestone delivers true preventive controls for both channels using only user-mode APIs (no kernel driver, no minifilter, no EV signing).

## Why This Milestone

Cloud sync and print are the #1 and #2 exfiltration vectors not yet covered. The existing `notify`-based file monitoring is post-event audit only — it cannot prevent uploads. A DLP that can't block cloud uploads or print jobs has a massive compliance blind spot. This milestone builds the interception infrastructure (API hooking + WFP) that also serves future file interception needs.

## User-Visible Outcome

### When this milestone is complete, the user can:

- Copy a T4 file to a OneDrive folder → the write is blocked before OneDrive sees it
- Copy a T1 file to Dropbox → allowed, no friction
- Print a document containing T4 content → job cancelled before reaching printer
- Print T3 content → auth dialog required
- Copy a cloud share link (`https://1drv.ms/...`) to clipboard → alert emitted if linked content is sensitive
- Configure print monitoring thresholds and cloud provider settings via admin CLI

### Entry point / environment

- Entry point: DLP Agent Windows Service (dlp-agent.exe)
- Environment: Windows 10+ endpoints with cloud sync clients installed
- Live dependencies involved: OneDrive, Google Drive, Dropbox, Box sync clients; Windows Print Spooler; Windows Filtering Platform

## Completion Class

- Contract complete means: Hook DLL injects into sync clients, WFP filter registers, print spooler watcher starts, ABAC Action::CLOUD_UPLOAD and Action::PRINT evaluate correctly, all unit tests pass
- Integration complete means: Real sync client blocked on T4 write, real print job cancelled on T4 content, audit events flow to server, admin CLI shows status
- Operational complete means: Agent service starts/stops cleanly with hooks, WFP filter installs/uninstalls without reboot, config hot-reload updates thresholds, no memory leaks or handle leaks under sustained load

## Final Integrated Acceptance

To call this milestone complete, we must prove:

- OneDrive + Dropbox + Google Drive + Box sync clients all block T4 file writes on a live Windows machine
- A T4 print job is cancelled before the printer receives it
- A cloud share link copied to clipboard triggers an Alert audit event
- All existing v0.8.1 interception (USB, disk, clipboard, drag-and-drop) continues to work — zero regressions
- Admin CLI can view and configure cloud/print policy settings

## Architectural Decisions

### Cloud sync interception via API hooking + WFP

**Decision:** Use user-mode API hooking (IAT) in sync client processes for pre-write blocking, backed by WFP network egress filtering.

**Rationale:** True file interception without kernel driver or EV code signing. Hooks catch the common path (CreateFileW/NtCreateFile). WFP catches bypasses (direct syscalls, alternative upload paths).

**Alternatives Considered:**
- Kernel minifilter driver — Rejected: requires EV code signing, which is unavailable
- `notify` post-event monitoring — Rejected: cannot prevent uploads, only audit them
- API hooking only (no WFP) — Rejected: bypassable via direct syscalls

### Print spooler interception (medium approach)

**Decision:** Spool directory watch + XPS content extraction + `SetJob(..., JOB_CONTROL_DELETE)` cancellation.

**Rationale:** User-mode only, no port monitor DLL. `FindFirstPrinterChangeNotification` detects jobs. SHD metadata + SPL XPS parsing extracts content. `SetJob` cancels blocked jobs.

**Alternatives Considered:**
- Full port monitor DLL — Deferred: more robust but significantly more complex, requires spoolsv.exe integration
- Metadata-only — Rejected: user explicitly requested content peeking

### Cloud sync path discovery

**Decision:** Registry-based dynamic discovery with hardcoded path fallback.

**Rationale:** Enterprise deployments redirect sync folders. Registry/shell APIs discover actual paths. Hardcoded defaults cover the 90% case when discovery fails.

**Alternatives Considered:**
- Hardcoded only — Rejected: fails on non-default installs
- Sync client APIs — Rejected: provider-specific, undocumented, fragile

### Cloud share link detection

**Decision:** Clipboard URL pattern matching + stricter ABAC policy for sync-folder files.

**Rationale:** Local detection of share link creation is provider-specific and fragile. Clipboard monitoring catches share URLs post-creation. Stricter ABAC policy treats sync-folder files as higher-risk context.

**Alternatives Considered:**
- Sync client database monitoring — Rejected: internal schemas change between versions
- Cloud provider admin APIs — Rejected: server-side, not agent-side DLP

## Error Handling Strategy

| Failure Mode | Behavior |
|-------------|----------|
| API hook injection fails into sync client | WFP network filter blocks process HTTPS egress → upload prevented at network layer |
| API hook bypassed (direct syscall) | WFP catches upload attempt |
| Sync client updates, hook breaks | Agent detects version mismatch via process hash, alerts admin, WFP remains active |
| Classification timeout in hook DLL | Return `ACCESS_DENIED` immediately (fail-closed) |
| Agent service offline when hook DLL calls named pipe | Hook returns `ACCESS_DENIED` (fail-closed) |
| XPS parsing fails / not XPS format | Fall back to metadata-only. Config-driven: default `DENY` for T4, `ALLOW` for T1-T3 |
| WFP filter fails to register | Alert admin, degrade to detective-only (audit + alert on notify events) |
| `SetJob` cancellation fails | Emit Alert event — job may have printed, but incident is logged |

## Risks and Unknowns

- **API hook stability in sync client processes** — OneDrive/Dropbox may have anti-tampering or self-update mechanisms that break hooks. Why it matters: if hooks are unreliable, WFP is the only line of defense.
- **WFP filter coexistence with other security products** — VPNs, EDR, other WFP filters may conflict. Why it matters: WFP filter registration could fail or be bypassed by higher-priority filters.
- **XPS parsing performance on large print jobs** — Parsing a 100-page XPS while the spooler waits could cause timeouts. Why it matters: slow parsing delays printing for all users.
- **Named pipe latency between hook DLL and agent service** — Hook is in the hot path of every file create. Why it matters: high latency degrades system performance.
- **Hook DLL architecture mismatch** — Sync clients may be x64; agent service injects x64 DLL. But what about 32-bit processes? Why it matters: need separate 32-bit and 64-bit DLL builds.

## Existing Codebase / Prior Art

- `dlp-agent/src/interception/file_monitor.rs` — Existing `notify`-based file monitoring. Will be superseded by API hooking for sync folders, but remains for general file audit.
- `dlp-agent/src/interception/mod.rs` — Event loop that processes file actions, resolves identity, runs ABAC. The hook DLL will integrate here via a new IPC channel.
- `dlp-common/src/abac.rs` — ABAC types and evaluation. Needs `Action::CLOUD_UPLOAD` and `Action::PRINT` variants.
- `dlp-agent/src/audit_emitter.rs` — Audit event emission. Hook DLL and print watcher will emit through the same pipeline.
- `dlp-agent/src/service.rs` — Service startup. Needs to initialize hook injector and WFP filter.
- `dlp-agent/src/usb_enforcer.rs` / `dlp-agent/src/disk_enforcer.rs` — Existing enforcer pattern. Cloud and print enforcers will follow similar structure.
- `dlp-agent/tests/comprehensive.rs` — Test stubs TC-30..33 (cloud) and TC-50..52 (print) need real implementations.

## Relevant Requirements

- R001 — Cloud sync folder write interception → Advanced by S01 (hook framework) and S02 (cloud sync integration)
- R002 — Cloud share link detection → Advanced by S03
- R003 — Print spooler interception → Advanced by S04
- R004 — WFP network egress blocking → Advanced by S01
- R005 — Admin-configurable print settings → Advanced by S04
- R006 — Dynamic cloud sync path discovery → Advanced by S02

## Scope

### In Scope

- API hook DLL (Rust `cdylib`) for sync client process injection
- WFP network filter registration and management
- Named pipe protocol between hook DLL and agent service
- Cloud sync path discovery for OneDrive, Google Drive, Dropbox, Box
- ABAC integration with Action::CLOUD_UPLOAD
- Print spooler watcher (FindFirstPrinterChangeNotification)
- SHD metadata parser and SPL XPS content extractor
- ABAC integration with Action::PRINT
- Admin-configurable print settings (enable/disable, thresholds)
- Cloud share link clipboard detection
- Stricter ABAC policy for files in sync folders
- Admin CLI screens for cloud/print status and config
- End-to-end tests replacing TC-30..33 and TC-50..52 stubs

### Out of Scope / Non-Goals

- Kernel minifilter driver (R020 — explicitly rejected)
- Full port monitor DLL (R017 — deferred)
- EMF content extraction for print (R018 — deferred, fallback to metadata)
- Browser-level upload interception (M018)
- Dashboard/analytics (M019)
- Bulk download threshold detection (M020)
- Firefox/Safari browser extension support (R019 — deferred)

## Technical Constraints

- No kernel driver or minifilter (no EV signing certificate)
- Windows 10+ only (WFP, modern print spooler APIs)
- Agent runs as SYSTEM — can inject into other processes but must be stable
- All blocking must complete without degrading user experience (print jobs, file copies should not hang)
- Must coexist with existing USB/disk/clipboard interception — no regressions

## Integration Points

- **OneDrive / Google Drive / Dropbox / Box sync clients** — Target processes for API hook injection. Paths discovered dynamically.
- **Windows Filtering Platform** — Built-in OS feature for network filtering. No external dependency.
- **Windows Print Spooler** — `FindFirstPrinterChangeNotification` and `SetJob` APIs.
- **dlp-server** — Agent config distribution (print thresholds, cloud provider enablement). Audit event ingestion.
- **dlp-admin-cli** — New screens for cloud provider status and print policy config.

## Testing Requirements

- Unit tests: Hook DLL logic (path matching, classification trigger), WFP filter management, XPS parser, SHD parser
- Integration tests: Named pipe protocol, hook injection into test processes, WFP filter registration
- E2E tests: Real sync client blocked on T4 write, real print job cancelled, share link detected
- Regression tests: All existing v0.8.1 tests continue to pass

## Acceptance Criteria

### S01: API Hook Framework + WFP Filter
- Hook DLL injects into a test process and intercepts CreateFileW
- WFP filter registers and blocks HTTPS from a test process
- Named pipe communication between hook DLL and agent service works
- Hook returns ACCESS_DENIED within 50ms when agent is offline

### S04: Print Spooler Interception
- `FindFirstPrinterChangeNotification` detects print jobs
- SHD parser extracts document name and user
- XPS parser extracts text content from SPL files
- `SetJob(..., JOB_CONTROL_DELETE)` cancels blocked jobs
- Admin config enable/disable works via hot-reload

### S02: Cloud Sync Interception
- Registry discovery finds actual sync paths for all 4 providers
- Hook blocks T4 file writes to OneDrive folder
- Hook allows T1 file writes
- WFP blocks network upload if hook is bypassed
- Fallback to hardcoded paths when registry discovery fails

### S03: Cloud Share Link Detection
- Clipboard monitor detects `1drv.ms` URL patterns
- Clipboard monitor detects `drive.google.com/share` patterns
- Clipboard monitor detects `dropbox.com/s` and `box.com/s` patterns
- Alert audit event emitted for T3/T4 linked content
- Stricter ABAC policy applied to files in sync folders

### S05: Integration & UAT
- TC-30..33 test stubs pass with real implementations
- TC-50..52 test stubs pass with real implementations
- No regressions in existing comprehensive tests
- Admin CLI shows cloud provider status and print policy config
- End-to-end UAT script verified on live Windows machine

## Open Questions

- None remaining — all architectural and scope decisions resolved during discussion.
