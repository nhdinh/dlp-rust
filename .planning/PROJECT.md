---
name: DLP-RUST
version: v0.11.0-shipped
last_updated: 2026-06-18
status: in_progress
shipped: v0.2.0, v0.3.0, v0.4.0, v0.5.0, v0.6.0, v0.7.0, v0.7.1, v0.8.0, v0.8.1, v0.9.0, v0.11.0
active_milestone: v0.10.0
---

# DLP-RUST — Enterprise Data Loss Prevention System

## Core Value

Prevent enterprise data exfiltration across all major Windows endpoint channels — file copy, USB, clipboard, drag-and-drop, cloud sync, print — through ABAC-based policy enforcement, without requiring kernel drivers or EV code signing.

## Mission

Deliver production-grade DLP for Windows enterprises that combines NTFS access control, Active Directory identity, and a fine-grained ABAC policy engine into a four-layer defense stack with centralized administration, real-time enforcement, and full audit/SIEM integration.

## What This Is

A five-crate Rust workspace deployed as Windows services and operator tooling:

| Crate | Role |
|-------|------|
| `dlp-common` | Shared types — ABAC engine, audit events, classification, AD client, disk/USB models |
| `dlp-server` | Central HTTP server — admin API, policy store, audit store, SIEM relay, alert router |
| `dlp-agent` | Windows Service — file/clipboard/USB/disk/cloud/print interception, policy enforcement, IPC |
| `dlp-user-ui` | User-session GUI — notifications, dialogs, clipboard monitor, system tray |
| `dlp-admin-cli` | Interactive TUI — password management, policy CRUD, system config screens |

### Architecture Layers

1. **Identity** — Active Directory via `ldap3`; AD is the source of identity truth.
2. **Access** — NTFS ACLs provide coarse-grained baseline enforcement.
3. **Policy** — ABAC engine evaluates user/resource/action/environment attributes against operator-authored rules (boolean ALL/ANY/NONE composition).
4. **Enforcement** — `dlp-agent` (SYSTEM session) intercepts I/O through OS-level hooks; `dlp-user-ui` (user session) handles clipboard and notifications.

### Critical Invariant

If NTFS ALLOW and ABAC DENY → FINAL RESULT = DENY. ABAC always tightens, never loosens, the underlying NTFS gate.

### Tech Stack

- **Language:** Rust Edition 2021, 100% of codebase
- **Async runtime:** Tokio (multi-threaded)
- **Platform:** Windows 10/11 only (Win32 API dependencies via `windows` 0.62)
- **Core deps:** `axum` 0.8, `rusqlite` 0.32 + `r2d2` 0.8, `ldap3` 0.11, `jsonwebtoken` 9.x
- **Enforcement deps:** `notify` 6.x, `prost` 0.13, `wmi` 0.14, `windows-service` 0.8
- **UI deps:** `ratatui` 0.29, `crossterm` 0.28, `iced` 0.13, `tray-icon` 0.19, `winrt-notification` 1.0
- **Infra deps:** `tracing`, `chrono` 0.4, `serde`, `parking_lot` 0.12, `tower-governor` 0.4, `lettre` 0.11

### Configuration Surfaces

- **Agent runtime config** — TOML at `C:\ProgramData\DLP\agent-config.toml`, polled from server with hot reload.
- **Operator config** — SQLite (SIEM destinations, alert routes, policies, device registries), hot-reload without restart.
- **Secrets** — Environment variables only (`JWT_SECRET`, SMTP creds, LDAP bind creds); never on disk in cleartext until v1.0.0 encryption phase.

## What This Is Not

- **Not** a kernel-driver DLP. User-mode IAT hooks + WFP cover the threat model without EV code signing.
- **Not** cross-platform. Windows-only by design; NTFS + AD enforcement is the foundation.
- **Not** a cloud-native policy engine. On-prem with enterprise AD dependency.
- **Not** file encryption at rest. NTFS ACLs + ABAC provide access control; encryption is out of scope.
- **Not** a native browser extension. Cloud share link detection works at clipboard layer.
- **Not** a mobile MDM. Endpoint DLP for managed Windows fleets only.

## Context

### Target Users

- Enterprise security teams running managed Windows fleets
- Compliance officers needing audit-grade evidence of access decisions
- Managed Service Providers protecting customer endpoints

### Operational Constraints

- Must work without kernel drivers (no EV cert chain in target environments).
- Must operate fail-safe: hook DLL fail-closed (deny on error), cloud enforcer fail-open (allow on error) — inverse policies justified by their respective threat models.
- Must produce SIEM-shaped audit events for every enforcement decision.
- Must run on locked-down endpoints where the agent has SYSTEM privileges but cannot enumerate or write user-session resources directly.

### Project Scale

- 10 milestones shipped (v0.2.0 through v0.9.0, v0.11.0)
- 50 phases executed
- ~9 months of development through 2026-05-22
- 659+ tests across the workspace, clippy-clean
- ~120K LOC Rust

## Current Milestone: v0.10.0 Real-Time File Access Prevention

**Goal:** Convert general file I/O from passive audit-trail-after-the-fact to active real-time blocking at the moment of access, via a hybrid of user-mode IAT hooks (primary enforcement), NTFS DACL tripwires (kernel-enforced backstop), and ETW Kernel-File telemetry (bypass detection). No kernel driver, no EV cert, no minifilter.

**Target features:**

- **Universal hook DLL injection** — generalize the v0.9.0 cloud-sync `dlp-hook-dll` pattern; inject into every user-mode process via `AppInit_DLLs` plus agent-driven `CreateRemoteThread` on process-creation events; allowlist system services and AV/EDR processes.
- **Expanded file-I/O hook surface** — patch `CreateFileW/A`, `NtCreateFile`, `WriteFile`, `MoveFileExW`, `CopyFileExW`, `DeleteFileW`, `SetFileInformationByHandle`; cover local NTFS, network shares (UNC paths), and SD / optical / virtual drives (SEED-004 folded in).
- **ntdll syscall-stub patching** — in-memory Detours-style trampoline on ntdll syscall entries to close the direct-syscall bypass hole.
- **DACL tripwire for T3/T4 root paths** — agent writes explicit Deny ACEs as defense-in-depth; repair watcher reverts and maintains under AD group changes and file moves.
- **ETW Kernel-File consumer + bypass alerts feed** — agent subscribes to `Microsoft-Windows-Kernel-File`; events that hit ETW but skipped the hook are flagged as suspected syscall-bypass and surfaced via SIEM, alert router, and a new admin TUI alerts feed.
- **Local classification cache on hook DLL** — in-process `path → classification` cache so fail-mode decisions don't require a live agent pipe.
- **Asymmetric fail semantics** — agent-unreachable: fail-closed for T3/T4 (return `ERROR_ACCESS_DENIED`), fail-open for T1/T2 (I/O proceeds, telemetry deferred). Cached classification drives the decision.
- **Admin CLI Protected Paths screen** — new TUI screen to list/add/remove DACL-tripwire path roots, with visible diff between policy-derived defaults and operator overrides.
- **Admin CLI Bypass Alerts screen** — new TUI screen for ETW-detected suspected-bypass events; integrates with SIEM relay and alert router.
- **SD/optical/virtual drive enumeration** — fold SEED-004 in; device enumeration for these volume classes; admin TUI policy UX mirrors USB/disk allowlist pattern.

**v1.0.0 Enterprise Hardening dropped.** HARD-02 through HARD-08 move to Out of Scope. HARD-01 (Secrets Encryption at Rest) stays validated — Phase 47 is shipped and carries forward as a v0.10.0 prerequisite. Phase 47's planning artifacts (`.planning/phases/47-secrets-encryption-at-rest/`) are retained, including the DPAPI-recovery handoff originally slated for v1.0.0 Phase 52 (now folded into v0.10.0's operational documentation surface).

## Shipped Milestones

### v0.11.0 — Label Service + Workflow + Syslog (Shipped: 2026-05-22)

**Delivered:**
- **Label Service** — SQLite schema with folder inheritance, ResolvedTier strictness semantics, label-aware ABAC evaluation, paginated admin API, admin TUI screens (Phase 59)
- **Data Owner Review Queue** — JWT-scoped confirmation/reject with SIEM audit, scanner confidence, department filtering (Phase 60)
- **Approval Workflow Engine** — T3 Data Owner approval with expiry, T4 Board Ed25519 digital signature, agent-side token validation (Phase 61)
- **Syslog Forwarder** — RFC 5424 over TLS, encrypted offline queue (KEK + DPAPI), admin TUI config screen (Phase 62)

**Deferred from v0.11.0:**
- Tamper-Evident Audit (HASH-01..04) → v0.12.0 or later
- Device Identity Expansion (DEVICE-01..05) → v0.12.0 or later

## Next Milestones (Pilot-First Path)

### v0.12.0 — Scanner Integration + Endpoint Controls

**Goal:** Add automated data discovery and close remaining endpoint enforcement gaps.

**Target features:**

- **File Scanner** — share/folder enumeration, metadata collection, rule-based classifier (Vietnamese PII), temporary label auto-assignment. OCR deferred to v0.12.1+.
- **Screenshot Control** — detect and block/alert on screenshots involving T3/T4 data.
- **Print Watermarking** — overlay user/timestamp/device/tier/approval ID on approved print output.
- **Email/Outlook Interception** — block T3/T4 attachments to unauthorized recipients.
- **RDP/Bluetooth Blocking** — block file redirection and Bluetooth transfer for T3/T4.
- **Backup/Ransomware Documentation** — backup policy docs, ransomware heuristics, canary files.

## Requirements

### Validated

- ✓ **SIEM relay & alert routing** (v0.2.0) — webhook + email; agent config polling; JWT hardening
- ✓ **AD LDAP integration & rate limiting** (v0.3.0) — admin audit logging, SQLite pooling, PolicyStore
- ✓ **Policy authoring via Conditions Builder** (v0.4.0) — CRUD without raw JSON, import/export
- ✓ **Boolean condition logic** (v0.5.0) — ALL/ANY/NONE composition, in-place editing, expanded operators
- ✓ **Application-aware DLP** (v0.6.0) — Authenticode + AUMID identity, Chrome Enterprise Connector, USB enumeration with trust tiers
- ✓ **Disk exfiltration prevention** (v0.7.0) — disk enumeration, BitLocker verification, WM_DEVICECHANGE handling, disk allowlist, admin TUI
- ✓ **AGENT-UNKNOWN remediation & operational hardening** (v0.7.1) — per-user device registry, `wmi` crate upgrade
- ✓ **UWP & drag-and-drop enforcement** (v0.8.0) — AUMID for UWP, WH_GETMESSAGE drag-drop interception, browser origin-aware clipboard policies
- ✓ **Deferred items & issue debt** (v0.8.1) — PnP USB enforcement, mount-time disk blocking, configurable grace period, full SanDisk UAT
- ✓ **Cloud & print exfiltration prevention** (v0.9.0) — user-mode IAT hook + WFP for cloud sync, FindFirstPrinterChangeNotification + XPS extraction for print, share link detection, admin CLI Cloud/Print screens
- ✓ **Secrets Encryption at Rest** (v0.10.0 Phase 47, shipped 2026-05-11 as HARD-01) — PBKDF2 + DPAPI machine-bound KEK for SMTP, SIEM, JWT, LDAP bind credentials; cleartext columns dropped; KEK rotation via admin CLI; full migration + log-scan + rotation integration tests
- ✓ **SD / Optical / Virtual Drive Enumeration + Volume-Class ABAC** (v0.10.0 Phases 56–56.1, completed 2026-06-18) — device enumeration with `source_volume_class` and `destination_volume_class` ABAC attributes; hook DLL populates volume class; agent hook IPC evaluates volume-class policies synchronously via `OfflineManager::offline_decision` (DRIVE-01..04)

### Active (v0.10.0 — Real-Time File Access Prevention)

REQ-IDs defined in `.planning/REQUIREMENTS.md`. High-level coverage:

- [ ] **BLOCK-** — universal user-mode hook DLL injection (AppInit_DLLs + CreateRemoteThread), expanded file-I/O hook surface, ntdll syscall-stub patching
- [ ] **DACL-** — defense-in-depth NTFS Deny-ACE tripwire for T3/T4 paths with repair watcher
- [ ] **ETW-** — Kernel-File consumer for suspected syscall-bypass detection, wired into SIEM and alert router
- [ ] **CACHE-** — local classification cache on hook DLL for fail-mode decisions
- [ ] **FAIL-** — asymmetric fail semantics: fail-closed T3/T4, fail-open T1/T2 on agent-unreachable
- [ ] **UX-** — admin CLI Protected Paths screen + Bypass Alerts screen
- [ ] **OPS-** — deployment guide covering AV/EDR allowlist procedure for global DLL injection

### Active (Post-v0.10.0 — Pilot-First Path)

Requirements merged from target architecture gap analysis (`new_docs/`, 2026-05-12). Delivered across v0.11.0 and v0.12.0.

- [ ] **LABEL-** — Label Service: temporary/confirmed labels, folder inheritance, Data Owner review queue, manual assignment (v0.11.0)
- [ ] **WORKFLOW-** — Approval Workflow Engine: T3 Data Owner approval, T4 Board digital signature, approval token validation (v0.11.0)
- [ ] **SYSLOG-** — Native RFC 5424 syslog forwarding to SIEM/SOC with encrypted offline queue (v0.11.0)
- [ ] **HASH-** — SHA-256 append-only hash chain for tamper-evident audit logging (v0.11.0)
- [ ] **DEVICE-** — Device fingerprint hash, MAC collection, VPN state detection, domain state, health status (v0.11.0)
- [ ] **SCANNER-** — File enumeration, metadata collection, rule-based classifier, temporary label auto-assignment (v0.12.0)
- [ ] **SCREENSHOT-** — Screenshot detection and blocking based on ABAC policy (v0.12.0)
- [ ] **WATERMARK-** — Print watermarking with user/timestamp/device/tier/approval ID overlay (v0.12.0)
- [ ] **EMAIL-** — Outlook attachment interception, browser upload detection (v0.12.0)
- [ ] **RDP-** — RDP file redirection blocking for T3/T4 (v0.12.0)
- [ ] **BT-** — Bluetooth file transfer blocking for T3/T4 (v0.12.0)
- [ ] **BCK-** — Backup policy documentation, ransomware heuristics, canary files (v0.12.0)

### Architecture Constraints (Cross-Cutting)

Requirements merged from updated target architecture (`new_docs/` 2026-05-12). These are non-functional constraints verified at every phase.

- [ ] **ARCH-** — No Windows Minifilter driver or kernel-mode filesystem filter dependency. Build audit verifies no `.sys` files, no minifilter headers, no `FltRegisterFilter`. Every control documents its enforcement point (GPO/AppLocker, user-mode API, server-side ACL, etc.).
- [ ] **ARCH-** — Pilot acceptance test TC-017: no minifilter dependency in code, build artifacts, install steps, requirements, or tests. Hard gate for pilot readiness.

### Out of Scope

- **Mobile app** — Windows-first product
- **macOS/Linux agent** — NTFS enforcement requires Windows
- **Cloud-native policy engine** — on-prem DLP with enterprise AD dependency
- **File encryption at rest** — NTFS ACLs + ABAC provide access control; BitLocker for disk encryption
- **Raw JSON policy editing** — replaced by Conditions Builder in v0.4.0
- **Kernel minifilter driver** — user-mode API hooking + WFP + DACL tripwire + ETW sufficient; no EV cert path (reaffirmed for v0.10.0)
- **Native browser extension** — deferred to post-v1.0 milestone (v1.3)
- **Admin API module refactor (HARD-02)** — dropped from v1.0.0; revisit when monolith size becomes a velocity blocker
- **Password-protected service-stop E2E in CI (HARD-04)** — dropped from v1.0.0; manual test remains until a Windows CI runner is in place
- **Performance baseline at scale (HARD-07)** — dropped from v1.0.0; revisit when v0.10.0 hook DLL is in production
- **OCR pipeline (full)** — Tesseract/OCRmyPDF integration deferred to v0.12.1+. v0.12.0 scanner identifies image-only PDFs but does not extract text from them.
- **Seismic/survey file parsers** — folder-level labeling sufficient per organizational non-goals
- **Microsoft Purview/Intune as primary DLP** — endpoint agent is the primary enforcement layer
- **Backup tool implementation** — backup policy documented; external tools (Restic, Veeam, Kopia) recommended rather than built

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Agent runs as SYSTEM (session 0); UI runs in user sessions | SYSTEM cannot access user clipboard or display dialogs; UI handles user-session resources | ✓ Shipped v0.2.0+ |
| Clipboard monitoring lives in UI process, not agent | User session isolation required by Win32 | ✓ Shipped v0.2.0+ |
| Centralized server-side password management | Single source of truth; agent doesn't need HKLM write permission | ✓ Shipped v0.2.0+ |
| Operator config in SQLite (not env vars) | Hot-reload without service restart; TUI-manageable; persistent across upgrades | ✓ Shipped v0.3.0+ |
| Agent config polled from server, persisted to TOML | Offline availability after first poll; operator retains control via admin API | ✓ Shipped v0.2.0+ |
| PolicyStore in-memory cache with 5-min background refresh | Sync hot-path avoids DB round-trip; refresh catches operator updates | ✓ Shipped v0.3.0+ |
| User-mode IAT hook + WFP, not kernel minifilter | Avoids EV code signing; hooks catch common path; WFP catches syscall bypass | ✓ Shipped v0.9.0 |
| Print enforcement via XPS extraction, not port monitor DLL | User-mode only, sufficient for content inspection; port monitor deferred to v1.2 | ✓ Shipped v0.9.0 |
| Registry-based cloud sync path discovery + hardcoded fallbacks | Enterprise deployments redirect sync folders; dynamic discovery is mandatory | ✓ Shipped v0.9.0 |
| Classification resolved in interception layer, passed explicitly to CloudEnforcer | Auditability — enforcer's input is its own log line | ✓ Shipped v0.9.0 |
| Fail-open in cloud enforcer; fail-closed in hook DLL | Inverse threat models: hook is mandatory access path (deny on error), cloud enforcer is best-effort (allow on error) | ✓ Shipped v0.9.0 |
| Phase 38.2 enforcement: PnP CM_Disable_DevNode + Volume DACL deny-all | Two real-time OS-enforced layers; API hooking rejected; minifilter deferred | ✓ Shipped v0.8.1 |
| EncryptionStatus serde mapping manual: DB stores `fully_encrypted`/`partially_encrypted`; Rust enum serializes as `encrypted`/`suspended` | Hot-reload compatibility; migration cost too high | ✓ Shipped v0.7.0+ |
| Lock-order invariant: config mutex MUST be acquired and released BEFORE acquiring `instance_id_map.write()` | T-37-13 deadlock reproduced and root-caused | ✓ Documented v0.6.0+ |

## Known Constraints & Gotchas

### Critical Windows-rs API Gotchas

| Issue | Resolution |
|-------|------------|
| windows-rs 0.62 print APIs use `PRINTER_HANDLE` (not `HANDLE`); `GetJobW` returns `BOOL` | Verify against crate source, not Win32 docs |
| SetupDi description lookup matches wrong device (Bluetooth interface name vs SanDisk USB) | Precise device path matching required, not name substring |
| `CM_Disable_DevNode` requires actual CM instance ID, not VID/PID/serial | Resolve from device interface path via SetupDi APIs |
| `WM_DEVICECHANGE` timing: `DBT_DEVICEARRIVAL` for USB_DEVICE arrives *before* VOLUME event | 500ms deferred processing via tokio runtime bridge |
| Boot drive letter case mismatch (`C:` vs `c:`) | Case-insensitive comparison across codebase; normalize at edge |
| Box share link `box.com/s/` is a substring of `dropbox.com/s/` | Anchor Box pattern with `//` prefix to prevent false-positive |
| `HookInjector` is not `Clone` | Construct fresh instances per thread from DLL path |
| Named-pipe `write_all` bug: `slice_len = buf.len() - remaining` computes 0 on first iteration | Use `offset = buf.len() - remaining` and `slice_len = remaining.min(65536)` — matches `read_exact` pattern (MEM013) |
| Hook DLL fail-closed: if named-pipe client can't connect, request times out, or agent responds DENY → return `ERROR_ACCESS_DENIED` | Prevents silent enforcement bypass when agent unreachable (MEM017) |
| WFP filter registration requires admin privileges; may fail on non-Windows targets | `WfpManager` constructed conditionally; registration failures logged as warnings without blocking startup (MEM019) |
| Thread-local `TEST_EVALUATOR_OVERRIDE` for Chrome handler parallel test isolation | Eliminates parallel test races without restructuring evaluator (MEM007) |
| `FindFirstPrinterChangeNotification` returns a raw `HANDLE`, not `Result` — the `?` operator does not apply | Manual `INVALID_HANDLE_VALUE` / null check at the call site |
| quick-xml 0.36 changed signatures: pass `reader.decoder()` (not the reader) to `decode_and_unescape_value` | Older code paths break silently when bumping the crate |
| Clipboard listener uses `unsafe` in three places (Win32 hook proc, `GetMessageW` loop, raw-pointer string parsing) | Mitigated by SAFETY comments, dedicated thread, and a 1M-character sanity limit; risk accepted |

### Outstanding Debt (Carries Into v0.10.0+)

| Item | Severity | Status |
|------|----------|--------|
| Secrets encryption at rest in SQLite | **High** | ✓ Validated v0.10.0 Phase 47 (HARD-01) |
| Direct-syscall bypass of v0.9.0 cloud-sync IAT hook | **High** | v0.10.0 — ntdll syscall-stub patching closes this for all hooks |
| Audit-only file I/O (Explorer copy/move not blocked in real time) | **High** | v0.10.0 — universal hook DLL + DACL tripwire |
| AV/EDR may flag global DLL injection | Medium | v0.10.0 OPS- — deployment guide allowlist procedure |
| Alert router wired but never invoked (dead code path) | Medium | Backlog — mirror SIEM relay pattern in a future minor |
| Webhook HMAC signing for SIEM relay | Medium | Backlog |
| Password-protected service-stop E2E test | Medium | Backlog — needs Windows CI runner |
| Audit hash chain (tamper detection) | High | Backlog — standalone milestone, N-SEC-07 |
| `admin_api.rs` monolithic 217 KB file | Medium | Backlog — revisit when velocity blocked |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason.
2. Requirements validated? → Move to Validated with phase reference.
3. New requirements emerged? → Add to Active.
4. Decisions to log? → Add to Key Decisions.
5. "What This Is" still accurate? → Update if drifted.

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections.
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state.

---

## Workspace Layout

All historical context now lives in-tree under `.planning/`:

- `PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`, `config.json` — active planning surface
- `MILESTONES.md`, `RETROSPECTIVE.md` — top-level project history (v0.2.0–v0.8.1)
- `milestones/` — per-milestone audits (v0.6.0, v0.8.0, v0.8.1) and the v0.9.0 four-doc close-out
- `codebase/` — architecture / stack / structure / integrations / conventions / testing / concerns reference docs
- `incidents/` — post-mortem write-ups for non-obvious bugs (start: clipboard monitoring no-alerts RCA)
- `research/` — strategic notes feeding future milestones
- `deferred-ideas/` — captured ideas (SEED-001..004), some delivered, some pending

The earlier `.planning.legacy/` (phase-numbered GSD format) and `.gsd.legacy/` (milestone-slice-task format) workspaces were consolidated into this tree and removed; commit `0f46795` and the consolidation commit preserve full history.

---

*Last updated: 2026-05-12 — milestone pivot from v1.0.0 Enterprise Hardening to v0.10.0 Real-Time File Access Prevention.*
