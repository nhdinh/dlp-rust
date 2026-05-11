---
name: DLP-RUST
version: v1.0.0-planning
last_updated: 2026-05-11
status: between-milestones
shipped: v0.2.0, v0.3.0, v0.4.0, v0.5.0, v0.6.0, v0.7.0, v0.7.1, v0.8.0, v0.8.1, v0.9.0
next_milestone: v1.0.0
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

- 9 milestones shipped (v0.2.0 through v0.9.0)
- 46 phases executed
- ~8 months of development through 2026-05-11
- 700+ tests across the workspace, clippy-clean

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

### Active (v1.0.0 — Enterprise Hardening & Scale)

- [ ] **HARD-01** — Encrypt SQLite secrets at rest (PBKDF2 + machine key)
- [ ] **HARD-02** — Split monolithic `admin_api.rs` (217 KB) into per-domain modules
- [ ] **HARD-03** — Append-only audit hash chain (SHA-256) for tamper detection
- [ ] **HARD-04** — End-to-end test coverage for password-protected service stop
- [ ] **HARD-05** — Manual smoke test on real Windows host with real sync clients and print jobs
- [ ] **HARD-06** — Operational runbooks + deployment guides
- [ ] **HARD-07** — Performance baseline at scale (1000+ policies, 100+ agents)
- [ ] **HARD-08** — SonarQube quality gate clean + v1.0.0 release tag

### Out of Scope

- **Mobile app** — Windows-first product
- **macOS/Linux agent** — NTFS enforcement requires Windows
- **Cloud-native policy engine** — on-prem DLP with enterprise AD dependency
- **File encryption at rest** — NTFS ACLs + ABAC provide access control
- **Raw JSON policy editing** — replaced by Conditions Builder in v0.4.0
- **Kernel minifilter driver** — user-mode API hooking + WFP sufficient; no EV cert path
- **Native browser extension** — deferred to post-v1.0 milestone (v1.3)

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

### Outstanding Debt (Carries Into v1.0.0)

| Item | Severity | Phase |
|------|----------|-------|
| Alert router wired but never invoked (dead code path) | Medium | v1.0.0 — mirror SIEM relay pattern |
| Audit hash chain (tamper detection) | High | v1.0.0 HARD-03 (N-SEC-07) |
| Webhook HMAC signing for SIEM relay | Medium | v1.0.0 |
| Password-protected service-stop E2E test | Medium | v1.0.0 HARD-04 |
| Secrets encryption at rest in SQLite | **High** | v1.0.0 HARD-01 |
| `admin_api.rs` monolithic 217 KB file | High | v1.0.0 HARD-02 |

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

## Legacy Reference

Two prior planning workspaces are preserved:

- **`.planning.legacy/`** (git-tracked) — phase-numbered workspace covering v0.2.0–v0.8.1 (Phases 0.1–46). Contains: ROADMAP.md, MILESTONES.md, RETROSPECTIVE.md, three milestone audits (v0.6.0, v0.8.0, v0.8.1), per-phase directories, research, codebase docs.
- **`.gsd.legacy/`** (gitignored, local-only) — milestone+slice+task format used by the newer GSD tooling. Contains M008–M017 (M017 = v0.9.0) with full slice/task breakdown, `gsd.db` SQLite state, journal, runtime, safety evidence.

Consult these when investigating decisions, regression context, or implementation history. They are read-only artifacts; all new planning happens in `.planning/`.

---

*Last updated: 2026-05-11 after re-initialization from IDEA-DOC.md (consolidating .planning + .gsd + .gsd.migrating).*
