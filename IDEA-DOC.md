---
created: 2026-05-11
source: .planning/, .gsd/, .gsd.migrating/ synthesis
purpose: Seed /gsd-new-project re-initialization with authoritative consolidated context
---

# DLP-RUST: Consolidated Project Idea Document

## 1. Project Vision & Mission

**Name:** DLP-RUST (Enterprise Data Loss Prevention System)

**What This Is:** Enterprise-grade Data Loss Prevention system that enforces ABAC-based access policies on Windows endpoints. Operates as a four-layer defense stack: Identity (AD), Access (NTFS ACLs), Policy (ABAC engine), Enforcement (Windows Service agent). Five-crate Rust workspace deployed as Windows services and CLI tools.

**Core Value:** Real-time file/clipboard/USB/disk/cloud/print interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.

**Mission:** Prevent enterprise data exfiltration across all major channels (file copy, USB, clipboard, drag-and-drop, cloud sync, print) through zero-knowledge fine-grained policies, without requiring kernel drivers or EV code signing.

**Target Users:** Enterprise security teams, compliance officers, managed service providers protecting Windows endpoints.

**Status:** Shipped v0.2.0–v0.8.1 (8 milestones across 46 phases). v0.9.0 (Cloud & Print Exfiltration Prevention) completed and integrated. Ready for v1.0.0 planning.

---

## 2. Architecture & Tech Stack

### Runtime & Language
- **Primary:** Rust Edition 2021 (100% of codebase)
- **Runtime:** Tokio async (multi-threaded) for all async crates
- **Platform:** Windows 10/11 only (Win32 API dependencies)

### Five-Crate Architecture
| Crate | Role |
|-------|------|
| dlp-common | Shared types: ABAC engine, audit events, classification, AD client, disk/USB models |
| dlp-server | Central HTTP server: admin API, policy store, audit store, SIEM relay, alert router |
| dlp-agent | Windows Service: file/clipboard/USB/disk/cloud/print interception, policy enforcement, IPC |
| dlp-user-ui | GUI: notifications, dialogs, clipboard monitor, system tray |
| dlp-admin-cli | Interactive TUI: password mgmt, policy CRUD, system config screens |

### Key Dependencies
- **Core:** axum 0.8, rusqlite 0.32 + r2d2 0.8, ldap3 0.11, jsonwebtoken 9.x, windows 0.62
- **Enforcement:** notify 6.x, prost 0.13 (protobuf), wmi 0.14, Windows Service 0.8
- **UI:** ratatui 0.29, crossterm 0.28, iced 0.13, tray-icon 0.19, winrt-notification 1.0
- **Infrastructure:** tracing, chrono 0.4, serde, parking_lot 0.12, tower-governor 0.4, lettre 0.11

### Configuration
- **Agent config:** TOML at C:\ProgramData\DLP\agent-config.toml (polled from server)
- **Operator config:** SQLite (SIEM, alerts, policies, device registries) with hot-reload
- **Secrets:** Environment variables (JWT_SECRET, SMTP creds, LDAP creds)

---

## 3. Completed Milestones (Validated Capabilities)

### v0.2.0–v0.8.1 (8 milestones, Phases 0.1–46)
All shipped and validated. Key milestones:

- **v0.2.0:** SIEM relay + alert routing, agent config polling, JWT hardening, 364+ tests
- **v0.3.0:** AD LDAP integration, rate limiting, admin audit logging, SQLite pooling, PolicyStore
- **v0.4.0:** Conditions Builder, Policy CRUD without raw JSON, Import/Export
- **v0.5.0:** Boolean logic (ALL/ANY/NONE), in-place condition editing, expanded operators
- **v0.6.0:** Application-aware DLP (Authenticode + AUMID), Chrome Enterprise Connector, USB enumeration + trust tier
- **v0.7.0:** Disk enumeration + BitLocker verification, WM_DEVICECHANGE handling, disk allowlist, admin TUI
- **v0.7.1:** AGENT-UNKNOWN remediation, per-user device registry, wmi crate upgrade, operational hardening
- **v0.8.0:** UWP app identity (AUMID), drag-and-drop enforcement (WH_GETMESSAGE), browser origin-aware clipboard policies

### v0.9.0 — Cloud & Print Exfiltration Prevention (Completed 2026-05-09)
**Delivered R001 + 4 supporting requirements. All 5 slices (S01–S05) complete.**

**Cloud sync blocking:** User-mode IAT hook (CreateFileW/NtCreateFile patching in sync clients) + registry-based path discovery + WFP defense-in-depth (TCP/443 blocking for bypass protection).

**Print interception:** FindFirstPrinterChangeNotification + XPS content extraction (ZIP parsing Glyphs/@UnicodeString) + SetJob(JOB_CONTROL_DELETE) cancellation.

**API hook framework:** Hook DLL with CreateRemoteThread injection, named pipe classification protocol (bincode framing), fail-closed behavior (ERROR_ACCESS_DENIED on error).

**Cloud share link detection:** Clipboard URL pattern matching (all four providers with Box anchored to prevent Dropbox false-positive).

**Admin CLI screens:** CloudConfig + PrintConfig configuration screens in SystemMenu.

**Test coverage:** 172/172 comprehensive tests pass. 116/116 admin-cli tests pass.

---

## 4. Active Requirements & Next Milestone

### Current Status (2026-05-11)
- **All milestones shipped:** v0.2.0–v0.9.0 (9 total)
- **Active requirement:** R004 (WFP defense-in-depth validation) — validated by M017-S02, manual smoke test deferred to v1.0.0
- **Roadmap:** v1.0.0 planning to begin after M017 integration testing

---

## 5. Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| Agent SYSTEM session 0; UI in user sessions | SYSTEM cannot access user clipboard; UI handles clipboard |
| Clipboard in UI process, not agent | User session isolation required |
| Centralized server password management | Single source of truth; agent doesn't need HKLM write |
| Operator config in SQLite (not env vars) | Hot-reload without restart; TUI manageable; persistent |
| Agent config polled from server, persisted to TOML | Offline availability, operator control |
| PolicyStore in-memory cache + 5-min background refresh | Sync hot-path avoids DB round-trip; background refresh catches updates |
| User-mode IAT hook + WFP (not kernel minifilter) | No EV code signing; hooks catch common path; WFP catches syscall bypasses |
| Print XPS extraction (not port monitor DLL) | User-mode only, sufficient for content inspection |
| Registry-based cloud sync path discovery | Enterprise deployments redirect sync folders; dynamic + hardcoded fallbacks |
| Classification passed to CloudEnforcer (not resolved internally) | Interception layer owns resolution; enforcer only enforces (auditable) |
| Fail-open on ABAC errors in cloud path; fail-closed in hook DLL | Inverse policies: hook DLL deny-by-default; cloud enforcer allow-by-default on error |

---

## 6. Known Constraints & Gotchas

### Critical Gotchas
| Issue | Resolution |
|-------|-----------|
| Windows-rs 0.62 print APIs: PRINTER_HANDLE (not HANDLE), GetJobW returns BOOL | Verify against crate source, not Win32 docs |
| SetupDi description lookup matches wrong device (Bluetooth vs SanDisk) | Precise device path matching required |
| CM_Disable_DevNode needs actual CM instance ID (not VID/PID/serial) | Resolve from device interface path via SetupDi |
| WM_DEVICECHANGE timing: USB_DEVICE arrives before VOLUME | 500ms deferred processing via tokio runtime bridge |
| Boot drive letter case mismatch (C: vs c:) | Case-insensitive comparison across codebase |
| Box share link 'box.com/s/' is substring of 'dropbox.com/s/' | Anchor Box with '//' prefix |
| HookInjector is not Clone | Construct fresh instances in threads from DLL path |

### Deferred Work
| Issue | Status | Phase |
|-------|--------|-------|
| Alert router wired but dead code | Documented | Mirror SIEM pattern |
| Audit hash chain (tamper detection) | Documented | Phase 5 (N-SEC-07) |
| Webhook HMAC signing | Documented | Phase 4 execution |
| Password-protected service stop E2E test | Manual only | Integrate to CI |
| Secrets encryption at rest | Documented | Future key management phase |
| Admin API monolithic 217 KB file | Documented | Split per-domain modules |

---

## 7. Out of Scope

- Mobile app — Windows-first product
- macOS/Linux agent — NTFS enforcement requires Windows
- Cloud-native policy engine — on-prem DLP with enterprise AD dependency
- File encryption at rest — NTFS ACLs provide access control
- Raw JSON editing — replaced by Conditions Builder
- Kernel minifilter driver — user-mode API hooking + WFP sufficient
- Native browser extension — deferred to future milestone

---

## 8. Suggested Roadmap Seed

### v0.2.0–v0.9.0 (Completed: Archive as Validated)
All 46 phases complete, all requirements validated. Refer to milestone audits.

### v1.0.0 — Enterprise Hardening & Scale (Proposed)
- Encrypt secrets at rest in SQLite (PBKDF2 + machine key)
- Split admin_api.rs monolithic file into per-domain modules
- Implement append-only audit hash chain (SHA-256)
- E2E tests for password-protected service stop
- Manual smoke test on Windows host (real sync clients, real print jobs)
- Operational runbooks + deployment guides
- Performance testing at scale (1000+ policies, 100+ agents)
- v1.0.0 tag with clean SonarQube quality gate

### Post-v1.0 Aspirations
- v1.1: Multi-SIEM + multi-alert-destination support
- v1.2: Port monitor DLL for print robustness
- v1.3: Browser extension (native Chrome/Edge)
- v1.4: Cloud provider admin APIs for real-time share classification
- v2.0: Cross-platform (macOS agent)

---

## 9. Conflicts & Gaps

### REQUIREMENTS.md Drift
`.planning/REQUIREMENTS.md` (v0.8.1 state) does NOT mention v0.9.0 (M017). `.gsd/REQUIREMENTS.md` is authoritative for v0.9.0. Fresh init should use `.gsd/` files + M017-SUMMARY.md as ground truth.

### PROJECT.md Outdated
Both `.planning/PROJECT.md` and `.gsd/PROJECT.md` claim v0.8.0 (2026-05-07) as latest. Should update to reflect v0.9.0 completion (2026-05-09).

### DECISIONS.md Empty
`.gsd.migrating/DECISIONS.md` is template only. Fresh init should seed from Section 5 of this document + M017 key_decisions.

### M017 STATE.md Misleading
Says "1 active requirement not been mapped to a milestone" but R004 is validated by M017-S02. Should clarify: "R004 validated; manual smoke test deferred to v1.0.0."

---

## Summary

This document consolidates 9 shipped milestones, 46 phases, and 8 months of enterprise DLP development for `/gsd-new-project` fresh initialization. The system is feature-complete for cloud, print, USB, disk, clipboard, and drag-and-drop exfiltration prevention on Windows. All architectural decisions are documented. Known constraints, gotchas, and deferred work are explicitly cataloged. Ready for v1.0.0 hardening phase.

**Next step:** Run `/gsd-new-project` with this IDEA-DOC.md as context. Initialize `.planning/DECISIONS.md` with carved-out decisions. Prepare v1.0.0 planning phase.
