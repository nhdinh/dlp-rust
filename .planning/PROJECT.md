---
*Last updated: 2026-05-03 — Phase 34 complete: BitLocker verification engine built and wired*
---

# PROJECT.md — DLP-RUST

## What This Is

Enterprise-grade Data Loss Prevention system that enforces ABAC-based access policies on Windows endpoints. Operates as a four-layer defense stack: Identity (AD), Access (NTFS ACLs), Policy (ABAC engine), Enforcement (Windows Service agent). Five-crate Rust workspace deployed as Windows services and CLI tools.

## Core Value

Real-time file/clipboard/USB interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.

## Current Milestone: v0.7.0 Disk Exfiltration Prevention

**Goal:** Prevent data exfiltration via unregistered fixed disks by establishing an install-time disk allowlist with encryption verification.

**Target features:**
- Install-time enumeration of fixed disks with BitLocker/encryption validation
- Persistent disk allowlist in agent-config.toml and server-side registry
- Runtime blocking of unregistered fixed disks (USB-bridged SATA/NVMe, internal drives added post-install)
- Admin override/registry for adding disks after initial install
- Audit events for disk block/discovery actions

## Shipped: v0.6.0 Endpoint Hardening (2026-04-29)

**Delivered:** All 9 phases complete — APP-01..06, BRW-01..03, USB-01..04 all validated. Phase 30 (Automated UAT Infrastructure) closed all deferred human UAT gaps.

- Phase 22: dlp-common Foundation — shared types (AppIdentity, DeviceIdentity, UsbTrustTier) gating all three tracks
- Phase 23-24: USB Enumeration + Device Registry DB — VID/PID/Serial capture, trust-tier CRUD admin API, agent cache polling
- Phase 25-26: App Identity Capture + ABAC Enforcement — source/dest process identity via WinVerifyTrust, Authenticode anti-spoofing, evaluator honors app-identity conditions
- Phase 27: USB Toast Notification — per-drive 30s cooldown, winrt-notification reuse
- Phase 28: Admin TUI Screens — Device Registry, Managed Origins, App Identity conditions builder
- Phase 29: Chrome Enterprise Connector — named-pipe server at `\\.\pipe\brcm_chrm_cas`, protobuf frame protocol, browser clipboard block
- Phase 30: Automated UAT Infrastructure — headless TUI tests, E2E agent TOML write-back, hot-reload verification, CI build gates

## Current State — all surfaced as first-class ABAC subject attributes.

## Current State

**v0.2.0 Feature Completion shipped** (2026-04-13). All five crates compile and test. 364+ tests pass. The system covers: file/USB/network-share interception, clipboard monitoring, JWT auth, SIEM relay (Splunk HEC + ELK), alert routing (email + webhook), DB-backed operator config, agent config polling, and comprehensive TC test coverage.

**v0.3.0 Operational Hardening shipped** (2026-04-16). Five phases delivered: AD LDAP integration (R-05), rate limiting middleware (R-07), admin audit logging (R-09), SQLite connection pool (R-10), and Policy Engine Separation with cache invalidation (R-03). All 10 requirements validated. Phase 99 (Repository + Unit of Work) completed concurrently.

**v0.4.0 Policy Authoring shipped** (2026-04-20). Five phases delivered — Conditions Builder (13), Policy Create (14), Policy Edit + Delete (15), Policy List + Simulate (16), and Import + Export (17). All 8 POLICY requirements validated. The admin TUI now covers the complete policy lifecycle without any raw JSON editing.

## Shipped: v0.5.0 Boolean Logic (2026-04-21)

**Delivered:** All 4 phases complete — POLICY-09, POLICY-10, POLICY-11, POLICY-12 all validated.

- Phase 18: Boolean Mode Engine + Wire Format — `mode` column, evaluator switch, backward-compat ALL default (POLICY-12)
- Phase 19: Boolean Mode in TUI + Import/Export — mode picker in Create/Edit forms, round-trip through export/import (POLICY-09)
- Phase 20: Operator Expansion — per-attribute operator sets (`gt`, `lt`, `ne`, `contains`) in evaluator and builder (POLICY-11)
- Phase 21: In-Place Condition Editing — `'e'` key pre-fills 3-step picker, replace-at-index on save (POLICY-10)

## Deferred (future milestones)

- **v0.7.0 Server Hardening:** batch import endpoint to reduce cache invalidations, typed `Decision` action field, TOML export unblock (POLICY-F4..F6)
- **Browser Extension (SEED-002 Path A):** Native Chrome/Edge Manifest V3 extension for tab-level origin control
- **UWP App Identity (APP-07):** AUMID resolution via `IShellItem` / `GetApplicationUserModelId`
- **USB Audit Fields (USB-05):** VID/PID/Serial/description in USB block audit events
- **Per-User Device Registry (USB-06):** owner_user column for multi-user machines

## Architecture

| Crate | Role |
|-------|------|
| `dlp-common` | Shared types: ABAC, audit events, classification, text classifier |
| `dlp-server` | Central HTTP server: admin API, audit store, agent registry, SIEM relay, alert router |
| `dlp-agent` | Windows Service: file interception, policy enforcement, clipboard monitoring |
| `dlp-user-ui` | iced GUI: notifications, dialogs, clipboard monitor, system tray |
| `dlp-admin-cli` | Interactive ratatui TUI: password mgmt, policy CRUD, system config screens |

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Agent runs as SYSTEM in session 0; UI spawned into user sessions | SYSTEM session 0 cannot access user clipboard; UI process handles it |
| Clipboard monitoring runs in UI process | SYSTEM session 0 cannot access user clipboard |
| Password hashes managed centrally by dlp-server | Server is single source of truth; CLI doesn't need HKLM write access |
| File-based stop-password (plaintext base64, not DPAPI) | DPAPI fails cross-context (user vs SYSTEM) |
| SIEM/alert/config operator config in SQLite, not env vars | Hot-reload without restart; TUI manageable; persistent |
| Agent config via TOML file at `C:\ProgramData\DLP\agent-config.toml` | Agents poll server and persist config to TOML |
| `classify_text` in dlp-common | Shared classifier avoids duplication between agent and UI |
| Admin audit events via `store_events_sync` inside `spawn_blocking` | Avoids async deadlock; `ingest_events` is async so cannot call from within `spawn_blocking` |

## Requirements

### Validated (shipped in v0.2.0)

- ✓ R-01: SIEM relay integration (Splunk HEC + ELK) — DB-backed config, hot-reload — v0.2.0
- ✓ R-02: Alert routing (email via SMTP + webhook) — DB-backed config, hot-reload — v0.2.0
- ✓ R-04: Agent config distribution via polling — DB-backed, per-agent overrides — v0.2.0
- ✓ R-06: Fix integration tests — 364/364 workspace tests pass — v0.2.0
- ✓ R-08: JWT_SECRET required in production — `--dev` flag for dev only — v0.2.0
- ✓ R-12: Comprehensive DLP test suite — 32 agent TCs + 15 server TCs + 6 E2E TCs — v0.2.0

### Validated (shipped in v0.3.0)

- ✓ R-03: Policy Engine Separation — PolicyStore + cache invalidation + background refresh — v0.3.0
- ✓ R-05: Active Directory LDAP integration — real ABAC attribute resolution from AD — v0.3.0
- ✓ R-07: Rate limiting middleware — brute-force protection, per-agent event limits — v0.3.0
- ✓ R-09: Admin operation audit logging — policy CRUD + password changes → audit_events with EventType::AdminAction — v0.3.0
- ✓ R-10: SQLite connection pool — r2d2 pool, 220 workspace tests pass — v0.3.0

### Validated (shipped in v0.4.0)

- ✓ POLICY-01: Admin can list all policies with name, priority, action, and enabled state — v0.4.0 (Phase 16)
- ✓ POLICY-02: Admin can create a new policy with name, description, priority, action, and one or more typed conditions — v0.4.0 (Phase 14)
- ✓ POLICY-03: Admin can edit an existing policy's name, description, priority, action, enabled flag, and conditions — v0.4.0 (Phase 15)
- ✓ POLICY-04: Admin can delete a policy with a confirmation prompt — v0.4.0 (Phase 15)
- ✓ POLICY-05: Admin can build policy conditions using a structured picker (attribute → operator → value) — no raw JSON — v0.4.0 (Phase 13)
- ✓ POLICY-06: Admin can simulate a policy decision by filling an EvaluateRequest form and viewing the decision + matched policy — v0.4.0 (Phase 16)
- ✓ POLICY-07: Admin can export the full policy set to a JSON file — v0.4.0 (Phase 17). TOML deferred as POLICY-F4.
- ✓ POLICY-08: Admin can import policies from a JSON file with conflict detection — v0.4.0 (Phase 17)

### Validated (shipped in v0.5.0)

- ✓ POLICY-09: Admin can choose a top-level boolean mode (ALL / ANY / NONE) per policy; evaluator honors the mode across the condition list — v0.5.0 (Phase 19)
- ✓ POLICY-10: Admin can edit an existing condition in-place in the conditions builder without deleting and recreating it — v0.5.0 (Phase 21)
- ✓ POLICY-11: Admin can pick expanded operators (`gt`, `lt`, `ne`, `contains`) where the attribute type permits; evaluator honors them — v0.5.0 (Phase 20)
- ✓ POLICY-12: Existing v0.4.0 policies default to `mode = ALL`; backward-compat migration via `ALTER TABLE` — v0.5.0 (Phase 18)

### Validated (shipped in v0.6.0)

- ✓ APP-01: DLP agent captures destination process image path and publisher at paste time — Phase 25
- ✓ APP-02: DLP agent captures source process identity via GetClipboardOwner at clipboard-change time — Phase 25
- ✓ APP-03: Evaluator enforces allow/deny based on source_application and destination_application ABAC attributes — Phase 26
- ✓ APP-04: Admin can author policies using app identity conditions (publisher, image path, trust tier) in TUI — Phase 28
- ✓ APP-05: Audit events include source_application and destination_application fields populated on clipboard block — Phase 25
- ✓ APP-06: Anti-spoofing: Authenticode signature verification for process identity (prevents renamed binary bypass) — Phase 25
- ✓ BRW-01: dlp-agent registers as Chrome Content Analysis agent via named pipe — Phase 29
- ✓ BRW-02: Admin can manage managed-origins list (trusted web domains) via TUI and admin API — Phase 28
- ✓ BRW-03: Paste from protected origin to unmanaged origin is blocked and audited — Phase 29
- ✓ USB-01: DLP agent captures VID/PID/Serial/description on USB device arrival via SetupDi API — Phase 23
- ✓ USB-02: Admin can register/deregister USB devices with trust tier via TUI and admin API — Phase 24
- ✓ USB-03: Agent enforces trust tier at I/O time (read_only: allow reads, deny writes; blocked: deny all) — Phase 26
- ✓ USB-04: User receives toast notification on USB block with policy explanation — Phase 27

### Deferred to future milestones

- [ ] USB-05: Audit events include device identity fields (VID, PID, serial, description) on USB block
- [ ] USB-06: Per-user device registry (owner_user column)
- [ ] APP-07: UWP app identity via AUMID

### Out of Scope

- Mobile app — Windows-first DLP product
- macOS/Linux agent — NTFS enforcement requires Windows
- Cloud-native policy engine — on-prem DLP with enterprise AD dependency
- File encryption at rest — NTFS ACLs provide access control
- Raw JSON conditions editing — replaced by structured conditions builder

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

## Context

**v0.3.0 timeline:** 2026-04-14 to 2026-04-16 (~3 days)
**v0.3.0 phases shipped:** 6 (7, 8, 9, 10, 11, 99)
**v0.3.0 plans shipped:** 11 plans across 5 phases + 3 plans for Phase 99
**Deferred to v0.3.0:** 5 requirements (R-03/05/07/09/10)
**Commits since 2026-04-10:** ~90 commits, 63 files changed, ~15K LOC

**Key decisions made during v0.3.0:**
- Operator config (SIEM, alerts, agent config) lives in SQLite, not env vars — hot-reload + TUI manageable
- `AppState { db, siem }` is the canonical axum state for dlp-server handlers
- Phase 04.1 (test suite) was inserted mid-sprint as urgent work — three-wave TDD approach (unit → server → E2E)
- Axum 0.7.9 `.route()` calls for the same path do NOT merge methods — consolidate all HTTP verbs into one `.route()` call

## Tech Stack

- **Runtime:** tokio async, Windows Service API
- **HTTP:** axum 0.8 (server), reqwest (client)
- **DB:** SQLite via rusqlite + r2d2 pool
- **TUI:** ratatui + crossterm
- **GUI:** iced (tiny-skia renderer)
- **Auth:** bcrypt + JWT (jsonwebtoken)
- **IPC:** Win32 named pipes (3-pipe architecture)
- **Logging:** tracing + tracing-subscriber + tracing-appender
- **Config:** TOML for agent config; SQLite for operator config

## Team

- Solo developer (nhdinh)
- AI-assisted development (Claude Code + GSD workflow)
