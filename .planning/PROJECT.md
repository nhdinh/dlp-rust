---
*Last updated: 2026-04-16 — Phase 13 complete*
---

# PROJECT.md — DLP-RUST

## What This Is

Enterprise-grade Data Loss Prevention system that enforces ABAC-based access policies on Windows endpoints. Operates as a four-layer defense stack: Identity (AD), Access (NTFS ACLs), Policy (ABAC engine), Enforcement (Windows Service agent). Five-crate Rust workspace deployed as Windows services and CLI tools.

## Core Value

Real-time file/clipboard/USB interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.

## Current Milestone: v0.4.0 Policy Authoring

**Goal:** Give admins a full TUI-based policy lifecycle — create, edit, simulate, and import/export — without touching raw SQLite.

**Target features:**
- TUI policy list, detail, create, and edit screens in dlp-admin-cli wired to existing /admin/policies CRUD API
- Structured conditions builder — pick attribute/operator/value, generates PolicyCondition JSON; no raw JSON entry
- Policy simulate / dry-run — fill EvaluateRequest form in TUI, call POST /evaluate, display decision + matched policy
- Policy import / export — serialize policy set to TOML/JSON file, import from file

## Current State

**v0.2.0 Feature Completion shipped** (2026-04-13). All five crates compile and test. 364+ tests pass. The system covers: file/USB/network-share interception, clipboard monitoring, JWT auth, SIEM relay (Splunk HEC + ELK), alert routing (email + webhook), DB-backed operator config, agent config polling, and comprehensive TC test coverage.

**v0.3.0 Operational Hardening shipped** (2026-04-16). Five phases delivered: AD LDAP integration (R-05), rate limiting middleware (R-07), admin audit logging (R-09), SQLite connection pool (R-10), and Policy Engine Separation with cache invalidation (R-03). All 10 requirements validated. Phase 99 (Repository + Unit of Work) completed concurrently.

**v0.4.0 Policy Authoring in progress** (started 2026-04-16). Defining requirements and roadmap.

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

### Active (v0.4.0)

- [ ] POLICY-01: Admin can list all policies with name, priority, action, and enabled state
- [ ] POLICY-02: Admin can create a new policy with name, description, priority, action, and one or more typed conditions
- [ ] POLICY-03: Admin can edit an existing policy's name, description, priority, action, enabled flag, and conditions
- [ ] POLICY-04: Admin can delete a policy with a confirmation prompt
- ✓ POLICY-05: Admin can build policy conditions using a structured picker (attribute → operator → value) — no raw JSON — Validated in Phase 13
- [ ] POLICY-06: Admin can simulate a policy decision by filling an EvaluateRequest form and viewing the decision + matched policy
- [ ] POLICY-07: Admin can export the full policy set to a TOML or JSON file
- [ ] POLICY-08: Admin can import policies from a TOML or JSON file, with conflict detection

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
