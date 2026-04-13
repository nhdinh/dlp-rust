---
*Last updated: 2026-04-14 after Phase 09*
---

# PROJECT.md — DLP-RUST

## What This Is

Enterprise-grade Data Loss Prevention system that enforces ABAC-based access policies on Windows endpoints. Operates as a four-layer defense stack: Identity (AD), Access (NTFS ACLs), Policy (ABAC engine), Enforcement (Windows Service agent). Five-crate Rust workspace deployed as Windows services and CLI tools.

## Core Value

Real-time file/clipboard/USB interception with ABAC-based policy enforcement, centralized admin control, and SIEM/alert integration.

## Current State

**v0.2.0 Feature Completion shipped** (2026-04-13). All five crates compile and test. 364+ tests pass. The system covers: file/USB/network-share interception, clipboard monitoring, JWT auth, SIEM relay (Splunk HEC + ELK), alert routing (email + webhook), DB-backed operator config, agent config polling, and comprehensive TC test coverage.

**v0.3.0 — Operational Hardening in progress** (Phase 09 shipped — admin audit logging; remaining: AD LDAP, rate limiting, SQLite pool, policy engine separation).

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

### Active (planned for v0.3.0)

- [ ] R-03: Policy Engine Separation — architectural split into policy engine + evaluation replica
- [ ] R-05: Active Directory LDAP integration — real ABAC attribute resolution from AD
- [ ] R-07: Rate limiting middleware — brute-force protection, per-agent event limits
- [ ] R-10: SQLite connection pool — replace Mutex<Connection> with r2d2 pool

### Validated (v0.3.0)

- ✓ R-09: Admin operation audit logging — policy CRUD + password changes → audit_events with EventType::AdminAction — Phase 09

### Out of Scope

- Mobile app — Windows-first DLP product
- macOS/Linux agent — NTFS enforcement requires Windows
- Cloud-native policy engine — on-prem DLP with enterprise AD dependency
- File encryption at rest — NTFS ACLs provide access control

## Context

**v0.2.0 timeline:** 2026-04-10 to 2026-04-13 (~4 days)
**v0.2.0 phases shipped:** 9 (0.1, 1, 2, 3, 3.1, 4, 04.1, 6, 12)
**v0.2.0 plans shipped:** 14 plans across 9 phases
**Deferred to v0.3.0:** 5 requirements (R-03/05/07/09/10)
**Commits since 2026-04-10:** ~70 commits, 63 files changed, ~15K LOC

**Key decisions made during v0.2.0:**
- Operator config (SIEM, alerts, agent config) lives in SQLite, not env vars — hot-reload + TUI manageable
- `AppState { db, siem }` is the canonical axum state for dlp-server handlers
- Phase 04.1 (test suite) was inserted mid-sprint as urgent work — three-wave TDD approach (unit → server → E2E)
- Axum 0.7.9 `.route()` calls for the same path do NOT merge methods — consolidate all HTTP verbs into one `.route()` call

## Tech Stack

- **Runtime:** tokio async, Windows Service API
- **HTTP:** axum 0.7 (server), reqwest (client)
- **DB:** SQLite via rusqlite (single Mutex<Connection> — pool in v0.3.0)
- **TUI:** ratatui + crossterm
- **GUI:** iced (tiny-skia renderer)
- **Auth:** bcrypt + JWT (jsonwebtoken)
- **IPC:** Win32 named pipes (3-pipe architecture)
- **Logging:** tracing + tracing-subscriber + tracing-appender
- **Config:** TOML for agent config; SQLite for operator config

## Team

- Solo developer (nhdinh)
- AI-assisted development (Claude Code + GSD workflow)
