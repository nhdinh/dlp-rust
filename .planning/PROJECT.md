# PROJECT.md

## Project Identity

- **Name:** DLP-RUST
- **Type:** Enterprise Data Loss Prevention System
- **Language:** Rust
- **Platform:** Windows (NTFS + Active Directory + ABAC)

## Description

Enterprise-grade Data Loss Prevention system that enforces ABAC-based access policies on Windows endpoints. Operates as a four-layer defense stack: Identity (AD), Access (NTFS ACLs), Policy (ABAC engine), Enforcement (Windows Service agent).

## Architecture

Rust workspace with 5 crates:

| Crate | Role |
|-------|------|
| `dlp-common` | Shared types: ABAC, audit events, classification, text classifier |
| `dlp-server` | Central HTTP server: admin API, audit store, agent registry, SIEM relay |
| `dlp-agent` | Windows Service: file interception, policy enforcement, clipboard monitoring |
| `dlp-user-ui` | iced GUI: notifications, dialogs, clipboard monitor, system tray |
| `dlp-admin-cli` | Interactive ratatui TUI: password mgmt, policy CRUD, system status |

## Key Design Decisions

- Agent runs as SYSTEM in session 0; UI spawned into user sessions via CreateProcessAsUserW
- Password hashes managed centrally by dlp-server; agents sync on startup + on-demand
- File-based stop-password flow (no DPAPI cross-context; plaintext base64 in admin-only directory)
- Clipboard monitoring runs in UI process (user session has clipboard access; SYSTEM does not)
- Agent config via TOML file at C:\ProgramData\DLP\agent-config.toml

## Current State

Phases 1-5 complete. All crates implemented and tested. Recent work:
- Server-managed auth hash (centralized password management)
- Interactive ratatui TUI for dlp-admin-cli
- Service stop bug fixes (DPAPI, STOP_CONFIRMED race, runtime shutdown, USB hang)
- Clipboard monitoring wired end-to-end
- File-based agent logging (C:\ProgramData\DLP\logs\)

## Current Milestone

**v0.2.0 — Feature Completion**

Focus: Complete remaining features that are wired but not integrated:
- SIEM relay (Splunk HEC + ELK)
- Alert routing (email + webhook)
- Policy sync (multi-replica)
- Config push (agent config distribution)
- AD integration for real ABAC attribute resolution

## Tech Stack

- **Runtime:** tokio async, Windows Service API
- **HTTP:** axum (server), reqwest (client)
- **DB:** SQLite via rusqlite
- **TUI:** ratatui + crossterm
- **GUI:** iced (tiny-skia renderer)
- **Auth:** bcrypt + JWT (jsonwebtoken)
- **IPC:** Win32 named pipes (3-pipe architecture)
- **Logging:** tracing + tracing-subscriber + tracing-appender

## Team

- Solo developer (nhdinh)
- AI-assisted development (Claude)
