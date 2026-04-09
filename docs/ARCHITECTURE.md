# System Architecture (Audit-Ready)

**Document Version:** 1.0
**Date:** 2026-03-31
**Status:** Draft

> **Terminology Note:** Several names in this project are easily confused. Read this before making changes:
>
> - **`dlp-admin`** — the DLP solution superuser credential. Stored as a bcrypt hash in `HKLM\SOFTWARE\DLP\Agent\Credentials\DLPAuthHash`. NOT an AD account or Windows user account. NOT a crate name.
> - **`dlp-agent/`** — the Windows Service crate. Runs as SYSTEM account.
> - **`dlp-user-ui/`** — the iced endpoint UI subprocess, a **separate crate** in the Cargo workspace (`dlp-user-ui/`). One instance per active user session; dlp-agent spawns a new instance for each session that connects via `CreateProcessAsUser`.
> - **`dlp-server/`** — the central HTTP server crate (Phase 5); serves ABAC policy evaluation, policy CRUD, audit ingestion, SIEM relay, admin auth, and agent registry on port 9090.
>
> Do **not** use `dlp-ui` alone — it is ambiguous.

## Overview

Enterprise DLP system integrating:

- Active Directory (Identity)
- NTFS (Access Control)
- ABAC Engine (Policy Decision)
- Rust-based dlp-agents (Enforcement)

## High-Level Architecture

[User] → [AD] → [NTFS Check] → [ABAC Engine] → [dlp-agent Enforcement]

## Components

- AD Domain Controller
- File Servers (NTFS)
- **dlp-agent** (`dlp-agent/` crate) — Windows Service, SYSTEM account, file interception, dlp-server HTTPS client (evaluation + audit + heartbeat), IPC pipe servers, UI spawner; configurable via `C:\ProgramData\DLP\agent-config.toml` (monitored paths, exclusions)
- **dlp-user-ui** (`dlp-user-ui/` crate) — iced subprocess spawned by the Agent in each active user session; one UI instance per session; handles toast notifications, override dialogs, clipboard, system tray, and sc stop password dialog for that session's user (separate workspace crate)
- **dlp-server** (`dlp-server/` crate) — Central HTTP server: ABAC policy evaluator (`POST /evaluate`), policy CRUD REST API, audit store, SIEM relay, admin auth, agent registry — **introduced in Phase 5**
- Logging + SIEM

## Trust Boundaries

- Endpoint vs Server
- Internal vs External Network

> For full component detail, data flows, IPC protocol, and acceptance criteria, see `docs/SRS.md`.
