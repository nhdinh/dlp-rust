# System Architecture (Audit-Ready)

## Overview

Enterprise DLP system integrating:

- Active Directory (Identity)
- NTFS (Access Control)
- ABAC Engine (Policy Decision)
- Rust-based DLP Agents (Enforcement)

## High-Level Architecture

[User] → [AD] → [NTFS Check] → [ABAC Engine] → [DLP Agent Enforcement]

## Components

- AD Domain Controller
- File Servers (NTFS)
- Policy Engine (Rust, gRPC)
- **DLP Agent** (`dlp-agent/` crate) — Windows Service, SYSTEM account, file interception, Policy Engine gRPC, audit emission, IPC pipe servers, UI spawner
- **dlp-endpoint-ui** (`dlp-endpoint-ui/` crate) — Tauri subprocess spawned by the Agent on the interactive user desktop; handles toast notifications, override dialogs, clipboard, system tray, and sc stop password dialog
- **dlp-admin-portal** (`dlp-admin-portal/` crate) — Tauri-based administrative UI for `dlp-admin`; policy CRUD, dashboard, audit viewer — **deferred to a later phase** (audit logs read directly from JSON during Phase 1)
- Logging + SIEM

> **⚠️ Terminology:** Do not use `dlp-ui` or `DLP UI` alone. Always use `dlp-admin-portal` (admin) or `dlp-endpoint-ui` (endpoint). `dlp-admin` is the AD user account.

## Trust Boundaries

- Endpoint vs Server
- Internal vs External Network
