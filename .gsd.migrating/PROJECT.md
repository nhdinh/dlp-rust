# Project: dlp-rust

## What This Is

Enterprise Data Loss Prevention (DLP) system for Windows endpoints. The agent service runs as SYSTEM and intercepts sensitive data exfiltration through USB, disk, clipboard, drag-and-drop, browser origins, cloud sync, and print. A central policy server provides ABAC policy evaluation, audit storage, SIEM relay, and an admin TUI.

## Core Value

Sensitive data cannot leave the endpoint without policy evaluation and explicit authorization. The system is preventive first, detective second — blocking exfiltration at the point of attempt, not just logging it after the fact.

## Project Shape

- **Complexity:** complex
- **Why:** Multi-process Windows service architecture, kernel-adjacent interception (without kernel drivers), real-time ABAC evaluation, multiple exfiltration channels, enterprise policy authoring and distribution.

## Current State

v0.8.1 complete. The system covers:
- **Clipboard monitoring** — classify and block paste based on content + destination origin
- **USB enforcement** — PnP disable + DACL deny for unregistered devices, with CM instance ID resolution
- **Disk exfiltration prevention** — mount-time blocking + I/O-time enforcement for unregistered fixed disks
- **Application-aware DLP** — UWP identity resolution, drag-and-drop interception, Chrome Content Analysis API
- **ABAC policy engine** — boolean mode (ALL/ANY/NONE), offline caching, AD group integration
- **Audit & SIEM** — structured JSONL audit logs, SMTP/webhook alerts, SIEM relay
- **Admin CLI** — ratatui-based TUI for policy management, device registry, agent config

**In progress:** v0.9.0 (M017) — Cloud & Print Exfiltration Prevention

## Architecture / Key Patterns

- **Agent service:** Windows Service in session 0 (SYSTEM). Spawns UI processes into user sessions. IPC via named pipes.
- **Server:** Axum-based HTTP API with SQLite backend. AppState { db, siem } pattern.
- **Stateless ABAC:** Policies evaluate locally in the agent using a cached policy set. No server round-trip on every operation.
- **User-mode interception:** All blocking is user-mode — no kernel drivers, no minifilters. APIs: `DefineDosDeviceW`, `IOCTL_VOLUME_OFFLINE`, `SetWindowsHookEx`, DACL manipulation, API hooking (M017+).
- **Hot-reload config:** Agent config polled from server. SQLite for server-side persistence.
- **Audit-first:** Every intercepted operation emits an audit event. Failures in audit emission never block enforcement.

## Capability Contract

See `.gsd/REQUIREMENTS.md` for the explicit capability contract, requirement status, and coverage mapping.

## Milestone Sequence

- [ ] **M017** — v0.9.0 Cloud & Print Exfiltration Prevention — API hooking for cloud sync clients, WFP network defense, print spooler interception
- [ ] **M018** — v0.10.0 Native Browser Extension (MV3) — Full browser-level upload and clipboard interception
- [ ] **M019** — v0.11.0 Operational Analytics & Management — Dashboards, agent health, policy analytics, RBAC
- [ ] **M020** — v0.12.0 Detective Controls & Anomaly Detection — Bulk download thresholds, AD working hours, user behavior baselines
