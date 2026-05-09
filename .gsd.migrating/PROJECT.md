# Project: dlp-rust

## What This Is

Enterprise Data Loss Prevention (DLP) system for Windows endpoints. The agent service runs as SYSTEM and intercepts sensitive data exfiltration through USB, disk, clipboard, drag-and-drop, browser origins, cloud sync, and print. A central policy server provides ABAC policy evaluation, audit storage, SIEM relay, and an admin TUI.

## Core Value

Sensitive data cannot leave the endpoint without policy evaluation and explicit authorization. The system is preventive first, detective second — blocking exfiltration at the point of attempt, not just logging it after the fact.

## Project Shape

- **Complexity:** complex
- **Why:** Multi-process Windows service architecture, kernel-adjacent interception (without kernel drivers), real-time ABAC evaluation, multiple exfiltration channels, enterprise policy authoring and distribution.

## Current State

v0.9.0 complete (M017). The system covers:
- **Clipboard monitoring** — classify and block paste based on content + destination origin; share-link detection for cloud provider URLs (OneDrive, GDrive, Dropbox, Box)
- **USB enforcement** — PnP disable + DACL deny for unregistered devices, with CM instance ID resolution
- **Disk exfiltration prevention** — mount-time blocking + I/O-time enforcement for unregistered fixed disks
- **Application-aware DLP** — UWP identity resolution, drag-and-drop interception, Chrome Content Analysis API
- **ABAC policy engine** — boolean mode (ALL/ANY/NONE), offline caching, AD group integration; Actions: WRITE, COPY, DRAG_DROP, PASTE, CLOUD_UPLOAD, SHARE_LINK, PRINT
- **Cloud sync interception** — IAT hook DLL (CreateFileW/NtCreateFile) injected into sync client processes; WFP TCP/443 defense-in-depth; registry-based sync path discovery for all four providers
- **Print spooler interception** — FindFirstPrinterChangeNotification + XPS ZIP text extraction + SetJob(JOB_CONTROL_DELETE) cancellation; ABAC-driven with metadata-only fallback for non-XPS jobs
- **Audit & SIEM** — structured JSONL audit logs, SMTP/webhook alerts, SIEM relay
- **Admin CLI** — ratatui-based TUI for policy management, device registry, agent config, cloud/print configuration

## Architecture / Key Patterns

- **Agent service:** Windows Service in session 0 (SYSTEM). Spawns UI processes into user sessions. IPC via named pipes.
- **Server:** Axum-based HTTP API with SQLite backend. AppState { db, siem } pattern.
- **Stateless ABAC:** Policies evaluate locally in the agent using a cached policy set. No server round-trip on every operation.
- **User-mode interception:** All blocking is user-mode — no kernel drivers, no minifilters. APIs: `DefineDosDeviceW`, `IOCTL_VOLUME_OFFLINE`, `SetWindowsHookEx`, DACL manipulation, IAT API hooking, WFP network filters, Win32 print spooler.
- **Enforcer pattern:** `new() / start() / stop() / update_enabled()` shape; `Option<T>` storage in RunLoopContext for safe shutdown. Classification passed explicitly to enforcer `check()` — interception layer owns resolution.
- **Hook DLL:** Fail-closed — any pipe error, timeout, or DENY returns ERROR_ACCESS_DENIED. Injected via CreateRemoteThread+LoadLibraryW with x86/x64 architecture detection.
- **Hot-reload config:** Agent config polled from server. SQLite for server-side persistence.
- **Audit-first:** Every intercepted operation emits an audit event. Failures in audit emission never block enforcement.

## Capability Contract

See `.gsd/REQUIREMENTS.md` for the explicit capability contract, requirement status, and coverage mapping.

## Milestone Sequence

- [x] **M017** — v0.9.0 Cloud & Print Exfiltration Prevention — API hooking for cloud sync clients, WFP network defense, print spooler interception, share-link detection, admin CLI cloud/print config screens
- [ ] **M018** — v0.10.0 Native Browser Extension (MV3) — Full browser-level upload and clipboard interception
- [ ] **M019** — v0.11.0 Operational Analytics & Management — Dashboards, agent health, policy analytics, RBAC
- [ ] **M020** — v0.12.0 Detective Controls & Anomaly Detection — Bulk download thresholds, AD working hours, user behavior baselines
