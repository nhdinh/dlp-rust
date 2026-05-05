# M002: Endpoint Hardening (v0.6.0)

**Gathered:** 2026-04-22
**Status:** Closed (shipped 2026-04-29)

## Project Description

Hardened endpoint agent with app identity capture, USB device control, Chrome Enterprise Connector integration, and automated UAT infrastructure.

## Why This Milestone

The agent needed to identify which application initiated file operations (for context-aware policies), control USB device access (for exfiltration prevention), and integrate with Chrome for browser-based DLP. Automated UAT was needed to validate complex hardware-dependent flows.

## User-Visible Outcome

### When this milestone is complete, the user can:

- See which application triggered a DLP event in audit logs
- Block/allow USB devices based on policy
- Enforce DLP policies on Chrome file downloads via Enterprise Connector
- Run automated UAT scripts for USB and device scenarios

### Entry point / environment

- Entry point: DLP Agent service + Chrome extension
- Environment: Windows endpoint
- Live dependencies involved: DLP server, Chrome browser, USB hardware

## Scope

### In Scope

- App identity capture (process to executable to publisher)
- USB device detection and control (WM_DEVICECHANGE)
- Chrome Enterprise Connector protocol
- Automated UAT infrastructure (PowerShell scripts)
- Device registry (server-side USB tracking)

### Out of Scope / Non-Goals

- Bluetooth device control
- Network share monitoring
- macOS/Linux endpoints
