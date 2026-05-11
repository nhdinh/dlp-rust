---
title: Logical Storage Interface Monitoring Strategy
date: 2026-05-06
context: DLP agent storage monitoring expansion beyond physical devices
---

# Logical Storage Interface Monitoring Strategy

## Background

The dlp-agent currently monitors physical storage devices (fixed disk, USB drives). This note captures the strategy for extending monitoring to logical storage interfaces that can serve as exfiltration paths.

## Identified Interfaces

1. **Network drives / mapped drives** — remote server connections, high-volume exfiltration risk
2. **Cloud storage sync folders** — OneDrive, Google Drive, Dropbox, etc.
3. **SD cards / card readers** — removable media via card slots
4. **Optical drives (CD/DVD/Blu-ray)** — physical media burning
5. **Virtual drives** — Daemon Tools, VM disk mounts, ISO images

## Phased Approach

| Phase | Interfaces | Rationale |
|-------|-----------|-----------|
| Phase 1 (now) | Network drives, Cloud sync folders | Highest volume, most common exfiltration paths |
| Phase 2 (later) | SD cards, Virtual drives | Medium risk, less common but still exploitable |
| Phase 3 (eventually) | Optical drives | Diminishing threat surface on modern endpoints |

## Policy Model

All interfaces are governed by the same ABAC-style policy framework already used for NTFS + AD:

- **User role / AD group membership** — who is attempting the action
- **Time of day / location** — contextual risk signals
- **Data classification tier** — what data is being touched (T1-T4)
- **Destination allowlist** — is the target sanctioned (e.g., `\\corp-fileserver`) or unknown

Example posture:
- Network drive to allowlisted corp file server + business hours + T2 data → ALLOW
- Network drive to unknown share + 2 AM + T4 data → DENY + alert

## Key Principle

Context-aware enforcement, not blanket allow/block. A network drive mapping is legitimate business use most of the time — the policy engine must distinguish based on the full context.
