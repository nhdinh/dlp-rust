# DLP-RUST

## Enterprise Data Loss Prevention // NTFS + Active Directory + ABAC

## What It Does

DLP-RUST is an enterprise-grade Data Loss Prevention system built entirely in Rust.

It enforces ABAC-based access policies on Windows endpoints by operating as a four-layer defense stack:

1. **Identity Layer** — Active Directory provides authoritative user and device identity
2. **Access Layer** — NTFS ACLs provide the coarse-grained enforcement baseline
3. **Policy Layer** — An ABAC engine evaluates contextual access requests and renders decisions
4. **Enforcement Layer** — A Windows Service agent intercepts file operations and applies those decisions

The system classifies data across four tiers (T1 Public through T4 Restricted) and enforces the Critical Rule at all times:

```
NTFS ALLOW + ABAC DENY = DENY
```

Data exfiltration paths blocked include USB mass storage, SMB/FTP uploads, and clipboard operations against classified content. Every enforcement decision is emitted as a structured JSON audit event and relayed through a central management server to SIEM platforms.

---

## Components

| Crate               | Role                                                      | Phase        |
| ------------------- | --------------------------------------------------------- | ------------ |
| `dlp-server/`       | Central server: ABAC evaluator, audit store, agent registry, SIEM relay, admin API | 1+5 |
| `dlp-agent/`        | Windows Service: file interception, policy enforcement    | 1            |
| `dlp-user-ui/`      | iced subprocess: notifications, dialogs, clipboard, tray  | 1            |
| `dlp-admin-cli/`    | Admin CLI: password management, policy CRUD, server status | 1            |

The agent runs as a Windows Service under SYSTEM. User-facing interactions (notifications, clipboard, dialogs) are handled by a subprocess spawned on the interactive desktop. Stopping the service requires dlp-admin credentials.

---

## Threat Model

Least privilege. Default deny on T3/T4 resources. NTFS provides coarse-grained baseline; ABAC provides fine-grained veto. Critical rule holds: NTFS ALLOW + ABAC DENY = DENY.

---

## Documentation

```
docs/
  SRS.md                    Requirements specification (IEEE 830)
  ARCHITECTURE.md           System architecture
  SECURITY_ARCHITECTURE.md  Zero Trust, Least Privilege controls
  THREAT_MODEL.md           STRIDE threat analysis
  IMPLEMENTATION_GUIDE.md   Rust implementation guidance
  AUDIT_LOGGING.md         SIEM integration, event schemas
  ABAC_POLICIES.md         Sample ABAC policy rules
  ISO27001_MAPPING.md      ISO 27001:2022 control mappings
  CLAUDE.md                 Project instructions for AI assistants
```

---

## Status

Phase 1 through 5 are complete. All crates are implemented and tested.

| Phase | Focus                                                   | Crates                                                   |
| ----- | ------------------------------------------------------- | -------------------------------------------------------- |
| 1     | Foundation: shared types, ABAC evaluation, agent, UI    | `dlp-common`, `dlp-server`, `dlp-agent`, `dlp-user-ui`  |
| 2     | Process protection + IPC hardening                      | `dlp-agent`, `dlp-user-ui`                               |
| 3     | File interception + integration tests                   | `dlp-agent`                                              |
| 4     | Production hardening: MSI installer, security audit     | All                                                      |
| 5     | Central management: audit store, SIEM, admin API        | `dlp-server`, `dlp-admin-cli`                            |
