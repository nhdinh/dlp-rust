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

| Crate               | Role                                                   |
| ------------------- | ------------------------------------------------------ |
| `policy-engine/`    | ABAC policy evaluator, gRPC server                     |
| `dlp-server/`       | Audit ingestion, SIEM relay, admin auth, policy sync   |
| `dlp-agent/`        | Windows Service: file interception, policy enforcement |
| `dlp-admin-portal/` | Admin UI: policy management, audit viewer              |

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

Currently in the documentation and design phase. Implementation follows a 4-phase plan: Foundation (workspace, types, engine), Core Enforcement (agent, IPC, policy integration), UI & Integration (endpoint UI, admin portal, SIEM), Production Hardening (security audit, load testing, deployment). Phase 5 (dlp-server) follows.

No code committed yet.
