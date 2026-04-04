# Security Overview

**Document Version:** 1.0
**Date:** 2026-03-31
**Status:** Draft

> **See also:** Full detail in [SRS.md §6 (Security Requirements)](SRS.md#6-security-requirements) and [SRS.md §7 (Compliance Requirements)](SRS.md#7-compliance-requirements).

## Security Principles

- **Zero Trust** — assume breach; verify explicitly
- **Least Privilege** — minimum necessary access at all times
- **Defense in Depth** — layered controls; no single point of failure

## Controls

| Layer | Mechanism |
|-------|-----------|
| Identity | Active Directory (LDAPS), MFA (TOTP) |
| Access | NTFS ACLs (coarse), ABAC runtime decision (fine) |
| Enforcement | DLP agents (endpoint), SIEM alerting |
| Data at rest | NTFS permissions + BitLocker |
| Data in transit | TLS 1.3, mTLS between services |

## Threat Model (STRIDE)

| Threat | Risk | Mitigation |
|--------|------|------------|
| **Spoofing** | AD credential theft | MFA, conditional access, LDAPS |
| **Tampering** | File modification | NTFS ACLs, integrity monitoring, immutable audit |
| **Repudiation** | User denies action | Central append-only audit logging |
| **Information Disclosure** | Data exfiltration | ABAC + DLP enforcement, clipboard controls |
| **Denial of Service** | Service disruption | Rate limiting, offline cached mode |
| **Privilege Escalation** | Unauthorized elevation | Strict RBAC + ABAC, process DACLs |

> For full threat coverage including syscall bypass (F-AGT-18, future minifilter) and named pipe impersonation (N-SEC-12), see SRS.md §6.1.

## ISO 27001:2022 Control Mapping

| Control | Implementation |
|---------|---------------|
| A.5 Information Security Policies | DLP policy defined |
| A.6 Organization of Information Security | Roles: DLP Admin, Data Owner |
| A.8 Asset Management | Data classification (T1–T4) |
| A.9 Access Control | NTFS + ABAC |
| A.12 Operations Security | Logging, monitoring |
| A.16 Incident Management | DLP alerts + response |

> For the full ISO 27001 control table with specific requirements mapped to FRs and NFRs, see SRS.md §7.
