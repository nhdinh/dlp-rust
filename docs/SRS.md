# Software Requirements Specification

## Enterprise DLP System — NTFS + Active Directory + ABAC

**Document Version:** 1.1
**Date:** 2026-03-31
**Status:** Draft
**Author:** Principal Security Architect
**Changelog (v1.1):** Added Agent-as-Service architecture (§3.2, §3.3), IPC protocol (§3.4), updated crate structure (§5.2), new NFRs (§4.7), updated ACs (§9.6); fixed story point totals; added F-ADM-12; fixed ISO27001 x-ref; fixed DPAPI spec; fixed pipe name; added terminology note

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Overall Description](#2-overall-description)
3. [Functional Requirements](#3-functional-requirements)
4. [Non-Functional Requirements](#4-non-functional-requirements)
5. [System Architecture](#5-system-architecture)
6. [Security Requirements](#6-security-requirements)
7. [Compliance Requirements](#7-compliance-requirements)
8. [Implementation Plan](#8-implementation-plan)
9. [Acceptance Criteria](#9-acceptance-criteria)
10. [Glossary](#10-glossary)

---

## 1. Introduction

### 1.1 Purpose

This Software Requirements Specification (SRS) defines the complete requirements for an **Enterprise Data Loss Prevention (DLP) System** that integrates Windows NTFS access controls, Active Directory identity management, and Attribute-Based Access Control (ABAC) policy enforcement to prevent unauthorized data exfiltration across endpoints, email, and cloud services.

### 1.2 Scope

The system shall:

- Enforce DLP policies on Windows endpoints using a Rust-based agent running as a Windows Service
- Provide a centralized ABAC Policy Engine with a gRPC interface
- Classify data using a four-tier model (T1–T4)
- Integrate with Active Directory for identity and group membership
- Use NTFS ACLs as the baseline (coarse-grained) access control layer
- Apply ABAC decisions as the fine-grained dynamic enforcement layer
- Emit structured JSON audit logs to SIEM platforms (Splunk / ELK)
- Provide a Tauri-based endpoint UI (spawned by the Agent) for all user-facing interactions
- Provide a separate Administrative UI (dlp-ui) for the DLP Admin

**Out of Scope:**

- Native macOS/Linux endpoint agents (future consideration)
- Email gateway integration (Phase 2)
- Cloud DLP integration for SaaS (Phase 2)

### 1.3 Definitions

| Term                | Definition                                                                                                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **DLP**             | Data Loss Prevention — controls to detect and prevent data exfiltration                                                                                                  |
| **NTFS**            | New Technology File System — Windows file system with ACL support                                                                                                        |
| **ABAC**            | Attribute-Based Access Control — policy model using subject/resource/environment attributes                                                                              |
| **AD**              | Active Directory — Microsoft identity and access management service                                                                                                      |
| **dlp-admin**       | Designated superuser with full policy and system control                                                                                                                 |
| **Classification**  | Data sensitivity tier assignment (T1–T4)                                                                                                                                 |
| **T4 Restricted**   | Highest sensitivity — catastrophic impact if disclosed                                                                                                                   |
| **T3 Confidential** | High sensitivity — serious impact if disclosed                                                                                                                           |
| **T2 Internal**     | Moderate sensitivity — internal use only                                                                                                                                 |
| **T1 Public**       | Low sensitivity — no harm if disclosed                                                                                                                                   |
| **Policy Engine**   | ABAC decision service, evaluates access requests                                                                                                                         |
| **DLP Agent**       | Endpoint enforcement component, runs as Windows Service under SYSTEM account, does not interact with OS users directly                                                   |
| **DLP UI**          | Endpoint interaction component, Tauri subprocess spawned by the Agent on the interactive desktop; handles all user-facing work (notifications, dialogs, clipboard, tray) |
| **IPC**             | Inter-Process Communication — Agent ↔ UI communication via Windows named pipes                                                                                           |
| **Named Pipe**      | Windows kernel object for bidirectional message-mode IPC between processes                                                                                               |
| **SCM**             | Service Control Manager — Windows component that manages Windows Services                                                                                                |
| **SIEM**            | Security Information and Event Management                                                                                                                                |
| **gRPC**            | Remote Procedure Call framework used for Policy Engine communication                                                                                                     |
| **dlp-server**      | Central management HTTP server — owns agent registry, audit ingestion & SIEM relay, admin auth (TOTP + JWT), policy sync to engine replicas, alert routing, exception records |


> **⚠️ Terminology Note:** Throughout this document and the project, the following terms have specific, unambiguous meanings:
>
> - **`dlp-admin`** — the user account (privileged, superuser) used for policy management and secure service stop and his encrypted password is stored securely by dlp-server. Never use this token to name a crate or directory.
> - **`dlp-admin-portal`** — the Tauri-based administrative UI crate (`dlp-admin-portal/` in code), used exclusively by `dlp-admin` for policy CRUD, dashboard, and audit log access. In earlier versions this was called `dlp-ui`.
> - **`dlp-endpoint-ui`** — the Tauri subprocess spawned by the DLP Agent into the interactive user desktop (`dlp-agent/src-tauri/` in code), used for toast notifications, override dialogs, clipboard, and system tray. In earlier versions this was called `DLP UI` or `dlp-ui`.

### 1.4 References

| Reference      | Document                        |
| -------------- | ------------------------------- |
| [ARCHITECTURE] | `docs/ARCHITECTURE.md`          |
| [SECURITY]     | `docs/SECURITY_ARCHITECTURE.md` |
| [THREAT]       | `docs/THREAT_MODEL.md`          |
| [IMPL]         | `docs/IMPLEMENTATION_GUIDE.md`  |
| [AUDIT]        | `docs/AUDIT_LOGGING.md`         |
| [ABAC]         | `docs/ABAC_POLICIES.md`         |
| [ISO27K]       | `docs/ISO27001_MAPPING.md`      |

---

## 2. Overall Description

### 2.1 System Overview

The Enterprise DLP System is a four-layer defense-in-depth architecture. The Enforcement Layer splits into two co-operating processes: the **DLP Agent** (Windows Service, SYSTEM account) and the **DLP UI** (Tauri subprocess, interactive user desktop).

```
┌─────────────────────────────────────────────────────┐
│         Enforcement Layer — DLP Agent (Service)     │
│         Rust, SYSTEM account, Windows API            │
│         Handles: interception, gRPC, audit, IPC      │
├─────────────────────────────────────────────────────┤
│         Enforcement Layer — DLP UI (Tauri)           │
│         User desktop, spawned by Agent               │
│         Handles: notifications, dialogs, clipboard   │
├─────────────────────────────────────────────────────┤
│              Policy Layer (ABAC Engine)              │
│         Rust, gRPC, Policy Evaluation               │
├─────────────────────────────────────────────────────┤
│              Access Layer (NTFS ACLs)               │
│         Coarse-grained baseline enforcement         │
├─────────────────────────────────────────────────────┤
│              Identity Layer (Active Directory)       │
│         Source of truth for users, groups, devices  │
└─────────────────────────────────────────────────────┘
```

**Critical Enforcement Rule:**

> NTFS ALLOW + ABAC DENY = **DENY** (ABAC always has final veto)

### 2.2 Agent ↔ UI Co-Process Model

The DLP Agent runs as a Windows Service under the SYSTEM account. Because a SERVICE process cannot interact with the interactive desktop user session, all user-facing work is delegated to the **DLP UI** (a Tauri subprocess) that the Agent spawns on the interactive desktop:

| Concern                                 | Owner  |
| --------------------------------------- | ------ |
| File operation interception             | Agent  |
| Policy Engine gRPC communication        | Agent  |
| Audit event emission                    | Agent  |
| Windows Service lifecycle               | Agent  |
| User notifications (toast)              | DLP UI |
| Override request dialog + justification | DLP UI |
| Clipboard read/write                    | DLP UI |
| System tray widget                      | DLP UI |
| sc stop password dialog                 | DLP UI |
| Shell integration (tooltips)            | DLP UI |
| Audit event storage & SIEM relay     | dlp-server |
| Agent registry & heartbeat tracking    | dlp-server |
| Admin auth (TOTP + JWT)             | dlp-server |
| Policy sync to engine replicas        | dlp-server |
| Alert routing (DENY_WITH_ALERT)       | dlp-server |
| Exception/override approval records   | dlp-server |

Communication between Agent and DLP UI uses **3 Windows named pipes**.

### 2.3 Stakeholders

| Stakeholder             | Role                    | Needs                                                                        |
| ----------------------- | ----------------------- | ---------------------------------------------------------------------------- |
| **DLP Admin**           | Superuser (`dlp-admin`) | Full policy CRUD, system monitoring, incident response, secure service stop  |
| **Corporate End User**  | Windows AD user         | Normal file access, visibility into policy blocks, override request workflow |
| **Security Operations** | SOC / IR team           | Incident investigation, audit reports, compliance evidence                   |
| **Data Owner**          | Business unit owner     | Asset classification authority, policy review                                |
| **IT Operations**       | Infrastructure team     | Agent deployment, engine scaling, SIEM integration                           |
| **Auditor**             | Compliance reviewer     | Evidence of controls, ISO 27001 audit trail                                  |

### 2.4 Assumptions and Dependencies

1. Target environment is Windows Server 2019+ / Windows 10/11 Enterprise
2. All endpoints are joined to Active Directory Domain
3. DLP Admin account is a dedicated, privileged AD account
4. Policy Engine server runs on a hardened Windows or Linux host
5. SIEM infrastructure (Splunk or ELK) is available for log ingestion
6. Network communication between agents and Policy Engine uses TLS 1.3
7. All users have individual AD accounts; no shared accounts
8. Data classification is applied at the file/folder level via extended attributes or EDR metadata
9. The Agent runs as a Windows Service (SYSTEM account); it spawns the DLP UI into each active interactive session
10. Named pipe names are fixed well-known values (auditable and debuggable)

---

## 3. Functional Requirements

### 3.1 DLP Admin Features

| ID       | Requirement                                                                                                 | Priority |
| -------- | ----------------------------------------------------------------------------------------------------------- | -------- |
| F-ADM-01 | Admin shall create, read, update, and delete ABAC policies via the administrative UI                        | Must     |
| F-ADM-02 | Admin shall assign data classification (T1–T4) to files and folders                                         | Must     |
| F-ADM-03 | Admin shall view real-time system health (Policy Engine uptime, agent connectivity, policy hit rates)       | Must     |
| F-ADM-04 | Admin shall configure alert thresholds and notification recipients                                          | Must     |
| F-ADM-05 | Admin shall view and export audit logs filtered by date range, user, resource, and event type               | Must     |
| F-ADM-06 | Admin shall define exclusion paths (e.g., IT scan folders) that bypass DLP enforcement                      | Should   |
| F-ADM-07 | Admin shall manage endpoint agent configurations (push updates, version control)                            | Should   |
| F-ADM-08 | Admin shall receive real-time alerts for T3/T4 policy violations                                            | Must     |
| F-ADM-09 | Admin shall trigger on-demand file scans for classification review                                          | May      |
| F-ADM-10 | Admin shall review and approve or deny exception requests submitted by end users                             | Should   |
| F-ADM-11 | Admin shall stop the DLP Agent via `sc stop dlp-agent` after entering the dlp-admin password in a UI dialog | Must     |

### 3.2 Endpoint Agent (Windows Service)

| ID       | Requirement                                                                                        | Priority |
| -------- | -------------------------------------------------------------------------------------------------- | -------- |
| F-AGT-01 | Agent shall run as a Windows Service under the SYSTEM account                                      | Must     |
| F-AGT-02 | Agent shall start automatically at Windows boot via Service Control Manager                        | Must     |
| F-AGT-03 | Agent shall be a single-instance service; a second start attempt shall be rejected                 | Must     |
| F-AGT-04 | Agent shall register with Policy Engine on startup and maintain heartbeat                          | Must     |
| F-AGT-05 | Agent shall intercept file open/save/copy operations on monitored paths                            | Must     |
| F-AGT-06 | Agent shall request ABAC decision from Policy Engine before allowing sensitive file operations     | Must     |
| F-AGT-07 | Agent shall enforce ABAC DENY decisions by blocking the operation and logging the event            | Must     |
| F-AGT-08 | Agent shall enforce ABAC ALLOW decisions by permitting the operation (subject to NTFS)             | Must     |
| F-AGT-09 | Agent shall emit structured JSON audit events for every intercepted operation                      | Must     |
| F-AGT-10 | Agent shall apply local caching of policy decisions to minimize latency (TTL configurable)         | Should   |
| F-AGT-11 | Agent shall operate in offline mode with cached policy decisions when Policy Engine is unreachable | Must     |
| F-AGT-12 | Agent shall support configurable monitored paths (registry / config file)                          | Must     |
| F-AGT-13 | Agent shall detect and block USB mass storage copy of classified files                             | Must     |
| F-AGT-14 | Agent shall detect and block SMB/FTP upload of classified files to unauthorized destinations       | Must     |
| F-AGT-15 | Agent shall self-update from a configured update server endpoint                                   | May      |
| F-AGT-16 | Agent shall support supervised (managed) and unsupervised (unmanaged) device detection             | Must     |

### 3.3 Agent ↔ UI Co-Process Architecture

| ID       | Requirement                                                                                                                                               | Priority |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| F-SVC-01 | Agent shall spawn the Tauri DLP UI as a child subprocess on the interactive desktop when the service starts                                               | Must     |
| F-SVC-02 | Agent shall own the lifecycle of the UI subprocess (start, monitor, respawn on failure)                                                                   | Must     |
| F-SVC-03 | Agent shall communicate with the UI via exactly 3 Windows named pipes (see §3.4 for protocol)                                                             | Must     |
| F-SVC-04 | Agent shall check UI health every 5 seconds; if the UI is unresponsive or absent for 15 seconds, Agent shall terminate and respawn it                     | Must     |
| F-SVC-05 | Agent shall send blocking requests (BLOCK_NOTIFY, OVERRIDE_REQUEST) over the 2-way command pipe and wait for a response (timeout 60s, default DENY)       | Must     |
| F-SVC-06 | Agent shall send fire-and-forget events (TOAST, STATUS_UPDATE, HEALTH_PING) to the UI over Pipe 2                                                         | Must     |
| F-SVC-07 | UI shall send fire-and-forget acknowledgements (HEALTH_PONG, UI_READY, UI_CLOSING) to the Agent over Pipe 3                                               | Must     |
| F-SVC-08 | UI shall check Agent health every 5 seconds; if the Agent disappears or IPC connection is lost for 15 seconds, UI shall terminate itself within 5 seconds | Must     |
| F-SVC-09 | Both Agent and UI shall be protected from termination by non-dlp-admin users and administrators via Windows DACL                                          | Must     |
| F-SVC-10 | When `sc stop dlp-agent` is issued, the service shall not stop immediately; it shall signal the UI to display a dlp-admin password dialog                 | Must     |
| F-SVC-11 | On correct dlp-admin password verification, the service shall complete shutdown cleanly within 30 seconds                                                 | Must     |
| F-SVC-12 | On 3 consecutive incorrect password attempts, the service shall cancel the stop, log the event, and return to RUNNING state                               | Must     |
| F-SVC-13 | Agent shall enumerate the active console session via `WTSGetActiveConsoleSessionId` and spawn the UI in that session's desktop via `CreateProcessAsUser`  | Must     |
| F-SVC-14 | Password verification for service stop shall be performed by binding to AD as the dlp-admin user DN (LDAPS)                                               | Must     |

### 3.4 DLP UI (Tauri Endpoint Interface)

| ID       | Requirement                                                                                                                 | Priority |
| -------- | --------------------------------------------------------------------------------------------------------------------------- | -------- |
| F-INT-01 | UI shall display a Windows toast notification when Agent blocks a file operation                                            | Must     |
| F-INT-02 | UI shall display a blocking dialog when a user requests a policy override, requesting business justification text input     | Must     |
| F-INT-03 | UI shall send the user's override request and justification to the Agent via Pipe 1 (2-way command pipe)                    | Must     |
| F-INT-04 | UI shall read from the Windows clipboard when the Agent requests clipboard data for content inspection (via Pipe 1 command) | Must     |
| F-INT-05 | UI shall display the DLP Admin portal (policy management, audit viewer) when the system tray icon is double-clicked         | Must     |
| F-INT-06 | UI shall display a system tray icon showing real-time agent connection status                                               | Should   |
| F-INT-07 | UI shall display a dlp-admin password dialog when the Agent signals a pending service stop                                  | Must     |
| F-INT-08 | UI shall send clipboard text content back to the Agent over Pipe 1 response                                                 | Must     |
| F-INT-09 | UI shall write classification label tooltips into Windows Explorer shell integration                                        | Should   |

### 3.5 IPC Message Protocol

All IPC messages are UTF-8 JSON over Windows named pipes. Named pipes use `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE` mode.

#### Pipe Names (Fixed Well-Known)

| Pipe   | Name                        | Direction       | Mode                         |
| ------ | --------------------------- | --------------- | ---------------------------- |
| Pipe 1 | `\\.\pipe\DLPCommand`       | 2-way, duplex   | Synchronous request/response |
| Pipe 2 | `\\.\pipe\DLPEventAgent2UI` | 1-way, Agent→UI | Fire-and-forget              |
| Pipe 3 | `\\.\pipe\DLPEventUI2Agent` | 1-way, UI→Agent | Fire-and-forget              |

#### Pipe 1 — `\\.\pipe\DLPCommand` (Request / Response)

**Agent → UI (blocking):**

```json
{ "type": "BLOCK_NOTIFY",    "id": "uuid-v4", "file": "C:\\path\\file.xlsx", "reason": "T3 file copy to USB blocked", "classification": "T3", "timestamp": "2026-03-31T10:00:00Z" }
{ "type": "OVERRIDE_REQUEST", "id": "uuid-v4", "file": "C:\\path\\file.xlsx", "policy_id": "pol-003", "policy_name": "T3 USB Block", "classification": "T3", "timestamp": "2026-03-31T10:00:05Z" }
{ "type": "CLIPBOARD_READ",   "id": "uuid-v4", "timestamp": "2026-03-31T10:00:10Z" }
```

**UI → Agent (response):**

```json
{ "type": "USER_CONFIRMED",  "id": "uuid-v4", "justification": "Approved by manager via email" }
{ "type": "USER_CANCELLED",  "id": "uuid-v4" }
{ "type": "CLIPBOARD_DATA",  "id": "uuid-v4", "content": "Sensitive text from clipboard..." }
{ "type": "PASSWORD_SUBMIT",  "id": "uuid-v4", "password": "••••••••" }
{ "type": "PASSWORD_CANCEL", "id": "uuid-v4" }
```

#### Pipe 2 — `\\.\pipe\DLPEventAgent2UI` (Fire-and-forget, Agent→UI)

```json
{ "type": "TOAST",           "title": "DLP Blocked",           "body": "C:\\path\\file.xlsx copy to USB was blocked" }
{ "type": "STATUS_UPDATE",   "agent_version": "1.0.0",         "engine_connected": true, "cached_decisions": 3421 }
{ "type": "HEALTH_PING",     "timestamp": "2026-03-31T10:00:15Z" }
{ "type": "UI_RESPAWN",      "reason": "UI was unresponsive" }
```

#### Pipe 3 — `\\.\pipe\DLPEventUI2Agent` (Fire-and-forget, UI→Agent)

```json
{ "type": "HEALTH_PONG",     "timestamp": "2026-03-31T10:00:20Z" }
{ "type": "UI_READY",        "ui_version": "1.0.0" }
{ "type": "UI_CLOSING",     "reason": "user_logoff" }
```

### 3.6 Policy Engine Features

| ID       | Requirement                                                                                                                                           | Priority |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| F-ENG-01 | Engine shall evaluate ABAC policy rules in the format `IF <conditions> THEN <action>`                                                                 | Must     |
| F-ENG-02 | Engine shall support conditions based on: user identity, group membership, device trust level, resource classification, time of day, network location | Must     |
| F-ENG-03 | Engine shall support actions: ALLOW, DENY, ALLOW_WITH_LOG, DENY_WITH_ALERT                                                                            | Must     |
| F-ENG-04 | Engine shall provide a gRPC interface for policy evaluation requests                                                                                  | Must     |
| F-ENG-05 | Engine shall support REST API for policy CRUD operations (admin-facing)                                                                               | Must     |
| F-ENG-06 | Engine shall load and hot-reload policies from a JSON/YAML policy store without restart                                                               | Should   |
| F-ENG-07 | Engine shall return decisions within 50ms at P95 under normal load                                                                                    | Must     |
| F-ENG-08 | Engine shall enforce the priority order of policies (first-match wins)                                                                                | Must     |
| F-ENG-09 | Engine shall support policy versioning with rollback capability                                                                                       | Should   |
| F-ENG-10 | Engine shall validate policy syntax at load time and reject malformed policies                                                                        | Must     |
| F-ENG-11 | Engine shall query AD for group membership and device trust attributes                                                                                | Must     |
| F-ENG-12 | Engine shall apply the Critical Rule: if NTFS allows and ABAC denies, the final result is DENY                                                        | Must     |

### 3.7 Audit & Logging Features

| ID       | Requirement                                                                                                                                                          | Priority |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| F-AUD-01 | All audit events shall be emitted in structured JSON format                                                                                                          | Must     |
| F-AUD-02 | Audit event schema shall include: timestamp, event_type, user_sid, user_name, resource_path, classification, action_taken, decision, policy_id, agent_id, session_id | Must     |
| F-AUD-03 | Audit events shall be sent to dlp-server over HTTPS (dlp-server relays to SIEM)                                                                                      | Must     |
| F-AUD-04 | dlp-server shall buffer audit events locally when SIEM is unreachable and drain when connectivity is restored                                                 | Must     |
| F-AUD-05 | Logs shall not contain file content (payload) — only metadata                                                                                                        | Must     |
| F-AUD-06 | Audit log integrity shall be protected by append-only file storage or equivalent                                                                                     | Must     |
| F-AUD-07 | DLP Admin shall be able to query and export audit events from the administrative UI                                                                                  | Must     |
| F-AUD-08 | Policy violation events (DENY_WITH_ALERT) shall trigger immediate alert to configured recipients via dlp-server                                          | Must     |
| F-AUD-09 | dlp-server shall emit an audit event for every administrative action performed via dlp-admin-portal (identity, action, timestamp, resource)                 | Must     |

### 3.8 dlp-server Features

| ID | Requirement | Priority |
|----|-------------|----------|
| F-SRV-01 | dlp-server shall receive audit events from all dlp-agents over HTTPS | Must |
| F-SRV-02 | dlp-server shall write audit events to append-only storage | Must |
| F-SRV-03 | dlp-server shall forward audit events to SIEM (Splunk HEC / ELK HTTP Ingest) in batches (max 1s latency, max 1000 events/batch) | Must |
| F-SRV-04 | dlp-server shall maintain an agent registry: agent_id, hostname, IP, OS version, agent version, last_heartbeat, status | Must |
| F-SRV-05 | dlp-server shall receive agent heartbeats over HTTPS and mark agents offline after 90 seconds of no heartbeat | Must |
| F-SRV-06 | dlp-server shall expose a REST API for the dlp-admin-portal: GET /agents, GET /audit-events, policy CRUD, exception approval | Must |
| F-SRV-07 | dlp-server shall act as the TOTP validation and JWT issuance server for dlp-admin-portal sessions | Must |
| F-SRV-08 | dlp-server shall store exception/override approval records (approver, timestamp, duration, justification) | Should |
| F-SRV-09 | dlp-server shall sync policies to all policy-engine replicas on policy create/update | Must |
| F-SRV-10 | dlp-server shall push agent configuration changes to selected dlp-agents | Should |
| F-SRV-11 | dlp-server shall buffer audit events locally when SIEM is unreachable and drain when connectivity is restored | Must |

---

## 4. Non-Functional Requirements

### 4.1 Security

| ID       | Requirement                                                                                                                                                                                                            | Target |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| N-SEC-01 | All network communication shall use TLS 1.3                                                                                                                                                                            | Must   |
| N-SEC-02 | Credentials shall never be stored in plaintext; use Windows Credential Manager or HSM                                                                                                                                  | Must   |
| N-SEC-03 | Agent shall run as a Windows Service under the SYSTEM account; UI runs in the interactive user session as the logged-in user                                                                                           | Must   |
| N-SEC-04 | Policy Engine shall be deployed on an isolated, hardened host                                                                                                                                                          | Must   |
| N-SEC-05 | gRPC API shall authenticate agents via mutual TLS (mTLS)                                                                                                                                                               | Must   |
| N-SEC-06 | DLP Admin shall use MFA for all administrative sessions                                                                                                                                                                | Must   |
| N-SEC-07 | Audit logs shall be immutable once written                                                                                                                                                                             | Must   |
| N-SEC-08 | Agent shall verify Policy Engine certificate before establishing connection                                                                                                                                            | Must   |
| N-SEC-09 | Sensitive data in memory shall be zeroized after use                                                                                                                                                                   | Should |
| N-SEC-10 | Agent shall detect and alert on tampering / injection attempts                                                                                                                                                         | Should |
| N-SEC-11 | Process protection: Both Agent (service) and UI shall use Windows DACL to deny `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` to non-dlp-admin principals | Must   |
| N-SEC-12 | Named pipe connections shall be validated — UI must present a signed token on connect to prevent unauthorized pipe access                                                                                              | Should |

### 4.2 Performance

| ID       | Requirement                                                                                                                      | Target |
| -------- | -------------------------------------------------------------------------------------------------------------------------------- | ------ |
| N-PER-01 | Policy Engine shall handle ≥ 10,000 decision requests per second                                                                 | Must   |
| N-PER-02 | End-to-end decision latency (agent → engine → response) shall be ≤ 100ms at P95                                                  | Must   |
| N-PER-03 | Policy Engine decision latency (engine-only) shall be ≤ 50ms at P95                                                              | Must   |
| N-PER-04 | Agent shall consume ≤ 2% CPU at idle on a standard endpoint                                                                      | Should |
| N-PER-05 | Agent shall not increase file copy/save latency by more than 50ms                                                                | Must   |
| N-PER-06 | Policy Engine shall start and be ready to serve within 30 seconds                                                                | Must   |
| N-PER-07 | Agent ↔ UI IPC round-trip (blocking request → user response) shall complete within 60 seconds; Agent defaults to DENY on timeout | Must   |

### 4.3 Scalability

| ID       | Requirement                                                                              | Target |
| -------- | ---------------------------------------------------------------------------------------- | ------ |
| N-SCA-01 | Policy Engine shall support horizontal scaling (multiple instances behind load balancer) | Must   |
| N-SCA-02 | Agent shall support configuration for primary and secondary Policy Engine endpoints      | Must   |
| N-SCA-03 | System shall support ≥ 50,000 concurrent endpoints                                       | Must   |
| N-SCA-04 | Policy Engine shall support ≥ 100,000 active policies                                    | Must   |

### 4.4 Availability

| ID       | Requirement                                                                                                     | Target |
| -------- | --------------------------------------------------------------------------------------------------------------- | ------ |
| N-AVA-01 | Policy Engine shall achieve 99.9% uptime (≤ 8.7 hours downtime/year)                                            | Must   |
| N-AVA-02 | Agent shall operate in offline/cached mode when Policy Engine is unreachable                                    | Must   |
| N-AVA-03 | System shall support active-passive failover for Policy Engine                                                  | Should |
| N-AVA-04 | Agent shall reconnect automatically when Policy Engine becomes available                                        | Must   |
| N-AVA-05 | Agent shall survive user logoff; the UI shall be terminated by Agent on logoff and respawned on next user logon | Must   |

### 4.5 Compatibility

| ID       | Requirement                                                                   | Target |
| -------- | ----------------------------------------------------------------------------- | ------ |
| N-COM-01 | Agent shall support Windows 10 Enterprise (1903+)                             | Must   |
| N-COM-02 | Agent shall support Windows 11 Enterprise                                     | Must   |
| N-COM-03 | Agent shall support Windows Server 2019 and 2022                              | Must   |
| N-COM-04 | Policy Engine shall support Windows Server 2019+ and Linux (Ubuntu 22.04 LTS) | Must   |
| N-COM-05 | Administrative UI shall support Chrome 110+, Edge 110+, Firefox 110+          | Must   |
| N-COM-06 | SIEM integration shall support Splunk HEC and ELK HTTP Ingest                 | Must   |

### 4.6 Maintainability

| ID       | Requirement                                                                 | Target |
| -------- | --------------------------------------------------------------------------- | ------ |
| N-MNT-01 | All components shall be implemented in Rust                                 | Must   |
| N-MNT-02 | Code shall pass `cargo clippy` with zero warnings                           | Must   |
| N-MNT-03 | Code shall be formatted with `cargo fmt`                                    | Must   |
| N-MNT-04 | Each crate shall have complete unit test coverage for public APIs           | Must   |
| N-MNT-05 | Integration tests shall cover end-to-end policy evaluation flows            | Must   |
| N-MNT-06 | All public APIs shall have doc comments                                     | Must   |
| N-MNT-07 | Crates shall publish structured error types using `thiserror` or equivalent | Must   |

### 4.7 Agent-as-Service Operational

| ID       | Requirement                                                                                      | Target                                               |
| -------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------- |
| N-SVC-01 | Agent shall register as a Windows Service via `sc create dlp-agent type= own start= auto`        | Must                                                 |
| N-SVC-02 | Agent shall be a single-instance service; subsequent start attempts shall be rejected with error | Must                                                 |
| N-SVC-03 | Agent shall survive logoff of the interactive user session without stopping                      | Must                                                 |
| N-SVC-04 | UI shall launch on the interactive desktop of the logged-in user                                 | Must                                                 |
| N-SVC-05 | Named pipes shall use `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE` (message-mode, not byte-mode) | Must                                                 |
| N-SVC-06 | Service shutdown shall complete within 30 seconds after correct password verification            | Must                                                 |
| N-SVC-07 | UI shall terminate cleanly within 5 seconds of receiving the stop confirmation from Agent        | Must                                                 |

### 4.8 dlp-server Operational

| ID       | Requirement                                                                        | Target |
| -------- | ---------------------------------------------------------------------------------- | ------ |
| N-SRV-01 | dlp-server shall handle ≥ 50,000 concurrent agent heartbeat connections           | Must   |
| N-SRV-02 | dlp-server shall ingest ≥ 10,000 audit events per second                          | Must   |
| N-SRV-03 | SIEM relay shall batch events (max 1s latency, max 1,000 events/batch)            | Must   |
| N-SRV-04 | Agent config push shall complete within 30 seconds of agent acknowledgment          | Must   |
| N-SRV-05 | dlp-server shall be horizontally scalable (stateless replicas behind load balancer) | Must   |
| N-SRV-06 | Audit storage shall be append-only (no update or delete API exposed)              | Must   |
| N-SRV-07 | dlp-server shall use TLS 1.3 for all inbound and outbound connections             | Must   |
| N-SRV-08 | dlp-server shall store admin credentials using PBKDF2 + salt                     | Must   |
| N-SRV-09 | Policy sync to all engine replicas shall complete within 5 seconds of policy change | Must   |

---

## 5. System Architecture

### 5.1 Component Architecture

```
                                    ┌──────────────────────────────┐
                                    │     dlp-admin-portal         │
                                    │     (Rust / Tauri)           │
                                    │     dlp-admin only           │
                                    └──────────────┬───────────────┘
                                                   │ REST / HTTPS / JWT
                                    ┌──────────────▼───────────────┐
                                    │       dlp-server              │
                                    │  (axum HTTP, Rust)             │
                                    │  ┌─────────────────────────┐ │
                                    │  │  Agent Registry         │ │
                                    │  │  Audit Store (append)   │ │
                                    │  │  SIEM Connector         │ │
                                    │  │  Alert Router           │ │
                                    │  │  Policy Sync            │ │
                                    │  │  Admin Auth (JWT)       │ │
                                    │  │  Admin Audit            │ │
                                    │  └─────────────────────────┘ │
                                    └──────┬──────────────┬────────┘
                                           │              │
              HTTPS audit                 │   HTTPS       │ gRPC / TLS
             heartbeat /                  │   config push │
             config pull                  │              │
             ┌────────────────────────────▼──┐  ┌───────▼──────────────┐
             │   dlp-agent (Service, N)        │  │  policy-engine (N)   │
             │   SYSTEM account               │  │  gRPC, stateless      │
             └────┬───────────────────────────┘  └─────────────────────┘
                  │ IPC (3 Named Pipes)
        ┌─────────┼───────────────────┐
        │         │                   │
   Pipe 1    Pipe 2               Pipe 3
  \\.\pipe\  \\.\pipe\           \\.\pipe\
  DLPCommand DLPEventAgent2UI  DLPEventUI2Agent
        │
        └─────────────▼─────────────────────────────┐
                        │  DLP endpoint UI (Tauri subprocess)  │
                        │  Interactive user desktop              │
                        │  Toast · Dialogs · Clipboard · Tray      │
                        └─────────────────────────────────────────┘

                           ┌──────────────────────────────┐
                           │  SIEM                         │
                           │  (Splunk HEC / ELK Ingest)  │
                           │  ← dlp-server relay         │
                           └──────────────────────────────┘
```

### 5.2 Crate Architecture

```
dlp-rust/                           # Cargo workspace
├── Cargo.toml                      # Workspace definition
│
├── common-types/                   # Shared types (unchanged)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── abac.rs                 # Subject, Resource, Environment, Action
│       ├── audit.rs                # AuditEvent, EventType enums
│       └── classification.rs       # T1–T4 classification types
│
├── policy-engine/                  # ABAC decision engine (unchanged)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── engine.rs               # Policy evaluation logic
│       ├── ad_client.rs            # Active Directory LDAP client
│       ├── grpc_server.rs          # gRPC service implementation
│       └── policy_cache.rs         # Local policy cache (synced from dlp-server)
│
├── dlp-server/                    # NEW — Central management server
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # axum HTTP server entry
│       ├── agent_registry.rs      # Agent heartbeat, online/offline tracking
│       ├── audit_store.rs       # Append-only audit ingestion + query API
│       ├── siem_connector.rs    # Splunk HEC + ELK relay (batched)
│       ├── alert_router.rs      # Email (SMTP/TLS) + webhook for DENY_WITH_ALERT
│       ├── policy_sync.rs        # Push policies to policy-engine replicas
│       ├── exception_store.rs   # Override/exception approval records
│       ├── admin_auth.rs        # TOTP validation, JWT issuance/refresh
│       ├── admin_audit.rs      # Admin action audit log
│       ├── config_push.rs       # Agent configuration push
│       └── admin_api.rs        # REST API consumed by dlp-admin-portal
│
├── dlp-agent/                      # Endpoint enforcement (Windows Service)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs                 # Windows service entry (winreg / windows-rs)
│   │   ├── service.rs              # Service lifecycle (Start/Stop/Control)
│   │   ├── ui_spawner.rs          # CreateProcessAsUser, session detection
│   │   ├── ipc/
│   │   │   ├── mod.rs
│   │   │   ├── command_pipe.rs     # Pipe 1: \\.\pipe\DLPCommand (2-way)
│   │   │   ├── event_a2u.rs        # Pipe 2: \\.\pipe\DLPEventAgent2UI
│   │   │   └── event_u2a.rs        # Pipe 3: \\.\pipe\DLPEventUI2Agent
│   │   ├── interceptor.rs          # File operation interception (WinAPI)
│   │   ├── engine_client.rs        # gRPC client to Policy Engine
│   │   ├── server_client.rs        # HTTPS client to dlp-server (audit, heartbeat, config)
│   │   ├── cache.rs               # Local policy decision cache
│   │   ├── audit_emitter.rs       # JSON audit → dlp-server (not direct SIEM)
│   │   └── protection.rs          # Process DACL hardening
│   │
│   └── src-tauri/                  # Embedded Tauri endpoint UI
│       ├── Cargo.toml
│       ├── tauri.conf.json
│       └── src/
│           ├── main.rs
│           ├── ui_main.rs          # Tauri command handlers (IPC client)
│           ├── dialogs/
│           │   ├── block_notify.rs       # Blocking notification
│           │   ├── override_request.rs   # Override + justification
│           │   └── password_dialog.rs    # sc stop password dialog
│           ├── tray.rs             # System tray widget
│           ├── clipboard.rs        # Clipboard read/write
│           └── health_monitor.rs  # Pings Agent via Pipe 3
│
└── dlp-admin-portal/             # Administrative UI (was: dlp-ui/)
    ├── Cargo.toml
    ├── src/
    │   ├── main.rs
    │   ├── policies.rs             # Policy management panel
    │   ├── dashboard.rs           # Agent health dashboard (GET /agents from dlp-server)
    │   ├── incidents.rs          # Incident log viewer (GET /audit-events from dlp-server)
    │   ├── exceptions.rs        # Exception approval workflow
    │   └── api.rs               # dlp-server REST client (bearer JWT)
    └── tauri.conf.json
```

### 5.3 Data Flow

```
1. Windows boots → SCM starts dlp-agent service (SYSTEM account)
2. Agent sends REGISTER to dlp-server HTTPS endpoint (agent_id, hostname, version, OS)
   — dlp-server adds agent to registry, returns agent config
3. Agent registers with Policy Engine via gRPC, starts listening on 3 named pipes
4. Agent detects active console session (WTSGetActiveConsoleSessionId)
5. Agent calls CreateProcessAsUser → Tauri UI launches on interactive desktop
6. UI connects to all 3 pipes, sends UI_READY over Pipe 3
7. Agent sends heartbeat to dlp-server every 30 seconds (dlp-server marks offline after 90s miss)

--- Normal operation ---

8. User attempts to copy a classified file to USB
9. Agent intercepts via Windows API hook (minifilter / SSDT hook)
10. Agent constructs ABAC request (subject: user SID, groups, device trust;
    resource: path, T3 classification; action: COPY)
11. Agent sends gRPC EvaluateRequest to Policy Engine
12. Policy Engine evaluates policies in priority order
13. Policy Engine returns DENY_WITH_ALERT
14. Agent emits JSON AuditEvent → dlp-server HTTPS endpoint
15. dlp-server writes to append-only audit store
16. dlp-server batches events (≤1s / ≤1000 events) → SIEM
17. dlp-server triggers alert_router for DENY_WITH_ALERT → email + webhook

--- Policy CRUD flow ---

A1. dlp-admin logs into dlp-admin-portal (username + password + TOTP)
A2. dlp-admin-portal → dlp-server POST /auth/login (TOTP validated)
A3. dlp-server returns JWT (8h); all subsequent API calls carry bearer token
A4. Admin creates policy via dlp-admin-portal
A5. dlp-admin-portal → dlp-server POST /policies
A6. dlp-server writes to policy DB, syncs to all policy-engine replicas
A7. dlp-server emits admin_audit event (admin identity, action, timestamp)

--- sc stop flow ---

S1. Admin runs: sc stop dlp-agent
S2. SCM sends SERVICE_CONTROL_STOP to Agent
S3. Agent sets state STOP_PENDING, sends PASSWORD_DIALOG over Pipe 1
S4. DLP endpoint UI shows dlp-admin password dialog
S5. Admin enters credentials, submits
S6. DLP endpoint UI sends PASSWORD_SUBMIT over Pipe 1
S7. Agent validates via AD LDAP bind; correct → clean shutdown
S8. dlp-server marks agent as uninstalled in registry
```
14. Agent sends BLOCK_NOTIFY over Pipe 1, waits for response
15. DLP UI receives BLOCK_NOTIFY, shows toast notification
16. User reads notification; operation is blocked

--- Override request ---

17. User clicks "Request Override" in the notification
18. DLP UI shows dialog: "Please provide business justification"
19. User types justification, clicks Submit
20. DLP UI sends {USER_CONFIRMED, id, justification} over Pipe 1
21. Agent receives response, creates exception record
22. Agent permits operation (one-time or time-limited exception)
23. Audit event emitted with override justification

--- sc stop flow ---

24. Admin runs: sc stop dlp-agent
25. SCM sends SERVICE_CONTROL_STOP to Agent
26. Agent sets state STOP_PENDING, sends PASSWORD_DIALOG over Pipe 1
27. DLP UI shows dlp-admin password dialog
28. Admin enters dlp-admin credentials, submits
29. DLP UI sends PASSWORD_SUBMIT over Pipe 1
30. Agent validates credentials via AD LDAP bind
31. Password correct → Agent stops UI, stops service cleanly
32. Password wrong (×3) → Agent cancels stop, logs failure, returns to RUNNING
```

---

## 6. Security Requirements

### 6.1 Threat Coverage (STRIDE)

| Threat                     | Security Control                                              | Implementation               |
| -------------------------- | ------------------------------------------------------------- | ---------------------------- |
| **Spoofing**               | MFA for admin, mTLS for agent-to-engine                       | F-ADM-06, N-SEC-05           |
| **Tampering**              | NTFS ACLs, code signing for agent updates, process protection | N-SEC-03, N-SEC-11           |
| **Repudiation**            | Immutable audit logs, signed events                           | F-AUD-06, F-AUD-07           |
| **Information Disclosure** | ABAC + DLP enforcement, encryption at rest                    | F-ENG-12, N-SEC-01           |
| **Denial of Service**      | Rate limiting, horizontal scaling                             | N-SCA-01, F-ENG-10           |
| **Privilege Escalation**   | Strict RBAC + ABAC, process DACL, service stop MFA            | N-SEC-11, F-SVC-12           |
| **Agent Kill Bypass**      | Process protection DACL, health monitoring                    | N-SEC-11, F-SVC-04, F-SVC-08 |
| **Agent Impersonation**     | dlp-server authenticates agents via mTLS or signed JWT          | F-SRV-04, N-SRV-07           |
| **Audit Tampering**        | Append-only audit store + hash chain                           | F-SRV-02, N-SRV-06           |
| **Admin Credential Theft** | TOTP + JWT, PBKDF2 storage, DPAPI                           | F-SRV-07, N-SRV-08           |
| **SIEM Token Sprawl**     | Single SIEM credential in dlp-server; agents hold only dlp-server credentials | F-SRV-03              |

### 6.2 Encryption Requirements

| Data State                           | Protection                                                                                                                                                                                         | Standard |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| At rest (audit logs)                 | NTFS + BitLocker                                                                                                                                                                                   | AES-256  |
| In transit (agent ↔ engine)          | TLS 1.3 + mTLS                                                                                                                                                                                     | RFC 8446 |
| In transit (engine ↔ AD)             | LDAPS                                                                                                                                                                                              | RFC 4511 |
| In transit (logs → SIEM)             | TLS 1.3                                                                                                                                                                                            | RFC 8446 |
| In transit (Agent ↔ UI, named pipes) | Wire format is DPAPI-encrypted (`CRYPTUSERPROTECTIVE` scope); UI calls `CryptProtectData` before transmitting; Agent calls `CryptUnprotectData` on receipt; decryption is scoped to the local user | DPAPI    |

---

## 7. Compliance Requirements

### 7.1 ISO 27001:2022 Control Mapping

| Control                                 | Requirement                                                                 | Implementation        |
| --------------------------------------- | --------------------------------------------------------------------------- | --------------------- |
| **A.5.1** Information Security Policies | Policies documented and approved                                            | SRS, ABAC_POLICIES.md |
| **A.5.3** Segregation of Duties         | dlp-admin vs. end users vs. auditors                                        | SRS.md §2.3           |
| **A.6.2** Privileged Access Rights      | dlp-admin is single superuser; dlp-admin password required for service stop | F-SVC-10–F-SVC-12     |
| **A.7.2** Physical Security             | Policy Engine hosted on hardened, physically secure server                  | N-SEC-04              |
| **A.8.1** Asset Responsibility          | Data classification (T1–T4) applied to all assets                           | F-ADM-02              |
| **A.8.2** Classification                | Four-tier classification enforced by ABAC                                   | F-ENG-01              |
| **A.9.1** Access Control Policy         | NTFS + ABAC dual-layer enforcement                                          | Architecture §2.1     |
| **A.9.4** Secure Authentication         | AD authentication, MFA for admin                                            | N-SEC-06              |
| **A.9.5** Secure Authorization          | ABAC policy-based authorization                                             | F-ENG-01–F-ENG-12     |
| **A.12.3** Information Backup           | Audit log redundancy via SIEM                                               | F-AUD-03              |
| **A.12.4** Event Logging                | Structured JSON audit events                                                | F-AUD-01, F-AUD-02    |
| **A.12.5** Secure Communication         | TLS 1.3 all channels                                                        | N-SEC-01              |
| **A.16.1** Incident Management          | DLP alerts and response workflow                                            | F-AUD-08, F-ADM-08    |

---

## 8. Implementation Plan

### Phase 1 — Foundation (Weeks 1–6)

**Goal:** Establish the core workspace, shared types, and Policy Engine skeleton.

| ID     | Task                                                                                   | Deliverable                    | Priority |
| ------ | -------------------------------------------------------------------------------------- | ------------------------------ | -------- |
| P1-T01 | Initialize Cargo workspace with all 4 crates                                           | `Cargo.toml` workspace         | Must     |
| P1-T02 | Implement `common-types`: Subject, Resource, Environment, Action, Classification enums | `common-types/`                | Must     |
| P1-T03 | Implement `common-types`: AuditEvent schema and EventType enums                        | `common-types/`                | Must     |
| P1-T04 | Define gRPC `.proto` files for Policy Engine API                                       | `policy-engine/proto/`         | Must     |
| P1-T05 | Implement Policy Engine: policy store (JSON), rule evaluation engine                   | `policy-engine/`               | Must     |
| P1-T06 | Implement Policy Engine: gRPC server with `Evaluate` endpoint                          | `policy-engine/`               | Must     |
| P1-T07 | Implement Policy Engine: AD LDAP client for group membership                           | `policy-engine/`               | Must     |
| P1-T08 | Write unit tests for Policy Engine core evaluation logic                               | `policy-engine/tests/`         | Must     |
| P1-T09 | Implement AD mock server for integration testing                                       | `policy-engine/tests/mock_ad/` | Must     |
| P1-T10 | Write API documentation for Policy Engine gRPC interface                               | `docs/API.md`                  | Should   |

### Phase 2 — Core Enforcement (Weeks 7–12)

**Goal:** DLP Agent as Windows Service with IPC module and Policy Engine integration.

| ID     | Task                                                                                 | Deliverable                                           | Priority |
| ------ | ------------------------------------------------------------------------------------ | ----------------------------------------------------- | -------- |
| P2-T01 | Implement dlp-agent service skeleton: `main.rs`, `service.rs`, single-instance mutex | `dlp-agent/src/main.rs`, `service.rs`                 | Must     |
| P2-T02 | Implement IPC module: 3 named pipe servers in `dlp-agent/src/ipc/`                   | `dlp-agent/src/ipc/`                                  | Must     |
| P2-T03 | Implement UI spawner: `WTSGetActiveConsoleSessionId` + `CreateProcessAsUser`         | `dlp-agent/src/ui_spawner.rs`                         | Must     |
| P2-T04 | Implement process protection: DACL hardening on Agent and UI processes               | `dlp-agent/src/protection.rs`                         | Must     |
| P2-T05 | Implement mutual health monitoring: Agent pings UI (Pipe 2), UI pings Agent (Pipe 3) | `dlp-agent/src/`, `src-tauri/`                        | Must     |
| P2-T06 | Implement DLP Agent: Windows API hooks for file operations                           | `dlp-agent/src/interceptor.rs`                        | Must     |
| P2-T07 | Implement DLP Agent: gRPC client to Policy Engine                                    | `dlp-agent/src/engine_client.rs`                      | Must     |
| P2-T08 | Implement DLP Agent: local policy decision cache                                     | `dlp-agent/src/cache.rs`                              | Must     |
| P2-T09 | Implement DLP Agent: offline mode with cached decisions (fail-closed for T3/T4)      | `dlp-agent/src/`                                      | Must     |
| P2-T10 | Implement DLP Agent: USB mass storage and SMB upload detection                       | `dlp-agent/src/interceptor.rs`                        | Must     |
| P2-T11 | Implement DLP Agent: JSON audit event emission                                       | `dlp-agent/src/audit_emitter.rs`                      | Must     |
| P2-T12 | Implement Tauri UI: IPC client connecting to all 3 pipes                             | `dlp-agent/src-tauri/src/ui_main.rs`                  | Must     |
| P2-T13 | Implement Tauri UI: BLOCK_NOTIFY toast + dialog                                      | `dlp-agent/src-tauri/src/dialogs/`                    | Must     |
| P2-T14 | Implement Tauri UI: Override request dialog with justification                       | `dlp-agent/src-tauri/src/dialogs/override_request.rs` | Must     |
| P2-T15 | Implement Tauri UI: Clipboard read/write handler                                     | `dlp-agent/src-tauri/src/clipboard.rs`                | Must     |
| P2-T16 | Policy Engine: REST API for policy CRUD                                              | `policy-engine/`                                      | Must     |
| P2-T17 | Write integration tests: Agent ↔ Policy Engine end-to-end                            | `dlp-agent/tests/`                                    | Must     |
| P2-T18 | Write integration tests: all ABAC policies from ABAC_POLICIES.md                     | `policy-engine/tests/`                                | Must     |

### Phase 3 — UI & Integration (Weeks 13–18)

**Goal:** Complete DLP UI, Administrative UI, and SIEM integration.

| ID     | Task                                                                           | Deliverable                                          | Priority |
| ------ | ------------------------------------------------------------------------------ | ---------------------------------------------------- | -------- |
| P3-T01 | Implement Tauri UI: sc stop password dialog + AD credential verification       | `dlp-agent/src-tauri/src/dialogs/password_dialog.rs` | Must     |
| P3-T02 | Implement Tauri UI: service stop shutdown sequence (Agent → UI → clean exit)   | `dlp-agent/src-tauri/`, `dlp-agent/src/`             | Must     |
| P3-T03 | Implement Tauri UI: system tray widget with status indicator                   | `dlp-agent/src-tauri/src/tray.rs`                    | Must     |
| P3-T04 | Implement Tauri UI: double-click tray → open Admin portal                      | `dlp-agent/src-tauri/src/tray.rs`                    | Must     |
| P3-T05 | Implement Tauri UI: Admin portal (policy management + audit viewer)            | `dlp-agent/src-tauri/src/`                           | Must     |
| P3-T06 | Implement SIEM integration: Splunk HEC emitter                                 | `common-types/` or `dlp-agent/`                      | Must     |
| P3-T07 | Implement SIEM integration: ELK HTTP Ingest emitter                            | `common-types/` or `dlp-agent/`                      | Must     |
| P3-T08 | Implement audit log buffering: local encrypted buffer when SIEM is unreachable | `dlp-agent/src/audit_emitter.rs`                     | Should   |
| P3-T09 | Implement dlp-ui: system health dashboard                                      | `dlp-ui/src/dashboard.rs`                            | Must     |
| P3-T10 | Implement dlp-ui: authentication (dlp-admin MFA TOTP)                          | `dlp-ui/`                                            | Must     |
| P3-T11 | Implement alert routing: email/webhook for DENY_WITH_ALERT                     | `policy-engine/`                                     | Should   |
| P3-T12 | Write end-to-end tests: full data flow (UI → Agent → Engine → SIEM)            | `integration-tests/`                                 | Must     |

### Phase 4 — Production Hardening (Weeks 19–24)

**Goal:** Security hardening, performance validation, deployment readiness.

| ID     | Task                                                               | Deliverable                | Priority |
| ------ | ------------------------------------------------------------------ | -------------------------- | -------- |
| P4-T01 | Security audit: mTLS, MFA, DPAPI, process DACL, credential storage | Security audit report      | Must     |
| P4-T02 | Performance testing: 10k req/s, P95 latency ≤ 50ms                 | Performance test report    | Must     |
| P4-T03 | Load testing: 50k concurrent agents                                | Load test report           | Must     |
| P4-T04 | Policy Engine: horizontal scaling / load balancer integration      | `policy-engine/`           | Must     |
| P4-T05 | Agent self-update mechanism                                        | `dlp-agent/`               | May      |
| P4-T06 | Agent deployment: MSI installer, GPO/Intune integration guide      | Deployment guide           | Must     |
| P4-T07 | Write OPERATIONAL.md: runbook, failover, backup                    | `docs/OPERATIONAL.md`      | Must     |
| P4-T08 | Final integration testing and regression suite                     | Full test suite            | Must     |
| P4-T09 | Threat model review and red-team assessment                        | Security assessment report | Should   |
| P4-T10 | Pre-production deployment to staging environment                   | Staging deployment         | Must     |

### Phase 5 — dlp-server (Weeks 25–30)

**Goal:** Introduce dlp-server as the central management hub; update all other components to use it. After Phase 5, agents send audit to dlp-server (not direct to SIEM); dlp-admin-portal calls dlp-server REST API (not direct to policy-engine).

| ID     | Task                                                                       | Deliverable                          | Priority |
| ------ | -------------------------------------------------------------------------- | ------------------------------------ | -------- |
| P5-T01 | Implement dlp-server HTTP skeleton: axum, TLS, health endpoint             | `dlp-server/src/main.rs`             | Must     |
| P5-T02 | Implement agent registry: registration, heartbeat, offline detection        | `dlp-server/src/agent_registry.rs`   | Must     |
| P5-T03 | Implement admin auth: TOTP validation, PBKDF2 store, JWT issuance         | `dlp-server/src/admin_auth.rs`        | Must     |
| P5-T04 | Implement audit store: append-only ingestion, query API                     | `dlp-server/src/audit_store.rs`       | Must     |
| P5-T05 | Implement SIEM connector: batched Splunk HEC + ELK relay                  | `dlp-server/src/siem_connector.rs`    | Must     |
| P5-T06 | Implement alert router: email (SMTP/TLS) + webhook (HTTPS/TLS)             | `dlp-server/src/alert_router.rs`      | Must     |
| P5-T07 | Implement policy sync: push policies to policy-engine replicas              | `dlp-server/src/policy_sync.rs`       | Must     |
| P5-T08 | Implement exception store: approval records                                  | `dlp-server/src/exception_store.rs`   | Should   |
| P5-T09 | Implement admin REST API: /agents, /audit-events, /policies, /exceptions | `dlp-server/src/admin_api.rs`         | Must     |
| P5-T10 | Update dlp-agent: send audit to dlp-server (remove direct SIEM)            | `dlp-agent/src/audit_emitter.rs`      | Must     |
| P5-T11 | Update dlp-agent: send heartbeats to dlp-server                           | `dlp-agent/src/server_client.rs`     | Must     |
| P5-T12 | Update dlp-admin-portal: use dlp-server REST API (remove direct policy-engine calls) | `dlp-admin-portal/src/api.rs`   | Must     |
| P5-T13 | Implement config push: agent configuration management                       | `dlp-server/src/config_push.rs`      | Should   |
| P5-T14 | Update policy-engine: replace policy_store.rs with policy_cache.rs (sync from dlp-server) | `policy-engine/src/`            | Must     |
| P5-T15 | Load test: 50k agent heartbeats, 10k audit events/sec                    | Load test report                     | Must     |

---

## 9. Acceptance Criteria

### 9.1 Policy Engine

- [ ] gRPC `Evaluate` endpoint returns a decision for every valid request within 50ms at P95
- [ ] ABAC rules: T4 → DENY except owner, T3 + Unmanaged → DENY, T2 → ALLOW_WITH_LOG
- [ ] Engine rejects malformed policies at load time with descriptive error
- [ ] Engine queries AD and returns correct group membership for a given user SID
- [ ] Engine enforces Critical Rule: NTFS ALLOW + ABAC DENY = DENY
- [ ] Hot-reload: new policies take effect within 5 seconds without restart

### 9.2 DLP Agent

- [ ] Agent installs and registers as a Windows Service via `sc create`; survives reboot
- [ ] Agent is single-instance; second start attempt is rejected
- [ ] Agent spawns the Tauri UI subprocess on the interactive desktop on service startup
- [ ] Agent registers with Policy Engine and maintains heartbeat
- [ ] Agent blocks file copy to USB when resource classification = T3 or T4
- [ ] Agent blocks file upload to unauthorized SMB share when classification = T3 or T4
- [ ] Agent emits JSON audit event for every intercepted file operation
- [ ] Agent operates in offline mode with cached decisions when engine is unreachable; defaults DENY for T3/T4 on cache miss

### 9.3 Agent ↔ UI Co-Process

- [ ] Agent and UI communicate via exactly 3 named pipes (DLPCommand, DLPEventAgent2UI, DLPEventUI2Agent)
- [ ] Blocking file operation: Agent sends BLOCK_NOTIFY over Pipe 1; UI shows notification; Agent waits for USER_CONFIRMED/USER_CANCELLED (timeout 60s → default DENY)
- [ ] Override request: UI shows dialog with justification text input; sends OVERRIDE_REQUEST with justification over Pipe 1
- [ ] Agent health check: If UI is absent or unresponsive for 15 seconds, Agent kills and respawns UI
- [ ] UI health check: If Agent disappears or IPC connection is lost for 15 seconds, UI terminates itself within 5 seconds
- [ ] Normal user cannot terminate Agent service via Task Manager, Process Explorer, or `taskkill`
- [ ] Non-dlp-admin administrator cannot terminate Agent service via Task Manager or `taskkill`
- [ ] `sc query dlp-agent` shows correct service state (Running/Stopped/Stop-pending)
- [ ] Clipboard read: Agent sends CLIPBOARD_READ over Pipe 1; UI returns CLIPBOARD_DATA with content

### 9.4 Service Stop (Kill) Flow

- [ ] `sc stop dlp-agent` sets service to STOP_PENDING; Agent signals UI to show password dialog
- [ ] UI shows dlp-admin password dialog; on correct AD password → service stops cleanly within 30 seconds
- [ ] On 3 consecutive incorrect password attempts → event is logged, service cancels stop, returns to RUNNING
- [ ] UI terminates cleanly within 5 seconds after stop confirmation

### 9.5 dlp-admin-portal

- [ ] DLP Admin can create, edit, delete, and view ABAC policies
- [ ] DLP Admin can assign T1–T4 classification to a file/folder
- [ ] DLP Admin can view agent health: connected agents, offline count, agent version via dlp-server GET /agents
- [ ] DLP Admin can query and export audit logs filtered by date, user, and event type via dlp-server GET /audit-events
- [ ] DLP Admin receives real-time alert for every T3/T4 DENY_WITH_ALERT event
- [ ] Admin login requires username + password + TOTP; dlp-server issues JWT on success
- [ ] All dlp-admin-portal API calls carry JWT bearer token from dlp-server

### 9.6 Security

- [ ] All network traffic is TLS 1.3 (no downgrade)
- [ ] gRPC uses mutual TLS (mTLS)
- [ ] DLP Admin MFA is enforced (TOTP validated by dlp-server)
- [ ] Audit logs are immutable (append-only, in dlp-server)
- [ ] Named pipe password traffic is protected by DPAPI (CryptProtectData)
- [ ] No credentials stored in plaintext
- [ ] Process DACL denies PROCESS_TERMINATE to non-dlp-admin principals on both Agent and UI processes
- [ ] dlp-server uses PBKDF2 + salt for admin credential storage
- [ ] dlp-server audit store has no update or delete API exposed

### 9.8 Compliance

- [ ] dlp-server receives audit events from all connected agents over HTTPS
- [ ] dlp-server writes audit events to append-only storage
- [ ] dlp-server forwards audit events to SIEM in batches (≤1s latency, ≤1000 events/batch)
- [ ] dlp-server marks agent offline if heartbeat missed for 3 intervals (90 seconds)
- [ ] dlp-server routes DENY_WITH_ALERT to email (SMTP/TLS) and webhook (HTTPS/TLS)
- [ ] Policy create/update via dlp-admin-portal syncs to all policy-engine replicas via dlp-server
- [ ] dlp-server issues JWT on admin login (TOTP validated); all admin API calls are logged with admin identity
- [ ] dlp-server is horizontally scalable (stateless replicas)

### 9.7 Compliance

- [ ] ISO 27001 A.5 through A.16 controls are implemented as documented in §7
- [ ] Audit event schema matches F-AUD-02 for all logged events
- [ ] All doc files in `docs/` are consistent with this SRS

---

## 10. Glossary

| Term                             | Definition                                                                                                                   |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **ABAC**                         | Attribute-Based Access Control — authorization model evaluating subject/resource/environment attributes against policy rules |
| **ACL**                          | Access Control List — list of permissions attached to an object                                                              |
| **AES-256**                      | Advanced Encryption Standard with 256-bit key — symmetric encryption algorithm                                               |
| **API**                          | Application Programming Interface                                                                                            |
| **BitLocker**                    | Microsoft full-disk encryption for Windows                                                                                   |
| **CLAUDE.md**                    | Project definition file used by AI assistants                                                                                |
| **CreateProcessAsUser**          | Windows API to spawn a process in a specific user session                                                                    |
| **DACL**                         | Discretionary Access Control List — part of an object's security descriptor controlling access                               |
| **DLP**                          | Data Loss Prevention — system to monitor and prevent unauthorized data transfer                                              |
| **dlp-admin**                    | Designated superuser account for DLP system administration and secure service stop                                           |
| **DPAPI**                        | Data Protection API — Windows API for encrypting data using the user's credentials (CryptProtectData/CryptUnprotectData)     |
| **EDR**                          | Endpoint Detection and Response                                                                                              |
| **ELK**                          | Elasticsearch, Logstash, Kibana — open-source SIEM stack                                                                     |
| **gRPC**                         | Google Remote Procedure Call — high-performance RPC framework                                                                |
| **HEC**                          | HTTP Event Collector — Splunk's HTTP-based log ingestion endpoint                                                            |
| **HSM**                          | Hardware Security Module                                                                                                     |
| **IPC**                          | Inter-Process Communication — mechanism for processes to communicate; here: Windows named pipes                              |
| **ISO 27001**                    | ISO/IEC 27001 — international standard for information security management                                                   |
| **LDAPS**                        | LDAP over TLS — secure directory protocol                                                                                    |
| **MFA**                          | Multi-Factor Authentication                                                                                                  |
| **mTLS**                         | Mutual TLS — TLS with both client and server certificate authentication                                                      |
| **Named Pipe**                   | Windows kernel object (\\.\pipe\*) for message-mode IPC between processes                                                    |
| **NTFS**                         | New Technology File System — Windows default file system with ACL support                                                    |
| **P95**                          | 95th percentile — 95% of observations are at or below this value                                                             |
| **PII**                          | Personally Identifiable Information                                                                                          |
| **RBAC**                         | Role-Based Access Control — authorization model using roles and permissions                                                  |
| **Rust**                         | Systems programming language focused on safety and performance                                                               |
| **SCM**                          | Service Control Manager — Windows component managing Windows Services lifecycle                                              |
| **SID**                          | Security Identifier — unique identifier for Windows principals (users, groups)                                               |
| **SIEM**                         | Security Information and Event Management — centralized log collection and analysis                                          |
| **Splunk**                       | Commercial SIEM platform                                                                                                     |
| **SRS**                          | Software Requirements Specification                                                                                          |
| **STRIDE**                       | Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Privilege Escalation — threat modeling methodology            |
| **SYSTEM account**               | Windows local system account with highest privilege on a single machine                                                      |
| **Tauri**                        | Rust-based desktop app framework using WebView; here used for the endpoint interaction UI                                    |
| **TLS 1.3**                      | Transport Layer Security version 1.3 — current best-practice encryption in transit                                           |
| **TOTP**                         | Time-based One-Time Password — MFA method (RFC 6238)                                                                         |
| **TTL**                          | Time-To-Live — duration a cached entry remains valid                                                                         |
| **WinAPI**                       | Windows Application Programming Interface                                                                                    |
| **WTSGetActiveConsoleSessionId** | Windows API to get the session ID of the interactive console user                                                            |
