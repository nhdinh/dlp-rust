# Threat Model — DLP-RUST Enterprise DLP System

**Document Version:** 1.0
**Date:** 2026-03-31
**Status:** Draft
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

> **Companion documents:**
> - [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) — Security controls, trust boundaries, and design decisions referenced throughout this document.
> - [SRS.md](./SRS.md) — Full requirements including F-\*, N-\* functional and non-functional requirements.
> - [AUDIT_LOGGING.md](./AUDIT_LOGGING.md) — Audit event schema, SIEM relay, and integrity controls.
> - [ISO27001_MAPPING.md](./ISO27001_MAPPING.md) — ISO 27001:2022 control mappings.

---

## Table of Contents

1. [Methodology and Scope](#1-methodology-and-scope)
2. [System Overview and Data Flow](#2-system-overview-and-data-flow)
3. [STRIDE Threat Analysis](#3-stride-threat-analysis)
   - [3.1 Spoofing](#31-spoofing)
   - [3.2 Tampering](#32-tampering)
   - [3.3 Repudiation](#33-repudiation)
   - [3.4 Information Disclosure](#34-information-disclosure)
   - [3.5 Denial of Service](#35-denial-of-service)
   - [3.6 Elevation of Privilege](#36-elevation-of-privilege)
4. [Residual Risks](#4-residual-risks)
5. [Security Controls Summary](#5-security-controls-summary)

---

## 1. Methodology and Scope

### 1.1 STRIDE Overview

STRIDE is a threat modeling methodology that categorises threats into six classes:

| Threat Class | Property Violated | Description |
|---|---|---|
| **Spoofing** | Authentication | Pretending to be someone or something else |
| **Tampering** | Integrity | Modifying data or code without authorisation |
| **Repudiation** | Non-repudiation | Claiming not to have performed an action |
| **Information Disclosure** | Confidentiality | Exposing information to unauthorised parties |
| **Denial of Service** | Availability | Making a system or resource unavailable |
| **Elevation of Privilege** | Authorisation | Gaining capabilities without proper authorisation |

### 1.2 In Scope

- **Components:** dlp-agent (Windows Service), dlp-user-ui (iced subprocess), policy-engine (HTTPS REST API), Active Directory / LDAPS, Named pipes (Pipe 1/2/3), audit log (local JSONL), `notify`-based file system interception
- **Phases:** Phase 1 (current implementation); Phase 5 (dlp-server, SIEM relay) noted where relevant
- **Environments:** Enterprise Windows endpoints (domain-joined), corporate network

### 1.3 Out of Scope

- Kernel-mode threats (requires kernel-level threat modeling separate from this document)
- Physical access attacks (laptop theft, cold-boot attacks)
- Social engineering of end users
- Supply chain attacks on build infrastructure
- Phase 2–4 hardening not yet implemented

---

## 2. System Overview and Data Flow

### 2.1 Component Overview

```
[Endpoint: Windows OS]
  ├── dlp-agent (Windows Service, SYSTEM account)
  │     ├── interception/file_monitor.rs  — File system monitor (notify crate)
  │     ├── detection/usb.rs           — USB device notification listener
  │     ├── detection/network_share.rs  — SMB share access detector
  │     ├── clipboard/listener.rs       — WH_GETMESSAGE clipboard hook
  │     ├── identity.rs                 — SMB impersonation resolution
  │     ├── engine_client.rs            — HTTPS client → policy-engine
  │     ├── cache.rs                   — Policy decision cache (TTL)
  │     ├── offline.rs                 — Offline mode (fail-closed)
  │     ├── audit_emitter.rs           — JSONL append-only audit log
  │     ├── ipc/pipe1.rs              — Named pipe: command/response
  │     ├── ipc/pipe2.rs              — Named pipe: agent→UI fire-and-forget
  │     ├── ipc/pipe3.rs              — Named pipe: UI→agent events
  │     ├── health_monitor.rs          — Mutual health ping-pong
  │     ├── session_monitor.rs         — Session connect/disconnect
  │     └── ui_spawner.rs             — Spawns UI in user sessions
  │
  └── dlp-user-ui (iced subprocess, interactive user session)
        ├── pipe1 client               — Receives BlockNotify, OverrideRequest; sends UserConfirmed/Cancelled
        ├── pipe2 listener             — Receives HEALTH_PING, toast, StatusUpdate
        ├── pipe3 client               — Sends HEALTH_PONG, UiReady, UiClosing
        ├── clipboard.rs               — Read clipboard (GetClipboardData)
        └── stop_password.rs           — sc stop password dialog (DPAPI)

[Corporate Network]
  └── policy-engine (HTTPS REST, Rust)
        ├── ad_client.rs              — LDAPS → Active Directory
        ├── engine.rs                 — ABAC policy evaluation
        ├── policy_store.rs           — JSON policy file + hot-reload
        └── rest_api.rs              — Policy CRUD REST endpoints

[Active Directory]
  └── Domain Controller (LDAPS :636)
        ├── User SIDs + group membership
        ├── dlpDeviceTrust attribute
        ├── dlpNetworkLocation attribute
        └── *(no dlp-admin credentials — stored locally in registry)*
```

### 2.2 Trust Boundaries

| Boundary | Description |
|---|---|
| **Endpoint ↔ Policy Engine** | HTTPS/TLS 1.3; mTLS client certificates; network segmentation |
| **Agent ↔ AD** | (Not used — Agent does not query AD directly) |
| **Agent ↔ UI (Pipe 1/2/3)** | Named pipes; SYSTEM-only ACL; DPAPI encryption for password payload |
| **Policy Engine ↔ AD** | LDAPS :636; TLS; AD service account (read-only); ABAC attribute lookups |
| **Admin ↔ dlp-server** | HTTPS; TOTP + JWT (Phase 5) |

---

## 3. STRIDE Threat Analysis

### 3.1 Spoofing

#### THREAT-001: Local Credential Theft
- **Asset:** dlp-admin bcrypt hash (`HKLM\SOFTWARE\DLP\Agent\Credentials\DLPAuthHash`); AD service account credentials
- **Threat:** Attacker steals dlp-admin password or AD service account credentials via credential dumping (Mimikatz, LSASS access, credential relay)
- **Attack Vector:** Malicious process running in user context or SYSTEM context dumps LSASS memory
- **Impact:** Attacker can present the dlp-admin password to stop the service, or use the AD service account to query AD attributes
- **Mitigation:**
  - Service runs as SYSTEM; LSASS access requires SYSTEM or equivalent privilege (not standard user)
  - dlp-admin password is never stored; verified via bcrypt hash comparison against `DLPAuthHash` registry value; DPAPI-wrapped over pipe before transmission
  - Process DACL (`protection.rs`): non-Administrators cannot terminate or inspect the agent process
  - **Status:** Partially Mitigated — LSASS dump from SYSTEM context is not blocked by the agent itself; relies on Windows Defender/EDR for prevention

#### THREAT-002: Agent Impersonation
- **Asset:** Agent → Policy Engine HTTPS channel
- **Threat:** Attacker presents a forged TLS client certificate to impersonate a legitimate agent
- **Attack Vector:** Theft of the agent's TLS client private key from the endpoint filesystem
- **Impact:** Malicious agent could submit forged evaluation requests, receive policy decisions for other users' actions, and corrupt the audit trail
- **Mitigation:**
  - Agent TLS client certificate stored in `.env` (not in source); filesystem ACLs restrict access
  - Policy Engine verifies client certificate against its trusted certificate store
  - **Status:** Partially Mitigated — key storage security depends on endpoint hardening

#### THREAT-003: UI Process Impersonation
- **Asset:** Named pipes (Pipe 1/2/3)
- **Threat:** Attacker spawns a fake UI process that connects to the agent's named pipes
- **Attack Vector:** Malicious code running in the user's session creates a pipe client and sends `RegisterSession`, `UserConfirmed`, or `ClipboardData`
- **Impact:** Attacker could confirm blocked operations or submit clipboard data on behalf of the user
- **Mitigation:**
  - SYSTEM-only ACL on all three pipes (only SYSTEM and Administrators can connect)
  - `pipe1.rs::handle_client()` requires `RegisterSession` as the first message
  - Service runs as SYSTEM; user-level code cannot connect to SYSTEM-owned pipes without privilege escalation
  - **Status:** Implemented

#### THREAT-004: Policy Engine Certificate Spoofing
- **Asset:** Agent ↔ Policy Engine HTTPS channel
- **Threat:** Attacker presents a forged TLS server certificate to intercept agent ↔ engine traffic
- **Attack Vector:** Corporate proxy, DNS poisoning, or compromised CA
- **Impact:** Agent sends evaluation requests to a malicious server; decisions are forged; audit trail is polluted
- **Mitigation:**
  - Agent validates Policy Engine TLS certificate against a configured trusted CA
  - Certificate pinned or validated against a known good certificate
  - **Status:** Planned — certificate pinning in Phase 5 (N-SEC-08)

#### THREAT-005: SMB Session Hijacking
- **Asset:** File access on network shares
- **Threat:** Attacker hijacks an SMB session to impersonate another user accessing files on a DLP-protected file server
- **Attack Vector:** NTLM relay, SMB session token theft
- **Impact:** DLP attributes access to the wrong user (attribution confusion)
- **Mitigation:**
  - `identity.rs` resolves actual caller identity from SMB impersonation token via `QuerySecurityContextToken`
  - AD group membership is always queried from the Domain Controller, not from the token
  - **Status:** Partially Mitigated — SMB signing/encryption depends on network infrastructure

---

### 3.2 Tampering

#### THREAT-006: Policy File Tampering
- **Asset:** `policies.json` — ABAC policy rules
- **Threat:** Attacker modifies the policy file to weaken or remove restrictive policies (e.g., remove the T4 DENY rule)
- **Attack Vector:** Write access to the path where `policies.json` is stored; file server share with weak ACLs
- **Impact:** T4/T3 files become accessible; data exfiltration becomes possible
- **Mitigation:**
  - `policy-store.rs::reload_policies()` validates all policies on hot-reload before swapping into the engine
  - Invalid policies (empty ID, priority > 100,000) are rejected with a logged error
  - Policy store path is configurable; default ACLs restrict write access to Administrators
  - Hot-reload happens on file change; tampering is detected only by monitoring the file externally
  - **Status:** Partially Mitigated — file ACLs and validation are in place; no integrity check (hash/checksum) on the policy file yet

#### THREAT-007: File Monitor Disabling
- **Asset:** File system monitor (`notify` crate watcher)
- **Threat:** Attacker disables or bypasses the `notify` watcher to render file interception blind
- **Attack Vector:** Admin privileges or direct syscall hooking that evades `notify`'s `ReadDirectoryChangesW` coverage
- **Impact:** All file operations are invisible to the DLP agent; no blocking or auditing
- **Mitigation:**
  - The `notify` crate is cross-session and requires no elevation — harder to disable than session-local APIs
  - Audit events are emitted for all intercepted operations; gaps in coverage are detectable in SIEM
  - **Status:** Not Mitigated — relies on Windows Defender/EDR to detect process-level interference

#### THREAT-008: Audit Log Tampering
- **Asset:** Local JSONL audit log (`C:\ProgramData\DLP\logs\audit.jsonl`)
- **Threat:** Attacker modifies or deletes audit log entries to cover tracks
- **Attack Vector:** Administrative access to the endpoint; malware running as SYSTEM or Administrators
- **Impact:** Security incidents are not recorded; forensic evidence is destroyed; compliance violations
- **Mitigation:**
  - File opened with append-only handle (`FILE_APPEND_DATA`; no `WRITE_OWNER`, `WRITE_DAC`, or `DELETE`)
  - Audit log directory ACLs restrict write access to SYSTEM and Administrators
  - Events are also emitted to SIEM (Phase 5); local log tampering does not affect SIEM copy
  - Append-only store with no delete API in `dlp-server` (Phase 5)
  - SHA-256 hash chain for tamper-evident logs: **Planned Phase 5**
  - **Status:** Partially Mitigated — append-only handle in Phase 1; SIEM relay in Phase 5; hash chain future work

#### THREAT-009: File Monitor Interference
- **Asset:** File system monitor (`notify` crate watcher)
- **Threat:** Attacker interferes with the `notify` watcher to cause missed file events
- **Attack Vector:** Administrative privileges or process injection to block the watcher thread
- **Impact:** File events are silently dropped; no audit event; no blocking decision
- **Mitigation:**
  - The `notify` watcher uses `try_send` (non-blocking) — missed events do not crash the pipeline
  - The monitor checks the stop flag every 500 ms and can be restarted
  - **Status:** Not Mitigated — no integrity verification of the monitor itself; rely on EDR

#### THREAT-010: Registry Tampering (Credentials)
- **Asset:** `HKLM\SOFTWARE\DLP\Agent\Credentials\DLPAuthHash` — dlp-admin bcrypt hash
- **Threat:** Attacker modifies the registry to tamper with or replace the bcrypt hash, enabling offline password cracking or bypass of verification
- **Attack Vector:** Administrative access to the registry
- **Impact:** Attacker replaces the stored hash with a known value, bypassing bcrypt verification to stop the service
- **Mitigation:**
  - Registry key ACLs restrict write access to Administrators
  - **Status:** Partially Mitigated — depends on OS ACL enforcement

---

### 3.3 Repudiation

#### THREAT-011: Admin Actions Without Audit Trail
- **Asset:** dlp-admin administrative actions (policy changes, override approvals)
- **Threat:** Administrator claims not to have made a policy change or override approval
- **Attack Vector:** No non-repudiation controls in place; admin acts anonymously
- **Impact:** Compliance violations; inability to attribute administrative actions
- **Mitigation:**
  - `ADMIN_ACTION` audit events include `user_sid` and `user_name` from the JWT
  - Audit log is append-only and timestamps each action
  - Phase 5: TOTP + JWT enforces authentication before admin actions
  - **Status:** Partially Mitigated in Phase 1 (TOTP + JWT auth via dlp-server in Phase 5); fully mitigated in Phase 5

#### THREAT-012: User Override Justification Not Audited
- **Asset:** Override justification text
- **Threat:** User claims not to have entered a specific justification for an override
- **Attack Vector:** User types free-text justification; text is logged in audit event
- **Impact:** The justification IS logged (non-repudiation in place), but the text may contain PII and has been raised as a privacy risk
- **Mitigation:**
  - Override justifications are stored in audit events with timestamp and user identity
  - **Status:** Implemented (with privacy note: free-text field may contain PII — see Residual Risks)

#### THREAT-013: No Code Signing of Agent Binary
- **Asset:** dlp-agent binary
- **Threat:** Attacker replaces the agent binary with a modified version and claims it was the original
- **Attack Vector:** Write access to the directory where the agent binary is installed
- **Impact:** Modified agent bypasses all DLP controls; no accountability for the modified binary
- **Mitigation:**
  - **Planned Phase 4** — code signing and binary integrity verification
  - **Status:** Not Mitigated (Phase 1–3)

---

### 3.4 Information Disclosure

#### THREAT-014: Audit Log Access
- **Asset:** Audit log file containing file access metadata
- **Threat:** Attacker reads the audit log to understand which sensitive files were accessed and by whom
- **Attack Vector:** Filesystem access to `C:\ProgramData\DLP\logs\audit.jsonl`
- **Impact:** Sensitive file access patterns are disclosed; security control effectiveness is reduced
- **Mitigation:**
  - Directory ACLs restrict read access to SYSTEM and Administrators
  - Log contains metadata only, not file content
  - **Status:** Implemented (ACL-based)

#### THREAT-015: dlp-admin Password Over Named Pipe
- **Asset:** dlp-admin password transmitted from UI to Agent
- **Threat:** Attacker with local access intercepts the plaintext password as it traverses the named pipe
- **Attack Vector:** Malicious code in the user session reads the named pipe or memory
- **Impact:** dlp-admin password is captured; service can be stopped; DLP enforcement is disabled
- **Mitigation:**
  - DPAPI encryption (`CryptProtectData`) applied by the UI before sending the password payload over Pipe 1
  - Agent impersonates the user session to decrypt with `CryptUnprotectData`; bcrypt hash comparison against `DLPAuthHash` is performed server-side
  - **Status:** Implemented — DPAPI unwrap wired in Batch 2 (`password_stop.rs::dpapi_unprotect()`); bcrypt verification performed after DPAPI unwrap

#### THREAT-016: Clipboard Data Disclosure
- **Asset:** Clipboard content being read and classified
- **Threat:** Clipboard data containing sensitive information (SSN, credit card) is read by the clipboard listener
- **Attack Vector:** Clipboard listener reads clipboard text via `GetClipboardData`; data is held in process memory
- **Impact:** Sensitive PII (SSN, credit card numbers) is temporarily held in agent process memory; could be dumped via memory inspection
- **Mitigation:**
  - Clipboard data is classified and immediately emitted as an audit event; it is not persistently stored
  - Process memory is protected by the process DACL
  - **Status:** Implemented (with memory inspection risk — inherent to any process that reads clipboard)

#### THREAT-017: Classification Metadata Leakage
- **Asset:** Classification attribute of files/directories
- **Threat:** Extended file attributes storing classification metadata are visible to any process with file read access
- **Attack Vector:** Standard user enumerates file metadata
- **Impact:** Reveals sensitivity of files; attacker can target high-sensitivity files
- **Mitigation:**
  - Classification is not stored in file metadata (NTFS alternate data streams or extended attributes are not used)
  - Classification is a policy rule attribute, not a file attribute
  - **Status:** Not Applicable — classification is not stored in filesystem metadata

#### THREAT-018: Policy Rules Disclosed
- **Asset:** ABAC policy rules
- **Threat:** Attacker reads `policies.json` to understand which files are protected and how
- **Attack Vector:** Read access to the policy file path
- **Impact:** Attacker can craft targeted attacks to bypass known policies
- **Mitigation:**
  - Policy file ACLs restrict read access to SYSTEM and Administrators
  - **Status:** Implemented (ACL-based)

#### THREAT-019: Cached Policy Decisions Exposed
- **Asset:** Policy decision cache (`cache.rs`)
- **Threat:** Attacker reads the in-memory or on-disk cache to understand past policy decisions
- **Attack Vector:** Memory dump of the agent process
- **Impact:** Past access patterns are disclosed; attacker can correlate file access with users
- **Mitigation:**
  - Cache is in-memory only; requires SYSTEM or process memory access
  - Process DACL restricts access to the agent process memory
  - **Status:** Implemented

---

### 3.5 Denial of Service

#### THREAT-020: Service Stop (Kill the DLP)
- **Asset:** dlp-agent availability
- **Threat:** Attacker stops the DLP agent to remove file interception
- **Attack Vector:** `sc stop` without password; or killing the agent process
- **Impact:** No DLP enforcement until service is restarted; 5-minute SCM auto-restart applies
- **Mitigation:**
  - `sc stop` requires dlp-admin password (bcrypt hash verification) — 3 attempts max
  - Process DACL prevents non-Admin from killing the agent
  - SCM auto-restart on crash: `sc.exe failure` recovery actions (Phase 1 config in `Manage-DlpAgentService.ps1`)
  - **Status:** Implemented

#### THREAT-021: Policy Engine Offline (No ABAC Decisions)
- **Asset:** Policy Engine availability
- **Threat:** Policy Engine becomes unreachable; all requests fall back to cache
- **Attack Vector:** Network disruption; Policy Engine process crash
- **Impact:** Offline mode activates; T3/T4 deny (fail-closed); T2/T1 allow (default-allow). T2/T1 files can be exfiltrated without ABAC evaluation during the outage.
- **Mitigation:**
  - Offline mode is the designed fallback, not a failure
  - `offline.rs::offline_decision()` applies fail-closed for T3/T4
  - T2/T1 allow during offline mode is a documented limitation
  - Heartbeat loop probes engine every 30 seconds; transitions back to online automatically
  - **Status:** Designed behavior (T2/T1 allow during offline is a risk; documented in SRS N-AVA-02)

#### THREAT-022: File Monitor Evasion (Direct Syscall Bypass)
- **Asset:** File system monitor (`notify` crate watcher)
- **Threat:** Attacker uses direct NTFS syscalls (e.g., `NtWriteFile`) that bypass `notify`'s `ReadDirectoryChangesW` subscription
- **Attack Vector:** Direct NTFS syscalls; kernel-level file access that does not go through the Windows object layer
- **Impact:** File operations are invisible to `notify`; no audit event; no blocking decision
- **Mitigation:**
  - `notify` monitors the NTFS volume change journal — most file operations are visible
  - Kernel-level minifilter driver (future phase) is the only complete mitigation
  - **Status:** Not Mitigated — `notify`/`ReadDirectoryChangesW` cannot cover direct syscall paths; requires minifilter (future phase)

#### THREAT-023: Disk Full (Audit Log Overflow)
- **Asset:** Audit log disk space
- **Threat:** Attacker writes enough data to fill the disk, causing audit log to fail or rotate excessively
- **Attack Vector:** High-volume file operations; malicious process generating many audit events
- **Impact:** Audit log stops writing; events are lost; disk fills; system instability
- **Mitigation:**
  - Log rotation at configurable size (default 50 MB per file, 9 generations)
  - Audit emission failure is logged but does not block file operations
  - **Status:** Implemented (rotation + failure isolation)

#### THREAT-024: Named Pipe DoS
- **Asset:** Named pipes (Pipe 1/2/3)
- **Threat:** Attacker opens many pipe connections to exhaust resources or block legitimate clients
- **Attack Vector:** Local code opens many pipe instances; exceeds `NUM_INSTANCES` limit
- **Impact:** Legitimate UI cannot connect to the agent
- **Mitigation:**
  - `NUM_INSTANCES = 4` per pipe; one per active session is sufficient
  - Pipe 1/2/3 connections are session-scoped; one per user session
  - SYSTEM-only ACL prevents non-admin processes from opening pipes
  - **Status:** Implemented (resource limit + ACL)

#### THREAT-025: Clipboard Listener Resource Exhaustion
- **Asset:** Clipboard listener thread
- **Threat:** Attacker copies extremely large data to the clipboard, overwhelming the listener
- **Attack Vector:** Clipboard write with multi-GB data
- **Impact:** Listener thread hangs or consumes excessive memory
- **Mitigation:**
  - `GetClipboardData(CF_UNICODETEXT)` is called only after a `WM_PASTE` or `WM_CLIPBOARDUPDATE` message; Windows clips the data at a reasonable limit
  - Classifier applies size limits before processing
  - **Status:** Partially Mitigated — Windows clipboard itself limits data; classifier adds size limits

---

### 3.6 Elevation of Privilege

#### THREAT-026: Service Account Privilege Abuse
- **Asset:** SYSTEM account (agent process)
- **Threat:** Attacker escapes a contained process and obtains SYSTEM privileges via the agent service
- **Attack Vector:** Exploit in any agent subsystem (file interception, MPR/SMB, clipboard, HTTP client)
- **Impact:** Attacker gains SYSTEM-level code execution on the endpoint
- **Mitigation:**
  - Agent runs as SYSTEM because it needs filesystem interception privileges; this is the minimum privilege for the required functionality
  - Process DACL prevents other users from interacting with the agent process
  - Agent has no unnecessary privileges beyond file system access, process creation, and AD/LDAP access
  - **Status:** Partially Mitigated — SYSTEM privilege is necessary; process DACL restricts access

#### THREAT-027: DLL Injection into Agent Process
- **Asset:** dlp-agent process
- **Threat:** Attacker injects a DLL into the agent process to intercept DLP decisions or suppress audit events
- **Attack Vector:** DLL search order hijacking; remote thread creation into the agent process
- **Impact:** Attacker could suppress audit events or bypass DLP decisions without detection
- **Mitigation:**
  - Process DACL prevents non-Admin from creating threads in the agent process
  - Phase 2: Process protection (code integrity, DLL load constraints)
  - **Status:** Partially Mitigated in Phase 1; DLL load hardening planned Phase 2

#### THREAT-028: DLL Injection into UI Process
- **Asset:** dlp-user-ui subprocess
- **Threat:** Attacker injects code into the UI subprocess to send fake `UserConfirmed` messages
- **Attack Vector:** Remote thread in the UI process
- **Impact:** Attacker can confirm blocked operations as the user
- **Mitigation:**
  - UI runs in the user's own session with user's own privileges; if the user's session is compromised, DLP is already ineffective
  - The `UserConfirmed` message only travels to the agent via Pipe 1; the agent's `RegisterSession` gate prevents arbitrary registration
  - **Status:** Not Mitigated (inherent: UI runs in user session)

#### THREAT-029: ABAC Policy Logic Error
- **Asset:** ABAC policy rules in `policies.json`
- **Threat:** Administrator misconfigures a policy rule, inadvertently allowing access to T4/T3 resources
- **Attack Vector:** Misconfiguration (not malicious)
- **Impact:** Unauthorised access to sensitive files
- **Mitigation:**
  - `policy_store.rs` validates policy structure on reload (empty ID, priority range)
  - No structural validation for policy logic correctness (a DENY rule can be accidentally disabled)
  - Policy change generates an audit event (F-AUD-09); deviation from expected policies can be detected by a monitoring rule
  - **Status:** Partially Mitigated — validation + audit; policy review process required

#### THREAT-030: Service Stop Without Password (Race Condition)
- **Asset:** Service stop flow
- **Threat:** Attacker exploits the 500ms polling loop in `service.rs::run_loop()` to race between `is_stop_confirmed()` checks
- **Attack Vector:** Precise timing to cause the service to stop without verified password
- **Impact:** Service stops without dlp-admin password verification
- **Mitigation:**
  - The password confirmation flag is set by `password_stop.rs::confirm_stop()` which is called only after successful bcrypt hash verification
  - The 500ms poll checks an atomic flag (`STOP_CONFIRMED: AtomicBool`); there is no race condition in this design
  - **Status:** Not a threat (no exploitable race condition)

---

## 4. Residual Risks

The following risks are **Not Mitigated** or **Planned** in a future phase:

| Risk | Threat Class | Impact | Status |
|---|---|---|---|
| File monitor can be interfered with by admin | Tampering / DoS | File interception blind | **Not Mitigated** — requires kernel-level or EDR control |
| DLL injection into agent process | Elevation of Privilege | Full DLP bypass | **Planned Phase 2** — DLL load hardening |
| Agent binary update mechanism is unauthenticated | Tampering / Spoofing | Binary replacement attack | **Planned Phase 4** — code signing |
| ABAC policy store has no integrity check (hash/checksum) | Tampering | Policy file tampering goes undetected | **Planned Phase 5** — policy store integrity via hash |
| SIEM relay credentials in dlp-server memory | Information Disclosure | SIEM token theft | **Planned Phase 5** — HSM / Azure Key Vault |
| Override justification free-text may contain PII | Information Disclosure | PII in audit log | **Not Mitigated** — admin process guidance required |
| UI process DLL injection leads to fake UserConfirmed | Elevation of Privilege | Blocked operations confirmed without user consent | **Not Mitigated** — inherent to user-session UI |
| Policy Engine certificate spoofing | Spoofing | Forged ABAC decisions | **Planned Phase 5** — certificate pinning |
| AD service account credential theft from LSASS (SYSTEM context) | Spoofing | ABAC attribute queries via Policy Engine LDAPS channel | **Not Mitigated** — dlp-admin credential (bcrypt hash) is not in LSASS; AD service account still at risk |
| Physical access: cold-boot attack on endpoint | Information Disclosure | Memory decryption key extracted | **Out of Scope** — physical security domain |

---

## 5. Security Controls Summary

### 5.1 Implemented Controls (Phase 1)

| Control | Threat Addressed | Component | STRIDE |
|---|---|---|---|
| SYSTEM-only ACL on named pipes | UI impersonation | `pipe1.rs`, `pipe2.rs`, `pipe3.rs` | Spoofing |
| DPAPI encryption of password payload | Password sniffing over pipe | `stop_password.rs`, `password_stop.rs` | Information Disclosure |
| CryptUnprotectData DPAPI unwrap | Password bypass | `password_stop.rs::dpapi_unprotect()` | Information Disclosure |
| RegisterSession as first-pipe message | Pipe message injection | `pipe1.rs::handle_client()` | Spoofing |
| Process DACL (DENY non-admin terminate/read/write) | Process kill/tamper | `protection.rs` | Spoofing, Tampering, Elevation |
| Single-instance anonymous mutex | Duplicate agent instances | `service.rs::acquire_instance_mutex()` | Elevation |
| Password challenge on sc stop | Unauthorised service stop | `password_stop.rs`, `pipe1.rs` | Elevation |
| 3-attempt limit on password challenge | Brute-force password | `password_stop.rs::MAX_ATTEMPTS` | Elevation |
| bcrypt hash comparison for credential verification | Local credential exposure | `password_stop.rs::verify_credentials()` | Spoofing |
| Append-only audit log | Audit log tampering | `audit_emitter.rs` | Tampering |
| JSONL log rotation | Disk exhaustion | `audit_emitter.rs::rotate()` | DoS |
| Log rotation (9 generations, 50MB each) | Disk exhaustion | `audit_emitter.rs::MAX_ROTATED_FILES` | DoS |
| Hot-reload policy validation | Policy tampering | `policy_store.rs::validate_policy()` | Tampering |
| Fail-closed for T3/T4 on cache miss | Engine offline bypass | `offline.rs::offline_decision()` | DoS |
| Heartbeat loop (30s probe) | Permanent offline mode | `offline.rs::heartbeat_loop()` | DoS |
| File monitor via `notify` crate | File access detection | `interception/file_monitor.rs` | Tampering (detective) |
| Clipboard classification | PII clipboard exfiltration | `clipboard/listener.rs`, `clipboard/classifier.rs` | Information Disclosure |
| Device trust + network location ABAC | Contextual access control | `abac.rs`, `engine.rs` | Elevation |
| Identity resolution via SMB impersonation | SMB session hijacking | `identity.rs` | Spoofing |
| USB device notifications | Removable media exfiltration | `detection/usb.rs` | DoS |
| SMB share MPR polling (`WNetOpenEnumW`) | Network share exfiltration | `detection/network_share.rs` | DoS |
| WTSQueryUserToken UI spawning | Multi-session UI support | `ui_spawner.rs` | Elevation |
| Mutual health monitor (Pipe 2/3) | Zombie UI / hung agent | `health_monitor.rs` | DoS |

### 5.2 Planned Controls

| Control | Phase | Threats Addressed |
|---|---|---|
| Code signing + binary integrity verification | Phase 4 | Binary tampering, code injection |
| DLL load hardening | Phase 2 | DLL injection |
| Certificate pinning (mTLS) | Phase 5 | Policy Engine certificate spoofing |
| SHA-256 hash chain for audit logs | Phase 5 | Audit log tampering |
| HSM / Azure Key Vault for secrets | Phase 5 | SIEM token theft, key disclosure |
| dlp-server (SIEM relay, append-only audit store) | Phase 5 | Audit log tampering, persistence |
| TOTP + JWT for admin auth (dlp-server) | Phase 5 | Admin action non-repudiation, credential theft |
| Policy store integrity (signed policies) | Phase 5 | Policy file tampering |
