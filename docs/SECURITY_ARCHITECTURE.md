# Security Architecture

**Document Version:** 1.0
**Date:** 2026-03-31
**Status:** Draft
**Author:** Principal Security Architect

---

> **Companion documents:**
> - [THREAT_MODEL.md](./THREAT_MODEL.md) — STRIDE threat analysis, attack vectors, mitigations, and residual risks referenced throughout this document.
> - [SRS.md](./SRS.md) — Full requirements including F-\*, N-\* functional and non-functional requirements.
> - [ISO27001_MAPPING.md](./ISO27001_MAPPING.md) — ISO 27001:2022 control mappings.
> - [AUDIT_LOGGING.md](./AUDIT_LOGGING.md) — Audit event schema, SIEM relay, and integrity controls.

---

## Table of Contents

1. [Security Design Principles](#1-security-design-principles)
2. [Trust Boundaries](#2-trust-boundaries)
3. [NTFS as Baseline Access Control](#3-ntfs-as-baseline-access-control)
4. [Critical Rule Enforcement](#4-critical-rule-enforcement)
5. [T4/T3 Fail-Closed Guarantees](#5-t4t3-fail-closed-guarantees)
6. [Secrets Management](#6-secrets-management)
7. [Named Pipe Security](#7-named-pipe-security)
8. [Windows Service Hardening](#8-windows-service-hardening)
9. [Attack Surface and Threat Model Summary](#9-attack-surface-and-threat-model-summary)
10. [Logging as a Security Control](#10-logging-as-a-security-control)
11. [ISO 27001:2022 Control Mapping](#11-iso-270012022-control-mapping)

---

## 1. Security Design Principles

The DLP system enforces five foundational security principles across all layers. These principles are mandatory and apply to every design decision, implementation choice, and operational procedure.

### 1.1 Least Privilege

**Principle:** Every principal — user, process, and service — is granted only the minimum permissions necessary to perform its authorized function.

**Implementation:**

| Principal | Privilege Scope | Rationale |
|---|---|---|
| `dlp-agent` (Windows Service) | Runs as `SYSTEM` (LocalSystem); process DACL denies terminate/read/write to Authenticated Users; Administrators get explicit Allow | SYSTEM required for `SeSecurityPrivilege` to set process DACL; no broader privilege needed |
| `dlp-user-ui` (iced subprocess) | Runs as the interactive logged-in user; no elevated privileges; SYSTEM-only named pipe ACLs prevent cross-session access | UI is a userland process; cannot perform privileged operations |
| `dlp-server` | Runs as a dedicated AD service account (non-SYSTEM); LDAPS bind uses the AD service account exclusively for ABAC attribute lookups | Principle of least privilege: the server does not need SYSTEM |
| AD service account (`CN=dlp-svc,...`) | Read-only LDAP queries to AD; used only by dlp-server for ABAC attribute lookups; no domain join or replication rights | Limits exposure if the service account is compromised |
| `dlp-admin` (DLP credential) | Credential stored as bcrypt hash at `HKLM\SOFTWARE\DLP\Agent\Credentials\DLPAuthHash`; verified by bcrypt comparison at service stop; not an AD account | Not stored in AD; no LDAPS verification |

**Audit evidence:** `F-ADM-06` (admin MFA), `N-SEC-03` (SYSTEM account), `N-SEC-11` (process DACL), `F-ADM-11` (secure service stop with password challenge).

### 1.2 Default Deny

**Principle:** When no policy explicitly allows an action on sensitive data, the action is denied by default.

**Implementation:**

- **ABAC layer:** The dlp-server evaluates rules in priority order (first-match wins). No catch-all ALLOW rule is generated for T3/T4 resources. If no policy matches a T3 or T4 resource, the default decision is DENY.
- **Offline mode:** On cache miss, `offline.rs` returns `cache::fail_closed_response()` for T3/T4 resources (see §5).
- **dlp-server:** Exception/override approvals are explicit, time-limited, and audited. No override is permanent.
- **dlp-server:** The audit store exposes no update or delete API (`N-SRV-06`). Audit records are append-only.

### 1.3 Zero Trust

**Principle:** Assume breach. Never trust any request or principal without explicit verification, regardless of network location.

**Implementation:**

| Trust Signal | Verification Mechanism |
|---|---|
| User identity | AD group membership queried via LDAPS at each policy evaluation |
| Device trust | AD `dlpDeviceTrust` attribute queried per request; cached with 5-minute TTL |
| Network location | AD `dlpNetworkLocation` attribute used as ABAC environment attribute |
| Agent authenticity | mTLS: dlp-server verifies agent TLS certificate; agent verifies engine certificate (`N-SEC-08`) |
| Admin identity | TOTP + JWT (Phase 5); bcrypt hash verification for service stop (Phase 1) |
| Named pipe client | UI must send `RegisterSession` message as first frame on Pipe 1; sessions are tracked by Windows session ID |

**Verification chain:**
```
User action → SMB impersonation identity resolution (identity.rs)
           → AD LDAP attribute lookup (ad_client.rs, LDAPS)
           → ABAC policy evaluation
           → Agent enforces ABAC decision
           → Audit event emitted
```

The `identity.rs` module (`F-AGT-19`) resolves the actual remote user's SID from the SMB impersonation context using `QuerySecurityContextToken` and `ImpersonateSelf + GetTokenInformation`. If no impersonation context exists (local process), the process token is used. This prevents a compromised local service account from attributing its actions to another user.

### 1.4 Defense in Depth

**Principle:** Multiple independent controls protect every sensitive asset. No single control failure results in data exfiltration.

The defense-in-depth model has five layers:

```
┌──────────────────────────────────────────────────────┐
│  Layer 5: DLP Admin Audit Trail (dlp-server, Phase 5) │  Who changed what, when
├──────────────────────────────────────────────────────┤
│  Layer 4: Alert & Response (DENY_WITH_ALERT)         │  Real-time SOC notification
├──────────────────────────────────────────────────────┤
│  Layer 3: ABAC Policy Enforcement (dlp-server)         │  Fine-grained runtime veto
├──────────────────────────────────────────────────────┤
│  Layer 2: NTFS ACLs (baseline, file server)           │  Coarse-grained OS-level gate
├──────────────────────────────────────────────────────┤
│  Layer 1: Identity (Active Directory)                 │  Who you are; device posture
└──────────────────────────────────────────────────────┘
```

Each layer is independently capable of blocking data exfiltration. The ABAC engine provides the fine-grained veto over NTFS, and ABAC decisions cannot be bypassed by NTFS ACL grants.

### 1.5 Explicit Auditability

**Principle:** Every security-relevant action is logged in an immutable, tamper-evident record.

Every ABAC decision, every block event, every admin action, and every failed authentication attempt generates a structured JSON audit event. Events flow to `dlp-server` (Phase 5) which writes them to an append-only store before relaying to SIEM. No delete or update API is exposed. See [AUDIT_LOGGING.md](./AUDIT_LOGGING.md) for the full event schema.

**What must NEVER be logged (per [AUDIT_LOGGING.md](./AUDIT_LOGGING.md)):**

- File content (payload) — only metadata is logged
- Passwords, tokens, or session keys
- PII beyond the minimum necessary (user_sid and user_name are included for accountability)
- Override justification text beyond the policy requirement (free-text input may contain PII; this is a known risk documented in [THREAT_MODEL.md](./THREAT_MODEL.md))

---

## 2. Trust Boundaries

### 2.1 Trust Zone Diagram

```
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                        ENTERPRISE NETWORK (Corporate LAN)              ║
  ║                                                                       ║
  ║  ┌───────────────────────────────────────────────────────────────┐    ║
  ║  │              IDENTITY TRUST ZONE — Active Directory           │    ║
  ║  │   Domain Controller (LDAPS :636)                              │    ║
  ║  │   Source of: user SIDs, group membership, device trust,       │    ║
  ║  │             network location                                  │    ║
  ║  └──────────────────────────┬──────────────────────────────────┘    ║
  ║                               │ LDAPS                                 ║
  ║                               │ TLS 1.3 + certificate verify           ║
  ║  ┌──────────────────────────▼──────────────────────────────────┐    ║
  ║  │           POLICY TRUST ZONE — DMZ / Isolated Subnet           │    ║
  ║  │   dlp-server (HTTPS :9090) — Rust, stateless replicas        │    ║
  ║  │   Evaluates ABAC rules; queries AD; returns ALLOW/DENY        │    ║
  ║  └──────────────────────────┬──────────────────────────────────┘    ║
  ║                               │ HTTPS / mTLS                         ║
  ║  ════════════════════════════╪══════════════════════════════════════ ║
  ║           UNTRUSTED ZONE     ║   ENDPOINT TRUST BOUNDARY             ║
  ║  ┌───────────────────────────▼──────────────────────────────────┐    ║
  ║  │              ENDPOINT — dlp-agent (SYSTEM)                  │    ║
  ║  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────┐  │    ║
  ║  │  │ notify/     │  │ MPR         │  │ Named pipes (×3)  │  │    ║
  ║  │  │ ReadDirChg  │  │ WNetOpen    │  │ DLPCommand         │  │    ║
  ║  │  │ CreateFile  │  │ Enum        │  │ DLPEventAgent2UI   │  │    ║
  ║  │  │ WriteFile   │  │ (30s poll)  │  │ DLPEventUI2Agent   │  │    ║
  ║  │  │ DeleteFile  │  │             │  │ (SYSTEM-only ACL)  │  │    ║
  ║  │  └─────────────┘  └─────────────┘  └──────────────────────┘  │    ║
  ║  │           ↓                ↓                                 │    ║
  ║  │  ┌─────────────────────────────────────────────────────────┐│    ║
  ║  │  │     dlp-user-ui (iced subprocess, interactive user)     ││    ║
  ║  │  │  Toast notifications · Override dialogs · Clipboard     ││    ║
  ║  │  │  System tray · sc stop password dialog                  ││    ║
  ║  │  └─────────────────────────────────────────────────────────┘│    ║
  ║  └──────────────────────────┬──────────────────────────────────┘    ║
  ║                               │ HTTPS (Phase 5: via dlp-server)     ║
  ║  ════════════════════════════╪══════════════════════════════════════ ║
  ║                               │                                     ║
  ║  ┌───────────────────────────▼──────────────────────────────────┐    ║
  ║  │     MANAGEMENT ZONE (Phase 5) — dlp-server                  │    ║
  ║  │  Agent registry · Audit store (append-only) · SIEM relay     │    ║
  ║  │  Alert router · Policy sync · Admin auth (TOTP+JWT)          │    ║
  ║  └───────────────────────────────────────────────────────────────┘    ║
  ╚═══════════════════════════════════════════════════════════════════════╝
```

### 2.2 Zone Descriptions

| Zone | Components | Trust Level | Boundary Controls |
|---|---|---|---|
| **Identity Trust Zone** | AD Domain Controllers | Highest | LDAPS (TLS 1.3); service account read-only; no interactive logon |
| **Policy Trust Zone** | dlp-server replicas | High | Network segmentation (DMZ); mTLS agents → engine; no inbound from general network |
| **Endpoint** | dlp-agent, dlp-user-ui | Medium (assume compromised) | Named pipe ACLs; process DACL; DPAPI; no outbound except to dlp-server |
| **Management Zone** | dlp-server | High | TLS 1.3; JWT admin auth; SIEM credentials held only here |

### 2.3 Cross-Boundary Flows

| Flow | Direction | Protocol | Auth | Threat (see [THREAT_MODEL.md](./THREAT_MODEL.md)) |
|---|---|---|---|---|
| Agent → dlp-server | Outbound | HTTPS / TLS 1.3 + mTLS | Server cert verify + client cert | Spoofing the engine; tampering the decision |
| dlp-server → AD | Outbound | LDAPS :636 | TLS + service account bind | Credential theft from engine host |
| Agent → dlp-server (Phase 5) | Outbound | HTTPS / TLS 1.3 | mTLS or signed JWT | Tampering audit stream; impersonating agent |
| dlp-server → SIEM | Outbound | HTTPS / TLS 1.3 | HEC token / API key | Credential sprawl (SIEM token in agent — mitigated by relay model) |
| Admin → dlp-server | Inbound | HTTPS | TOTP + JWT (Phase 5) | Admin credential theft |
| Agent ↔ UI (Pipe 1/2/3) | Local only | Named pipe / DPAPI | SYSTEM-only ACL | Pipe impersonation; UI → admin password over pipe |

---

## 3. NTFS as Baseline Access Control

### 3.1 Role of NTFS in the Dual-Layer Model

NTFS ACLs provide **coarse-grained, persistent baseline enforcement** at the operating system level. They are the first gate a file access must pass.

**What NTFS does well:**
- Enforces read/write/delete permissions at the filesystem level for all processes
- Permissions persist across reboots and survive application crashes
- Integrated with AD: ACL entries reference AD Security Groups and user SIDs directly
- Audited by Windows Security Event Log independently of the DLP agent

**What NTFS cannot do alone:**
- Enforce context-aware decisions (time of day, network location, device trust)
- Respond dynamically to policy changes without ACL modification
- Block clipboard operations or classify content
- Enforce deny rules that override allow grants from nested group membership

### 3.2 Baseline ACL Configuration

On every NTFS volume hosting sensitive data, the DLP administrator configures:

| Classification | NTFS Permission | ABAC Role |
|---|---|---|
| **T4 Restricted** | `CREATOR OWNER` and `Domain DLP-T4-Readers` — Read; `Domain DLP-Admins` — Full Control | Deny everyone except owner unless explicit ABAC override |
| **T3 Confidential** | `Domain DLP-T3-Users` — Read/Write; deny USB and SMB to non-managed devices via ABAC | ABAC provides the veto for untrusted devices |
| **T2 Internal** | `Domain Users` — Read/Write | ABAC logs all access; no block at T2 |
| **T1 Public** | `Everyone` — Read | ABAC not invoked for T1 reads |

The `CREATOR OWNER` principle ensures that the file creator always has at least some access, which ABAC can then restrict further for T4 files (T4 rule: owner may READ but not COPY/DELETE unless ABAC explicitly allows).

### 3.3 ABAC as the Fine-Grained Veto

ABAC does not replace NTFS — it operates as a **supervisory layer above NTFS**. The dlp-server evaluates the full context of each access request and can **override an NTFS ALLOW** with a DENY. This is the Critical Rule.

The ABAC layer enforces:

1. **Temporal controls** — deny file copies outside business hours for T3
2. **Device trust controls** — deny USB writes of T3 content on unmanaged devices even if NTFS grants full control
3. **Network location controls** — deny uploads to non-corporate SMB destinations even if the user has NTFS write permission
4. **Action-specific controls** — allow READ but deny COPY for T4 files
5. **Override workflows** — allow a temporary ALLOW_WITH_LOG after admin-approved justification

### 3.4 Enforcement Order in Code

In `dlp-agent/src/interception/file_monitor.rs`, the interception hook:

1. Resolves caller identity via `identity.rs` (SMB impersonation or process token)
2. Constructs an `EvaluateRequest` (subject, resource, environment, action)
3. Calls `engine_client.rs` → dlp-server
4. Applies the response decision:
   - `DENY` or `DENY_WITH_ALERT`: blocks the operation, emits `BLOCK` audit event
   - `ALLOW` or `ALLOW_WITH_LOG`: permits the operation (subject to NTFS), emits `ACCESS` audit event

The **NTFS check always happens first at the OS level** — the process cannot open a file if NTFS denies it. ABAC then makes the **second, context-aware decision** that may deny what NTFS allowed. The final result is always `MIN(NTFS_decision, ABAC_decision)`.

---

## 4. Critical Rule Enforcement

### 4.1 Statement of the Rule

> **NTFS ALLOW + ABAC DENY = DENY**
> If NTFS permits an operation but dlp-server (ABAC evaluator) returns DENY or DENY_WITH_ALERT, the dlp-agent **blocks the operation**.

This rule is the cornerstone of the dual-layer model. Without it, any user with sufficient NTFS permissions could exfiltrate data by simply copying it to a USB device or an unauthorized SMB share — NTFS knows nothing about device trust or network location.

### 4.2 Where the Rule is Enforced

The Critical Rule is enforced at two decision points:

**Decision Point 1 — dlp-server (`dlp-server/src/engine.rs`)**

The ABAC engine receives an `EvaluateRequest` from the agent and returns an `EvaluateResponse` with a `Decision` enum value. The engine evaluates policies in priority order (first-match). The decision is:

```rust
pub enum Decision {
    ALLOW,           // Policy explicitly allows
    ALLOW_WITH_LOG,  // Policy allows and logs
    DENY,            // Policy explicitly denies
    DENY_WITH_ALERT, // Policy denies and triggers alert
}
```

For a DENY or DENY_WITH_ALERT, the engine returns the decision and the `matched_policy_id`. The agent is responsible for enforcing this decision.

**Decision Point 2 — dlp-agent (`dlp-agent/src/engine_client.rs` + interception layer)**

After receiving the dlp-server response, the interception hook in `file_monitor.rs` checks the decision:

```rust
// Pseudocode — actual implementation in file_monitor.rs
let response = engine_client.evaluate(&request).await;
match response.decision {
    Decision::DENY | Decision::DENY_WITH_ALERT => {
        block_operation();
        emit_audit_event(AuditEvent { event_type: BLOCK, ... });
        if response.decision == Decision::DENY_WITH_ALERT {
            trigger_alert(response.matched_policy_id);
        }
    }
    Decision::ALLOW | Decision::ALLOW_WITH_LOG => {
        permit_operation();
        emit_audit_event(AuditEvent { event_type: ACCESS, ... });
    }
}
```

**Decision Point 3 — Offline Mode (`dlp-agent/src/offline.rs`)**

When the dlp-server is unreachable, `offline.rs::offline_decision()` applies the fail-closed response for T3/T4 (see §5). The Critical Rule is preserved in offline mode: if the cache returns a DENY for a sensitive resource, the operation is blocked.

### 4.3 Fail-Safe Behavior

The system is designed to fail safe. If the agent crashes, crashesafe, or is killed:

- The interception hooks (if still active) will fail to contact the agent and the default deny applies
- The UI subprocess detects loss of the agent connection (15-second timeout on Pipe 3) and terminates
- The agent service cannot be stopped without the dlp-admin password (F-SVC-10 through F-SVC-12)
- The process DACL prevents all non-Administrator principals from terminating or tampering with the agent or UI process

---

## 5. T4/T3 Fail-Closed Guarantees

### 5.1 Threat Model Assumption

The fail-closed guarantee addresses two scenarios:
1. **AD outage:** The agent cannot query group membership or device trust attributes
2. **dlp-server unreachable:** The agent cannot receive ABAC decisions

In both scenarios, the system must default to **DENY** for sensitive resources rather than silently allowing access.

### 5.2 AD Outage: dlp-server Behavior

`dlp-server/src/ad_client.rs` caches all AD lookups with a 5-minute TTL. If AD is unreachable during a cache miss:

1. The LDAP query returns `AdClientError`
2. The dlp-server logs the error and returns a DENY decision for any request where AD attributes are required
3. The decision is accompanied by an audit event indicating the AD lookup failure
4. Once AD is restored, the next request triggers a fresh cache entry

The AD service account has no privilege to modify AD objects — even if the account is compromised during an outage, it cannot alter group memberships or device trust attributes.

### 5.3 dlp-server Unreachable: Offline Mode

`dlp-agent/src/offline.rs` implements a three-tier offline decision model:

| Resource Classification | Cache Hit | Cache Miss |
|---|---|---|
| **T4** | Cached decision enforced | **DENY** (fail-closed) |
| **T3** | Cached decision enforced | **DENY** (fail-closed) |
| **T2** | Cached decision enforced | ALLOW (default-allow for non-sensitive) |
| **T1** | Cached decision enforced | ALLOW (default-allow for public) |

The offline mode logic:

```rust
// dlp-agent/src/offline.rs — offline_decision()
if let Some(cached) = cache.get(&resource.path, &subject.user_sid) {
    return cached;  // Use cached decision
}
// Cache miss — fail closed for T3/T4
cache::fail_closed_response(classification)
```

This is hard-coded behavior, not configurable — there is no registry setting or config file option to change the fail-closed default. An administrator cannot accidentally disable fail-closed for T4.

### 5.4 Heartbeat Loop

`offline.rs::heartbeat_loop()` probes the dlp-server every 30 seconds when offline. On successful probe, the agent transitions back to online mode and resumes live ABAC evaluation. The transition is logged as an audit event (`SERVICE_STOP_FAILED` family — specifically a transition event).

### 5.5 Guaranteed Properties

The following properties hold even in offline/AD-outage scenarios:

| Property | Mechanism | Evidence |
|---|---|---|
| T4 DENY on cache miss | Hard-coded `cache::fail_closed_response(Classification::T4)` | `offline.rs` line 131 |
| T3 DENY on cache miss | Hard-coded `cache::fail_closed_response(Classification::T3)` | `offline.rs` line 131 |
| No config toggle to disable fail-closed | Fail-closed is a compile-time guarantee in `cache.rs` | `cache.rs` — no feature flag |
| Agent cannot be stopped by non-admin during AD outage | Password challenge over Pipe 1 still works (UI runs in user session) | `service.rs` + `pipe1.rs` |
| Audit events continue to be written locally | Phase 1: local append-only JSON; Phase 5: dlp-server relay | `audit_emitter.rs` |

---

## 6. Secrets Management

### 6.1 Where Secrets Live

All secrets are stored outside source code, in environment variables or `.env` files. The `.env` file is declared in `.gitignore`.

| Secret | Storage Location | Access |
|---|---|---|
| dlp-server TLS client certificate + key | `.env` (`DLP_ENGINE_CERT_PATH`, `DLP_ENGINE_KEY_PATH`) | Read by `dlp-agent` at startup via `dotenvy` |
| AD service account password (LDAPS bind) | `.env` (`DLP_AD_BIND_PASSWORD`) | Read by `dlp-server` at startup via `dotenvy` |
| dlp-admin password | Not stored; verified via bcrypt hash comparison at service stop | Never persisted; verified in memory |
| SIEM HEC token | `.env` (`DLP_SIEM_HEC_TOKEN`) — Phase 5 only | Stored in `dlp-server`; agents never see SIEM credentials |
| dlp-server JWT signing key | Generated at startup; stored in memory only (Phase 5) | Not persisted; no secret file |
| TOTP shared secret | `.env` (`DLP_TOTP_SECRET`) — Phase 5 only | Read by `dlp-server` at startup; stored encrypted in memory |

### 6.2 DPAPI Usage

**Purpose:** DPAPI protects sensitive data that must be exchanged between processes running in different security contexts (Agent ↔ UI) over named pipes.

**Mechanism:** The SRS §6.2 specifies that named pipe traffic uses `CRYPTUSERPROTECTIVE` scope:

- **UI → Agent:** Before transmitting sensitive data (e.g., the dlp-admin password over Pipe 1), the UI calls `CryptProtectData`. The DPAPI encryption is scoped to the current Windows user — only processes running as the same user can decrypt.
- **Agent:** On receipt, `CryptUnprotectData` decrypts the payload. The service (running as SYSTEM) can decrypt because it impersonates the interactive user's token during the pipe read.

**Scope limitation:** DPAPI with `CRYPTUSERPROTECTIVE` does NOT protect data across user sessions. Since the UI runs in the interactive user's session and the Agent runs as SYSTEM, the Agent must impersonate the user to decrypt. This is achieved by the Agent using the session context established during `CreateProcessAsUser`.

**Limitation:** If the endpoint is compromised by malware running in the same user session, DPAPI does not provide protection — the malware can call `CryptUnprotectData` as the same user. DPAPI protects against offline disk attacks and credential-theft from memory in other sessions, but not against session-local code execution.

**Alternative considered:** Hardware-attested key storage (HSM) would provide stronger protection but requires hardware deployment. This is a **planned Phase 5 enhancement**.

### 6.3 LDAPS Certificates

The `ad_client.rs` connects to AD over LDAPS on port 636 by default. TLS certificate verification is enforced:

```rust
// dlp-server/src/ad_client.rs
let mut ldap = LdapConn::new(&url)  // url must be ldaps://...
    .map_err(|e| AdClientError::LdapInitError(e.to_string()))?;
```

The `escape_filter()` function (line 342) prevents LDAP injection by escaping special characters in user-supplied SID values before embedding them in LDAP filter strings. No untrusted input is ever passed directly to the LDAP query.

### 6.4 No Secrets in Logs

`tracing` structured logging is configured to never log sensitive fields. The `AuditEvent` schema explicitly excludes file content. No `dbg!()` macros or `println!()` statements involving credentials are permitted — this is enforced by the code review checklist and `cargo clippy`.

---

## 7. Named Pipe Security

### 7.1 Pipe Overview

Three Windows named pipes connect the dlp-agent (SYSTEM process) with the dlp-user-ui (interactive user process):

| Pipe | Name | Mode | Direction | Security |
|---|---|---|---|---|
| Pipe 1 | `\\.\pipe\DLPCommand` | Message-mode duplex | 2-way request/response | SYSTEM-only ACL |
| Pipe 2 | `\\.\pipe\DLPEventAgent2UI` | Message-mode | Agent → UI, fire-and-forget | SYSTEM-only ACL |
| Pipe 3 | `\\.\pipe\DLPEventUI2Agent` | Message-mode | UI → Agent, fire-and-forget | SYSTEM-only ACL |

### 7.2 Pipe ACL Configuration

The `CreateNamedPipeW` call in `pipe1.rs` (line 92–102) uses `None` for the security descriptor, which applies the **default security descriptor for the pipe creator's token**. Since the Agent runs as SYSTEM, the default security descriptor grants:

- `SYSTEM` — full access (read, write, create, delete)
- `Administrators` — full access
- `Everyone` — **no access** by default on SYSTEM-created pipes

This means **only processes running as SYSTEM or Administrators** can connect to the pipes. The interactive user (who runs the UI) does **not** have direct access to these pipes. The Agent must use `ImpersonateNamedPipeClient` or another impersonation mechanism to act on behalf of the UI.

### 7.3 Session Registration Gate

`pipe1.rs::handle_client()` (line 114) implements a critical security control: **the first message from a connecting client must be `RegisterSession`** with a valid session ID. If the first message is anything else or fails to deserialize, the pipe is disconnected immediately:

```rust
// dlp-agent/src/ipc/pipe1.rs — handle_client()
let msg: Pipe1UiMsg = serde_json::from_slice(&frame)?;
let Pipe1UiMsg::RegisterSession { session_id } = msg else {
    error!("Pipe 1: first message must be RegisterSession");
    return cleanup_pipe(pipe);  // Reject — no further processing
};
```

This prevents a malicious process from sending crafted pipe messages without first being acknowledged by the Agent's session registration protocol.

### 7.4 DPAPI Encryption of Pipe Payloads

The `PASSWORD_SUBMIT` message from the UI to the Agent contains the dlp-admin password. Per SRS §6.2 and this document §6.2, this payload is DPAPI-encrypted (`CRYPTUSERPROTECTIVE`) before transmission. The Agent calls `CryptUnprotectData` to decrypt.

**Critical:** The password is never transmitted in plaintext over the pipe, never logged, and never stored. After bcrypt hash comparison, the password bytes are zeroized in memory.

### 7.5 Pipe Health Monitoring

`health_monitor.rs` (F-SVC-04, F-SVC-08) implements mutual liveness monitoring:
- Agent sends `HEALTH_PING` over Pipe 2 every 5 seconds
- UI sends `HEALTH_PONG` over Pipe 3 every 5 seconds
- 15-second timeout triggers process termination and respawn

This prevents a zombie UI from holding an open pipe connection indefinitely and prevents a compromised UI from blocking the pipe server.

### 7.6 Threat Coverage (Named Pipes)

| Threat | Vector | Mitigation | Status |
|---|---|---|---|
| UI impersonation via pipe | Attacker spawns fake UI process | SYSTEM-only pipe ACL; session registration | Implemented |
| Man-in-the-middle on pipe | Attacker intercepts pipe I/O | SYSTEM-only ACL; DPAPI encryption | Implemented |
| Admin password sniffing | Malicious process reads Pipe 1 | DPAPI encryption; no plaintext | Implemented |
| Pipe name enumeration | Attacker guesses pipe names | Not mitigable; not a real threat (local-only) | N/A |
| Denial of service via pipe flood | Attacker opens many pipe connections | Single session per user; Pipe 1: 4 instances max | Implemented |

See [THREAT_MODEL.md](./THREAT_MODEL.md) §4 (Information Disclosure) and §5 (Denial of Service) for the full threat analysis.

---

## 8. Windows Service Hardening

### 8.1 Service Configuration

The dlp-agent is registered with the Windows Service Control Manager as:

```cmd
sc create dlp-agent type= own start= auto
```

- `type= own`: The service runs in its own process (not svchost)
- `start= auto`: Automatic start on Windows boot, before any user logs in
- `type= own` ensures the agent process is isolated from other services

### 8.2 Single-Instance Enforcement

`service.rs::acquire_instance_mutex()` uses an anonymous process-scoped mutex. Before entering the run loop it attempts `try_lock()` — if a second instance is already running, lock acquisition fails and the second instance exits cleanly. This prevents duplicate agents from creating conflicting policies or double-counting events.

### 8.3 Process DACL — protection.rs

`dlp-agent/src/protection.rs` applies a hardening DACL to both the Agent process and every UI subprocess immediately after creation.

**ACE entries applied:**

| Trustee | Access Mode | Mask |
|---|---|---|
| `Authenticated Users` (S-1-5-11) | **DENY** | `PROCESS_TERMINATE \| PROCESS_CREATE_THREAD \| PROCESS_VM_OPERATION \| PROCESS_VM_READ \| PROCESS_VM_WRITE` |
| `LocalSystem` (S-1-5-18) | ALLOW | `PROCESS_ALL_ACCESS` |
| `Builtin\Administrators` (S-1-5-32-544) | ALLOW | `PROCESS_ALL_ACCESS` |

The DENY ACE is set with `INHERIT_ONLY_ACE` + `OBJECT_INHERIT_ACE`, meaning the DENY applies to child processes spawned by the Agent/UI (i.e., it affects what others can do to the Agent/UI, not what the Agent/UI can do to itself).

**Effect:**
- Standard users cannot terminate the Agent via Task Manager, Process Explorer, or `taskkill`
- Non-dlp-admin Administrators cannot terminate the Agent
- Only `SYSTEM` or Administrators can terminate; dlp-admin password (bcrypt) required for service stop
- The Agent and UI can still terminate their own child processes (e.g., when respawning the UI)

**Privilege requirement:** Setting a DENY ACE on a process requires `SeSecurityPrivilege`. The service runs as LocalSystem, which holds this privilege automatically.

### 8.4 No Interactive Desktop Interaction

The Agent service:
- Does **not** create or interact with any desktop window
- Does **not** run a message pump for GUI events
- Communicates with the user desktop **only** through the iced UI subprocess, which runs in the interactive user session via `CreateProcessAsUser`

This separation prevents the service from being manipulated through UI automation tools running in the user's session.

### 8.5 Service Control Handler

`service.rs::service_control_handler()` (line 190) handles three control events:

| Control | Behavior |
|---|---|
| `STOP` | Reports `StopPending` to SCM with 120 s `wait_hint` via global `SCM_HANDLE`; calls `password_stop::initiate_stop()` to trigger the password dialog; on cancel/failure `revert_stop()` reports `Running` back to SCM |
| `PAUSE` | Transitions to Paused; interception may pause |
| `CONTINUE` | Transitions back to Running |
| `INTERROGATE` | No-op; SCM reads current status via the status handle |

The `STOP` control does **not** immediately stop the service. The control handler reports `StopPending` with a 120-second `wait_hint` directly to the SCM via a global `OnceLock<ServiceStatusHandle>` (`SCM_HANDLE`), giving the password dialog ample time. The agent spawns a lightweight `dlp-user-ui.exe --stop-password` process in the active console session via `CreateProcessAsUserW`. This process shows only the Win32 password dialog (no iced/tray) and writes the result to a temp file that the agent polls. This avoids the Pipe 1 synchronous I/O deadlock (Windows serialises `ReadFile`/`WriteFile` on non-overlapped handles). The actual exit occurs only after password verification (F-SVC-10 through F-SVC-12). If the password challenge fails or is cancelled, `revert_stop()` reports `Running` to the SCM so `sc query` reflects the correct state.

---

## 9. Attack Surface and Threat Model Summary

This section summarizes the threat landscape. For the full STRIDE analysis with per-threat assets, attack vectors, impacts, and mitigation status, see [THREAT_MODEL.md](./THREAT_MODEL.md).

### 9.1 Attack Surface Summary

| Surface | Description | Risk Level |
|---|---|---|
| **File interception hooks** | Windows API hooks in `file_monitor.rs` | High — if hooks are bypassed, ABAC is not consulted |
| **File monitor interference** | The `notify` watcher can be interfered with by admin-level processes | Medium — relies on EDR to detect process-level interference |
| **Named pipes** | 3 pipes connecting Agent ↔ UI | Medium — mitigated by SYSTEM-only ACL and DPAPI |
| **dlp-server HTTPS API** | `engine_client.rs` → dlp-server | High — protected by mTLS |
| **AD LDAP interface** | `ad_client.rs` (dlp-server only) → Domain Controller | High — protected by LDAPS + service account |
| **dlp-server API** (Phase 5) | Agent → dlp-server audit relay | Medium — protected by TLS + mTLS |
| **Admin interface** (Phase 5) | dlp-admin → dlp-server REST API | High — protected by TOTP + JWT |
| **Service stop flow** | `sc stop` → password challenge | High — protected by bcrypt hash comparison |

### 9.2 File Monitor Limitations

The file system monitor in `dlp-agent/src/interception/file_monitor.rs` uses the `notify` crate (backed by `ReadDirectoryChangesW` on Windows). It cannot intercept file operations performed via direct NTFS syscalls (`NtWriteFile`, `NtDeleteFile`, etc.) that bypass the Windows object layer.

**What it can detect:**
- File create, write, delete, rename, and read via the Win32 API
- Works cross-session without elevation

**What it cannot prevent:**
- Direct syscall operations that never touch `ReadDirectoryChangesW`
- Kernel-level file access that bypasses the NTFS change journal

**Status:** Implemented. A minifilter driver (future phase) is the only complete mitigation for direct syscall bypass.

### 9.3 Residual Risks

Key residual risks (Not Mitigated or Planned for future phases) documented in [THREAT_MODEL.md](./THREAT_MODEL.md):

| Risk | Impact | Mitigation Status |
|---|---|---|
| File monitor can be interfered with by admin | File interception blind | **Not Mitigated** — requires kernel-level or EDR control |
| Admin audit log overrides may contain PII | Compliance risk | **Not Mitigated** — free-text field in override justification |
| HSM not used for key storage | DPAPI subject to session-local code execution | **Planned Phase 5** |
| dlp-agent update mechanism is unauthenticated (Phase 1) | Binary replacement attack | **Planned Phase 4** — code signing |
| ABAC policy itself can be tampered with (Phase 1 local store) | Privilege escalation | **Planned Phase 5** — dlp-server policy sync |
| SIEM relay credentials in dlp-server memory | Credential theft from dlp-server host | **Planned Phase 5** — HSM / Azure Key Vault |

---

## 10. Logging as a Security Control

### 10.1 Audit as Detection and Forensics

Audit logging serves three security functions:

1. **Detection:** `DENY_WITH_ALERT` triggers immediate SOC notification
2. **Investigation:** Audit events provide the evidence chain for incident response
3. **Compliance:** Immutable audit records satisfy ISO 27001 A.12.4 requirements

### 10.2 Event Completeness

Every intercepted file operation generates an audit event — not just blocked ones. This ensures the audit log is a complete record of data access, not just violations. An analyst reviewing the audit log can detect anomalous access patterns even when no policy was violated.

### 10.3 What Must NEVER Be Logged

The following data must never appear in any audit log, trace output, or crash dump:

| Data | Reason |
|---|---|
| File content or payload | Could itself be the exfiltrated data |
| dlp-admin password | Would expose the highest-privilege credential |
| Override justification text | May contain PII (email addresses, names, ticket numbers) — **current gap** |
| DPAPI key material | Would compromise all other DPAPI-protected data |
| TLS private keys | Would compromise all TLS sessions |
| JWT signing keys | Would allow admin session forgery |
| AD service account password | Would allow unauthorized AD queries |
| SIEM HEC tokens (Phase 5) | Would allow unauthorized SIEM write access |

These restrictions are enforced by:
- Code review checklist (mandatory before commit)
- `cargo clippy` rules (detect `dbg!()` macros that might log sensitive values)
- ISO 27001 A.12.4.1 controls reviewed in [ISO27001_MAPPING.md](./ISO27001_MAPPING.md)

### 10.4 Immutability Guarantees

`audit_emitter.rs` (Phase 1) writes to a local append-only JSON file using a **write-only file handle** (`FILE_APPEND_DATA` only — no `DELETE`, `WRITE_OWNER`, or `WRITE_DAC`). The file is created with:
- Inherited DACL from the parent directory (SYSTEM + Administrators only)
- No `FILE_FLAG_WRITE_THROUGH` required (Durability is a separate concern)

In Phase 5, `dlp-server/src/audit_store.rs` implements append-only storage with no exposed update or delete API (`N-SRV-06`).

A SHA-256 hash chain for tamper-evident audit logs is identified as a **future enhancement** (noted in [AUDIT_LOGGING.md](./AUDIT_LOGGING.md) §11).

### 10.5 Admin Action Audit Trail

Every dlp-admin action via `dlp-server` generates an `ADMIN_ACTION` audit event (F-AUD-09). This includes:
- Admin identity (user_sid, user_name)
- Action type (POLICY_CREATE, POLICY_DELETE, POLICY_UPDATE, etc.)
- Resource affected
- Source IP address
- Timestamp

The admin audit trail is written to the same append-only store as user audit events and relayed to SIEM. This provides non-repudiation for administrative actions.

---

## 11. ISO 27001:2022 Control Mapping

This section maps the controls described in this document to ISO 27001:2022 annex A controls. For the full mapping table, see [ISO27001_MAPPING.md](./ISO27001_MAPPING.md).

### Key Control Mappings from This Document

| ISO 27001 Control | Security Architecture Mechanism | Evidence |
|---|---|---|
| **A.5.1** Information Security Policies | Security design principles documented in this document | SRS.md, SECURITY_ARCHITECTURE.md |
| **A.5.2** Information Security Roles | dlp-admin (superuser), AD-managed users, SOC | SRS.md §2.3 |
| **A.6.2** Privileged Access Rights | dlp-admin MFA; service stop password; process DACL | F-ADM-06, F-SVC-10–F-SVC-12, N-SEC-11 |
| **A.8.1** Asset Responsibility | Data classification T1–T4 | F-ADM-02, ABAC_POLICIES.md |
| **A.8.2** Information Classification | ABAC rules per tier | ABAC_POLICIES.md |
| **A.9.1** Access Control Policy | Dual-layer: NTFS + ABAC | §3 of this document |
| **A.9.2** User Registration | AD-managed individual accounts; no shared accounts | SRS.md §2.4 assumption 7 |
| **A.9.4** Secure Authentication | AD LDAPS auth; MFA for admin portal | N-SEC-06, F-SRV-07 |
| **A.9.4.6** Temporary and Privileged Access | Service account least privilege | §1.1 of this document |
| **A.12.4** Event Logging | Structured JSON audit; immutable | F-AUD-01, F-AUD-06, AUDIT_LOGGING.md |
| **A.12.4.1** Event Logging + Protection | Append-only store; no delete API; hash chain (planned) | N-SRV-06, §10.4 of this document |
| **A.12.5** Secure Communication | TLS 1.3 all channels; mTLS agent ↔ engine | N-SEC-01, N-SEC-05 |
| **A.16.1** Incident Management | DENY_WITH_ALERT; dlp-server alert router | F-AUD-08, F-ADM-08, AUDIT_LOGGING.md |

---

## Appendix A: Cross-Reference Table

| This Document Section | Related THREAT_MODEL.md Section | SRS Requirement |
|---|---|---|
| §2 (Trust Boundaries) | §2 (Data Flow Diagram), §3 (Trust Zones) | SRS §5.1 |
| §3 (NTFS + ABAC) | §3.1 (Tampering — NTFS ACL bypass) | SRS §2.1, F-ENG-12 |
| §4 (Critical Rule) | §3.2 (Tampering — policy file) | F-ENG-12 |
| §5 (Fail-Closed) | §5 (DoS — engine offline) | F-AGT-11, N-AVA-02 |
| §6 (Secrets) | §4 (Info Disclosure — credentials) | N-SEC-02, N-SEC-09 |
| §7 (Named Pipes) | §4 (Info Disclosure — pipe), §5 (DoS — pipe flood) | N-SEC-12, F-SVC-03 |
| §8 (Service Hardening) | §6 (Elevation of Privilege) | N-SEC-11, F-SVC-09 |
| §9 (ETW Bypass) | §3.3 (Tampering — ETW bypass) | F-AGT-18 (superseded) — SMB share detection via MPR polling (F-AGT-14, Phase 3) |
| §10 (Logging) | §3 (Repudiation) | F-AUD-06, F-AUD-09 |
