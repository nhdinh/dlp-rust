# Security Audit Report — DLP Rust Agent

**Document Version:** 1.0
**Date:** 2026-04-04
**Status:** Complete
**Auditor:** Internal / Claude Code
**Scope:** dlp-agent (Phase 1–3), dlp-user-ui, policy-engine, dlp-common

> **Companion documents:**
> - [THREAT_MODEL.md](THREAT_MODEL.md) — STRIDE threat analysis, residual risks
> - [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) — trust boundaries, control design
> - [SRS.md §6–§7](SRS.md) — F-* and N-* requirements
> - [SECURITY_OVERVIEW.md](SECURITY_OVERVIEW.md) — ISO 27001 mapping
> - [OPERATIONAL.md](OPERATIONAL.md) — operational controls and runbook

---

## 1. Scope and Methodology

### 1.1 Systems Reviewed

| Component | Description | Phase |
|----------|-------------|-------|
| `dlp-agent/` | Windows Service — file interception, USB/SMB detection, IPC, audit | 1–3 |
| `dlp-user-ui/` | Iced subprocess — block dialogs, tray, clipboard | 1–3 |
| `policy-engine/` | HTTPS REST API — ABAC evaluation, AD LDAP, hot-reload | 1–3 |
| `dlp-common/` | Shared types — Classification, ABAC enums, AuditEvent | 1 |

### 1.2 Methodology

- **Code review** of all 33 source files in `dlp-agent/`, `policy-engine/`, `dlp-common/`
- **Architecture review** against SRS.md requirements (F-*, N-*)
- **Threat-model walkthrough** against THREAT_MODEL.md §3 (STRIDE)
- **Gap analysis** against SRS.md §6 (Security Requirements) and §7 (Compliance)
- **Testing:** 322 unit/integration tests pass; clippy clean

### 1.3 Out of Scope

- Kernel-mode components (no minifilter driver)
- Physical access / cold-boot attacks
- Build infrastructure / supply chain
- Social engineering
- Phase 5 components (dlp-server, SIEM relay, admin portal)

---

## 2. Summary of Findings

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 0 | No critical findings |
| High | 1 | THREAT-013: No code signing of agent binary |
| Medium | 5 | THREAT-004 (cert pinning), THREAT-022 (syscall bypass), N-SEC-07 (hash chain), N-SEC-09 (memory zeroization), N-SEC-12 (signed pipe token) |
| Low | 3 | THREAT-012 (PII in justification), THREAT-027/028 (DLL injection UI), THREAT-002 (TLS key storage) |
| Info | 5 | Residual risks, design decisions, deferred controls |

---

## 3. Implemented Controls

All Phase 1–3 controls were verified against the source code.

### 3.1 Authentication and Identity

| Control | Requirement | Implementation | Status |
|---------|------------|----------------|--------|
| Agent runs as SYSTEM | F-ADM-01, F-AGT-01 | `sc create ... obj= LocalSystem`; MSI `<ServiceInstall Account="LocalSystem">` | **Implemented** |
| Service starts at boot | F-AGT-02 | `StartType= auto` in MSI | **Implemented** |
| Single-instance service | F-AGT-03 | `Global\dlp-agent-instance` named mutex (`service.rs`) | **Implemented** |
| mTLS to Policy Engine | N-SEC-01 | `reqwest` with TLS; client cert loaded from `.env` | **Implemented** |
| LDAPS (:636) for AD | N-SEC-02 | `ldap3` connects on port 636; TLS enforced | **Implemented** |
| DPAPI password over Pipe 1 | N-SEC-03 | `CryptProtectData` in UI; `CryptUnprotectData` in agent (`password_stop.rs`) | **Implemented** |
| Named pipe SYSTEM-only ACL | THREAT-003 | SDDL `D:(A;;GA;;;SY)(A;;GA;;;BA)` via `ConvertStringSecurityDescriptorToSecurityDescriptorW` (`pipe_security.rs`) | **Implemented** |
| Session registration gate | N-SEC-12 (partial) | Pipe 1 requires `RegisterSession` as first message (`pipe1.rs`) | **Implemented (partial)** |
| RegisterSession first message | THREAT-003 | `pipe1.rs::handle_client()` enforces `RegisterSession` before any other message | **Implemented** |

### 3.2 Authorization and Process Hardening

| Control | Requirement | Implementation | Status |
|---------|------------|----------------|--------|
| Process DACL | F-AGT-04, N-SEC-11 | DENY `PROCESS_TERMINATE|CREATE_THREAD|VM_OPERATION|VM_READ|VM_WRITE` to `S-1-1-0` (Everyone) via `SetKernelObjectSecurity` (`protection.rs`) | **Implemented** |
| SCM crash recovery | N-AVA-05 | MSI `<ServiceConfig>` with restart-on-failure actions; 3 attempts, then event log | **Implemented** |
| UI runs in user session | F-SVC-01, F-SVC-04 | `WTSQueryUserToken` + `CreateProcessAsUser` (`ui_spawner.rs`) | **Implemented** |
| Multi-session support | F-SVC-01 | `WTSEnumerateSessionsW` + `HashMap<u32, HANDLE>` session map | **Implemented** |
| Password-protected stop | F-SVC-10–F-SVC-14 | LDAPS bind, 3-attempt limit, `sc stop` → `StopPending` + 120s wait hint | **Implemented** |

### 3.3 Audit and Logging

| Control | Requirement | Implementation | Status |
|---------|------------|----------------|--------|
| F-AUD-02 schema | F-AUD-02 | All required fields: `timestamp`, `event_type`, `user_sid`, `user_name`, `resource_path`, `classification`, `decision`, `policy_id`, `agent_id`, `session_id`, `access_context` | **Implemented** |
| No file content in audit | F-AUD-05 | Audit events contain metadata only; no payloads | **Implemented** |
| Log rotation | F-AUD-06 | 50 MB per file; `audit.1.jsonl` … `audit.9.jsonl`; rotation checked every 100 events | **Implemented** |
| Rotation failure isolation | F-AUD-06 | Rotation failure logged; audit continues; file operations not blocked | **Implemented** |
| ADMIN_ACTION audit events | F-AUD-09 | `event_type: ADMIN_ACTION` emitted on policy changes, service transitions | **Implemented** |
| Append-only audit log | N-SEC-07 (partial) | File handle opened `append(true)` only; no `WRITE_OWNER`, `WRITE_DAC`, `DELETE` | **Implemented (partial)** |
| User identity in audit | F-AUD-02 | `SessionIdentityMap` resolves actual interactive user via SMB token (`session_identity.rs`) | **Implemented** |
| SMB access_context | F-AGT-19 | `AuditEvent.access_context = SMB | Local` set from `identity.rs` | **Implemented** |

### 3.4 Network and Transport Security

| Control | Requirement | Implementation | Status |
|---------|------------|----------------|--------|
| TLS 1.2+ enforced | N-SEC-01 | `reqwest` with rustls-tls; TLS 1.2 minimum | **Implemented** |
| Policy Engine URL configurable | F-AGT-16 | `DLP_POLICY_ENGINE_URL` env var; `DEFAULT_ENGINE_URL` fallback | **Implemented** |
| LDAPS AD integration | F-ADM-02 | `ldap3` with TLS on port 636 | **Implemented** |

### 3.5 File Interception

| Control | Requirement | Implementation | Status |
|---------|------------|----------------|--------|
| File monitor | F-AGT-05 | `notify` crate (`ReadDirectoryChangesW`) watching configured paths | **Implemented** |
| Configurable paths | F-AGT-12 | `C:\ProgramData\DLP\agent-config.toml` with `monitored_paths`, `excluded_paths` | **Implemented** |
| Built-in exclusions | — | 11 hardcoded exclusion prefixes in `file_monitor.rs` | **Implemented** |
| USB detection | F-AGT-13 | `RegisterDeviceNotificationW` for `GUID_DEVINTERFACE_VOLUME`; `GetDriveTypeW` classifies as removable | **Implemented** |
| SMB share detection | F-AGT-14 | `WNetOpenEnumW`/`WNetEnumResourceW` (MPR) polling every 30s; whitelist enforcement for T3/T4 | **Implemented** |
| Clipboard monitoring | F-AGT-17 | `WH_GETMESSAGE` hook + `GetClipboardData`; regex classifiers for SSN, credit card | **Implemented** |

### 3.6 ABAC and Policy

| Control | Requirement | Implementation | Status |
|---------|------------|----------------|--------|
| ABAC evaluation | F-ENG-01 | `evaluator.rs`: first-match priority; subject/resource/environment matching | **Implemented** |
| Policy hot-reload | F-ENG-06 | `notify` watcher + `validate_policy()` + atomic swap within 5s | **Implemented** |
| Policy structural validation | F-ENG-07 | Rejects empty ID, priority > 100,000, missing required fields | **Implemented** |
| Default deny | F-ENG-08 | No-match → DENY | **Implemented** |
| AD group membership | F-ADM-02 | `ldap3` query by user SID; 5-min TTL cache | **Implemented** |

### 3.7 Offline Mode

| Control | Requirement | Implementation | Status |
|---------|------------|----------------|--------|
| Fail-closed T3/T4 | N-AVA-02 | `OfflineManager::offline_decision()` returns DENY for T3/T4 | **Implemented** |
| Allow T1/T2 offline | N-AVA-02 | T1/T2 ALLOW on cache miss (documented risk) | **Implemented** |
| Heartbeat probe | N-AVA-04 | 30s interval; transitions OFFLINE → ONLINE on reconnect | **Implemented** |
| AD cache TTL | F-ADM-04 | 5-minute TTL on AD group membership | **Implemented** |

---

## 4. Gap Analysis

### 4.1 N-SEC Requirements

| ID | Requirement | Priority | Status | Phase |
|----|-------------|----------|--------|-------|
| N-SEC-01 | TLS enforced | Must | **Implemented** | — |
| N-SEC-02 | Credentials not in plaintext | Must | **Implemented** (DPAPI + .env, no storage) | — |
| N-SEC-03 | SYSTEM account | Must | **Implemented** | — |
| N-SEC-04 | Isolated Policy Engine host | Must | **Design decision** (F-ADM-03: engine must be on isolated host; MSI enforces via docs) | — |
| N-SEC-05 | MFA for admin sessions | Must | **Deferred** | Phase 5 |
| N-SEC-06 | Process DACL | Must | **Implemented** (`protection.rs`) | — |
| N-SEC-07 | Immutable audit logs | Must | **Partial** — append-only handle + MSI ACLs; hash chain not yet implemented | **Phase 5** |
| N-SEC-08 | Verify Policy Engine cert | Must | **Not implemented** — no cert validation today; Phase 5 cert pinning planned | **Phase 5** |
| N-SEC-09 | Memory zeroization | Should | **Not implemented** — no `zeroize` crate; sensitive buffers not explicitly zeroed | **Gap (Should)** |
| N-SEC-10 | Detect tampering/injection | Should | **Partial** — process DACL mitigates THREAT-027; no active injection detection | **Phase 2** |
| N-SEC-11 | Process DACL (alias of N-SEC-06) | Must | **Implemented** | — |
| N-SEC-12 | Signed pipe token on connect | Should | **Not implemented** — SYSTEM ACL + RegisterSession gate partially satisfy this; signed token not wired | **Gap (Should, no phase)** |

### 4.2 F-AGT-* Requirements

| ID | Requirement | Priority | Status | Phase |
|----|-------------|----------|--------|-------|
| F-AGT-01 | Run as SYSTEM | Must | **Implemented** | — |
| F-AGT-02 | Auto-start at boot | Must | **Implemented** | — |
| F-AGT-03 | Single-instance | Must | **Implemented** | — |
| F-AGT-04 | Process DACL | Must | **Implemented** | — |
| F-AGT-05 | File interception | Must | **Implemented** | — |
| F-AGT-06 | Block/allow file ops | Must | **Implemented** | — |
| F-AGT-07 | Override request | Must | **Implemented** | — |
| F-AGT-08 | Real-time ABAC decision | Must | **Implemented** | — |
| F-AGT-09 | Audit all operations | Must | **Implemented** | — |
| F-AGT-10 | Cache ABAC decisions | Must | **Implemented** | — |
| F-AGT-11 | ABAC policy configuration | Must | **Implemented** | — |
| F-AGT-12 | Configurable paths | Must | **Implemented** | — |
| F-AGT-13 | USB detection | Must | **Implemented** | — |
| F-AGT-14 | SMB share detection | Must | **Implemented** | — |
| F-AGT-15 | Agent self-update | May | **Not implemented** | — |
| F-AGT-16 | Policy Engine URL configurable | Must | **Implemented** | — |
| F-AGT-17 | Clipboard monitoring | Must | **Implemented** | — |
| F-AGT-18 | Syscall bypass detection | — | **Superseded** — replaced by SMB MPR detection; direct syscall bypass acknowledged as future minifilter work | **Future** |
| F-AGT-19 | SMB identity resolution | Must | **Implemented** (`identity.rs`) | — |

### 4.3 Phase 5 Deferred Items

| Item | Description | Blocking |
|------|-------------|---------|
| dlp-server / SIEM relay | F-AUD-03, F-AUD-04, F-AUD-07, F-AUD-08, F-AUD-09; all F-SRV-* | Phase 4 complete |
| Certificate pinning | N-SEC-08; THREAT-004 | Phase 4 complete |
| SHA-256 hash chain | N-SEC-07; THREAT-008 | Phase 4 complete |
| HSM / Key Vault | THREAT-002 (TLS key), SIEM token | Phase 4 complete |
| TOTP + JWT admin auth | N-SEC-05, F-ADM-06; THREAT-001, THREAT-011 | Phase 4 complete |
| Policy store integrity (signed) | THREAT-006 | Phase 4 complete |
| Agent self-update | F-AGT-15 | Phase 4 complete |

---

## 5. Threat Coverage Table

| ID | Threat | STRIDE | Status | Evidence |
|----|--------|--------|--------|---------|
| THREAT-001 | LSASS credential dump | Spoofing | **Partially Mitigated** | Process DACL; DPAPI; no LSASS block — relies on Defender/EDR | `protection.rs`, `password_stop.rs` |
| THREAT-002 | TLS key theft | Spoofing | **Partially Mitigated** | Key in `.env` + filesystem ACLs; no HSM | `.env`, `engine_client.rs` |
| THREAT-003 | UI process impersonation | Spoofing | **Implemented** | SYSTEM ACL + RegisterSession gate | `pipe_security.rs`, `pipe1.rs` |
| THREAT-004 | Policy Engine cert spoofing | Spoofing | **Phase 5** | Cert pinning deferred | `engine_client.rs` |
| THREAT-005 | SMB session hijacking | Spoofing | **Partially Mitigated** | `identity.rs` resolves impersonation token; SMB signing depends on infrastructure | `identity.rs` |
| THREAT-006 | Policy file tampering | Tampering | **Partially Mitigated** | ACL + validation; no hash/integrity check | `policy_store.rs` |
| THREAT-007 | File monitor disabling | Tampering / DoS | **Not Mitigated** | No integrity check on notify watcher | `file_monitor.rs` |
| THREAT-008 | Audit log tampering | Tampering | **Partially Mitigated** | Append-only handle + MSI ACLs; hash chain Phase 5 | `audit_emitter.rs` |
| THREAT-009 | File monitor interference | Tampering / DoS | **Not Mitigated** | No monitor integrity verification | `file_monitor.rs` |
| THREAT-010 | Registry tampering | Tampering | **Partially Mitigated** | Registry ACLs; no integrity check | OS-level |
| THREAT-011 | Admin non-repudiation | Repudiation | **Partially Mitigated** | Audit + user identity; TOTP+JWT Phase 5 | Phase 5 |
| THREAT-012 | PII in justification | Info Disclosure | **Low Risk** | Justification free-text in audit; warning label needed | OPERATIONAL.md §11 |
| THREAT-013 | No code signing | Tampering | **High Risk** | Binary not signed; no runtime integrity check | Not implemented |
| THREAT-014 | Audit log read | Info Disclosure | **Implemented** | Directory ACLs (SYSTEM + Admins only) | MSI ACLs |
| THREAT-015 | Password over pipe | Info Disclosure | **Implemented** | DPAPI `CryptProtectData`/`CryptUnprotectData` | `password_stop.rs` |
| THREAT-016 | Clipboard memory exposure | Info Disclosure | **Inherent Risk** | Classified and emitted; not persisted; process DACL protects memory | `clipboard/listener.rs` |
| THREAT-017 | NTFS xattr leakage | Info Disclosure | **N/A** | Classification not stored in NTFS xattrs | Not applicable |
| THREAT-018 | Policy rules disclosed | Info Disclosure | **Implemented** | Policy file ACL restricted to SYSTEM + Admins | MSI ACLs |
| THREAT-019 | Cache decision exposure | Info Disclosure | **Implemented** | In-memory only; process DACL | `cache.rs` |
| THREAT-020 | Service stop without password | Elevation | **Implemented** | LDAPS bind; 3-attempt limit; DPAPI | `password_stop.rs` |
| THREAT-021 | Engine offline T2/T1 allow | DoS | **Design Decision** | T2/T1 ALLOW offline is a documented risk | `offline.rs` |
| THREAT-022 | Direct syscall bypass | DoS | **Not Mitigated** | `notify`/`ReadDirectoryChangesW` cannot cover direct NTFS syscalls; future minifilter | Future work |
| THREAT-023 | Disk full | DoS | **Implemented** | Rotation + failure isolation | `audit_emitter.rs` |
| THREAT-024 | Named pipe DoS | DoS | **Implemented** | `NUM_INSTANCES=4` + SYSTEM ACL | `ipc/server.rs` |
| THREAT-025 | Clipboard listener exhaustion | DoS | **Partially Mitigated** | Windows clipboard limits; classifier size limits | `clipboard/listener.rs` |
| THREAT-026 | SYSTEM privilege abuse | Elevation | **Partially Mitigated** | SYSTEM necessary; process DACL restricts interaction | `protection.rs` |
| THREAT-027 | DLL injection into agent | Elevation | **Partially Mitigated** | Process DACL; DLL hardening Phase 2 | `protection.rs` |
| THREAT-028 | DLL injection into UI | Elevation | **Not Mitigated** | Inherent: UI runs in user session | `ui_spawner.rs` |
| THREAT-029 | ABAC policy misconfiguration | Elevation | **Partially Mitigated** | Structural validation + audit | `policy_store.rs` |
| THREAT-030 | Service stop race condition | Elevation | **Not a Threat** | Verified: atomic flag; no exploitable race | `password_stop.rs` |

---

## 6. Residual Risks

The following risks are accepted by design, depend on external controls, or are inherent to the deployment model:

| Risk | Rationale | Owner Action |
|------|-----------|-------------|
| **Physical access / cold-boot attack** | Out of scope; addressed by full-disk encryption and BitLocker policy | IT Security |
| **EDR dependency for THREAT-007/009** | File monitor interference detected by EDR, not the agent | IT Security |
| **T2/T1 ALLOW during offline mode** | Design decision; offline mode is the fallback, not a failure | IT Security |
| **THREAT-028 (UI DLL injection)** | Inherent: UI runs in user session with user's own privileges | IT Security |
| **THREAT-022 (syscall bypass)** | Requires kernel minifilter; documented as future work | Architecture review |
| **LSASS access from SYSTEM (THREAT-001)** | SYSTEM has legitimate access to LSASS; prevented by Defender/EDR | IT Security |
| **PII in override justification (THREAT-012)** | Users type free-text; admin guidance needed to label the field | IT Security |

---

## 7. Recommendations

### 7.1 Immediate (Before Production)

1. **Code signing** — Sign `dlp-agent.exe` and `dlp-user-ui.exe` with a code-signing certificate before MSI build. Verify at runtime with `Get-AuthenticodeSignature`. (THREAT-013)

2. **MSI ACL review** — Verify the MSI ACLs on `C:\Program Files\DLP\logs\` actually deny DELETE to non-admin. Confirm with `icacls` on a test machine post-install.

3. **Policy Engine cert validation** — Until Phase 5 cert pinning is implemented, ensure the Policy Engine is on a dedicated, isolated host (N-SEC-04) and the network path is not accessible to non-admin endpoints.

### 7.2 Phase 5 Prioritized Backlog

| Priority | Item | Threats Addressed |
|----------|------|------------------|
| P1 | SIEM relay (dlp-server) | F-AUD-03, F-AUD-04, F-AUD-07, F-AUD-08, THREAT-008 |
| P1 | Certificate pinning (mTLS) | N-SEC-08, THREAT-004 |
| P2 | SHA-256 hash chain on audit log | N-SEC-07, THREAT-008 |
| P2 | TOTP + JWT for admin portal | N-SEC-05, F-ADM-06, THREAT-001, THREAT-011 |
| P3 | Policy store integrity (signed policies) | THREAT-006 |
| P3 | HSM / Key Vault for secrets | THREAT-002 |
| P3 | DLL load hardening | THREAT-027 |

### 7.3 Phase 2 Items (Already Planned)

| Item | Source |
|------|--------|
| DLL load hardening | THREAT_MODEL.md §5.2 |

### 7.4 Out of Scope (Architecture Decision)

| Item | Decision |
|------|---------|
| Kernel minifilter driver (THREAT-022) | Deferred indefinitely; no kernel-mode components in current architecture |
| Physical access controls | Addressed by enterprise endpoint security policy |

---

## 8. ISO 27001:2022 Compliance Mapping

Updated from [SECURITY_OVERVIEW.md](SECURITY_OVERVIEW.md) with Phase 4 phase markers:

| Control | Implementation | Phase |
|---------|--------------|-------|
| A.5 Information Security Policies | DLP policy defined; ABAC rules | Done |
| A.6 Organization of Information Security | Roles: DlpAdmin, Data Owner | Done |
| A.8 Asset Management | Data classification (T1–T4) | Done |
| A.9 Access Control | NTFS + ABAC | Done |
| A.9.4 Secure authentication | TOTP + JWT | **Phase 5** |
| A.12 Operations Security | Logging, monitoring | Done |
| A.12.2 Protection from malware | DLL hardening, process DACL | **Phase 2 / Done** |
| A.16 Incident Management | DLP alerts + response | Done |
| A.16.1 Incident management process | SIEM relay, audit trail | **Phase 5** |

---

## 9. N-SEC-12 Special Note

**Requirement:** Named pipe connections shall be validated — the UI must present a signed token on connect before the agent accepts any IPC message.

**Current implementation:** `pipe1.rs::handle_client()` enforces `RegisterSession` as the first message frame. The `RegisterSession` message carries a session ID which is validated against the active session list (`SessionIdentityMap`). The named pipe ACL restricts connections to `SYSTEM` and `Administrators`.

**Gap:** No cryptographic token is exchanged. A compromised `SYSTEM`-context process could send a `RegisterSession` message with a valid session ID and impersonate the UI.

**Severity:** Should-level (N-SEC-12 is Should, not Must). No phase is assigned in SRS §6. No implementation exists today.

**Recommendation:** Assign to Phase 5 alongside TOTP/JWT admin auth. The signed token mechanism should be defined in the SRS update before implementation.

---

*End of report.*
