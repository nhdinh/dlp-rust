# Phase 1 Task Tracker

**Document Version:** 1.0
**Date:** 2026-03-31
**Status:** Draft
**Parent Document:** `docs/plans/user-stories.md`
**Legend:** `[ ]` Todo | `[~]` In Progress | `[x]` Done

> This file is the authoritative status tracker for Phase 1 tasks (T-01 through T-46).
> Update the Status column as work progresses. Keep it in sync with `docs/plans/user-stories.md`.

---

## Sprint 1 — Policy Engine Scaffold

| ID   | Status | Story | Task                                                                                                             | Deliverable                         |
| ---- | ------ | ----- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| T-01 | [x]    | US-01 | Initialize `policy-engine/` workspace crate: `Cargo.toml`, `tonic`, TLS config, `tower` middleware scaffold      | `policy-engine/src/`                |
| T-02 | [x]    | US-01 | Implement policy store: JSON file persistence, hot-reload via `notify` crate, version tracking                   | `policy-engine/src/policy_store.rs` |
| T-03 | [x]    | US-01 | Implement ABAC evaluation engine: first-match policy evaluation, subject/resource/environment condition matching | `policy-engine/src/evaluator.rs`    |
| T-07 | [x]    | US-01 | Write unit tests: all 3 ABAC rules from `ABAC_POLICIES.md`                                                       | `policy-engine/tests/`              |

---

## Sprint 2 — HTTPS Server + AD Client + REST API

| ID   | Status | Story | Task                                                                                                            | Deliverable                        |
| ---- | ------ | ----- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| T-04 | [x]    | US-17 | Implement HTTPS `Evaluate` endpoint: axum server, TLS 1.3, mTLS auth, request/response types from `dlp-common/` | `policy-engine/src/http_server.rs` |
| T-05 | [x]    | US-16 | Implement AD LDAP client: `ldap3` connection, group membership query, device trust attribute lookup             | `policy-engine/src/ad_client.rs`   |
| T-06 | [x]    | US-17 | Implement REST CRUD API: axum server, policy endpoints (GET/POST/PUT/DELETE), OpenAPI 3.0 spec                  | `policy-engine/src/rest_api.rs`    |
| T-08 | [x]    | US-16 | Implement AD mock server for integration tests                                                                  | `policy-engine/tests/mock_ad/`     |

---

## Sprint 3 — AD Group Lookup + Hot-Reload + Benchmark

| ID   | Status | Story | Task                                                                                                              | Deliverable                         |
| ---- | ------ | ----- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| T-22 | [x]    | US-16 | Implement AD group membership lookup: `ldap3` query by user SID, return all group SIDs; TTL cache (default 5 min) | `policy-engine/src/ad_client.rs`    |
| T-23 | [x]    | US-15 | Implement hot-reload: `notify` watcher on policy JSON files, validate on reload, atomic swap, within 5s           | `policy-engine/src/policy_store.rs` |
| T-24 | [x]    | US-14 | Performance validation: benchmark P95 latency ≤ 50ms on single request; ≥ 10k req/s throughput                    | `policy-engine/tests/benchmark.rs`  |

---

## Sprint 4 — dlp-agent Workspace + Windows Service Skeleton

| ID   | Status | Story | Task                                                                                                                                           | Deliverable                |
| ---- | ------ | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| T-09 | [x]    | US-A1 | Initialize `dlp-agent/` workspace crate: `Cargo.toml`, `windows-rs`, tokio, `dlp-common`                                                       | `dlp-agent/src/`           |
| T-10 | [x]    | US-A1 | Implement Windows Service skeleton: `windows-service` crate, SCM lifecycle, `sc create dlp-agent type= own start= auto`, single-instance mutex | `dlp-agent/src/service.rs` |

---

## Sprint 5 — UI Spawner (Multi-Session)

| ID   | Status | Story | Task                                                                                                                                                                                                           | Deliverable                   |
| ---- | ------ | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| T-30 | [x]    | US-A2 | Implement `ui_spawner.rs`: `WTSEnumerateSessionsW` on startup → `CreateProcessAsUser` per session; `WTSRegisterSessionNotification` for connect/disconnect; `HashMap<u32, HANDLE>` session-ID-to-UI-handle map | `dlp-agent/src/ui_spawner.rs` |

---

## Sprint 6 — Named Pipe IPC Servers

| ID   | Status | Story | Task                                                                                                                                                                                                                                         | Deliverable                   |
| ---- | ------ | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| T-31 | [x]    | US-A3 | Implement 3 named pipe IPC servers: `\\.\pipe\DLPCommand` (Pipe 1, 2-way duplex), `\\.\pipe\DLPEventAgent2UI` (Pipe 2, 1-way A→U), `\\.\pipe\DLPEventUI2Agent` (Pipe 3, 1-way U→A); `PIPE_TYPE_MESSAGE \| PIPE_READMODE_MESSAGE`; JSON serde | `dlp-agent/src/ipc/server.rs` |
| T-32 | [x]    | US-A3 | Implement Pipe 1 handler: BLOCK_NOTIFY, OVERRIDE_REQUEST, CLIPBOARD_READ, PASSWORD_DIALOG, PASSWORD_CANCEL; send USER_CONFIRMED, USER_CANCELLED, CLIPBOARD_DATA, PASSWORD_SUBMIT                                                             | `dlp-agent/src/ipc/pipe1.rs`  |
| T-33 | [x]    | US-A3 | Implement Pipe 2 sender: TOAST, STATUS_UPDATE, HEALTH_PING, UI_RESPAWN, UI_CLOSING_SEQUENCE — fire-and-forget, per session                                                                                                                   | `dlp-agent/src/ipc/pipe2.rs`  |
| T-34 | [x]    | US-A3 | Implement Pipe 3 receiver: HEALTH_PONG, UI_READY, UI_CLOSING — per session pipe                                                                                                                                                              | `dlp-agent/src/ipc/pipe3.rs`  |

---

## Sprint 7 — Health Monitor + Session Change Handler

| ID   | Status | Story | Task                                                                                                                                                                                                                        | Deliverable                        |
| ---- | ------ | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| T-35 | [x]    | US-A4 | Implement mutual health monitor: Agent pings all session UIs via Pipe 2 every 5s; per-session 15s timeout → kill + respawn; UI pings Agent via Pipe 3 every 5s; Agent pings back on Pipe 2; 15s timeout → UI exits          | `dlp-agent/src/health_monitor.rs`  |
| T-36 | [x]    | US-A8 | Implement session change handler: `WTSRegisterSessionNotification` per active session; on Session_Logoff → send UI_CLOSING_SEQUENCE, wait 5s, force-kill, remove from map; on Session_Connect → spawn new UI in new session | `dlp-agent/src/session_monitor.rs` |

---

## Sprint 8 — Process DACL Protection

| ID   | Status | Story | Task                                                                                                                                                                                                                                                                                     | Deliverable                   |
| ---- | ------ | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| T-37 | [x]    | US-A5 | Implement process protection DACL: `SetSecurityInfo` on Agent and UI process handles; deny `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` to Authenticated Users and non-dlp-admin Admins; explicit allow for dlp-admin SID | `dlp-agent/src/protection.rs` |

---

## Sprint 9 — Password-Protected Service Stop

| ID   | Status | Story | Task                                                                                                                                                                                                                                                                     | Deliverable                |
| ---- | ------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- |
| T-38 | [x]    | US-A6 | Implement password-protected service stop: `sc stop` → STOP_PENDING → send PASSWORD_DIALOG over Pipe 1 → collect PASSWORD_SUBMIT → DPAPI `CryptProtectData` → AD LDAP bind as dlp-admin DN → verify → clean shutdown; 3 wrong attempts → log EVENT_DLP_ADMIN_STOP_FAILED | `dlp-agent/src/service.rs` |

---

## Sprint 10 — Tauri UI Scaffold + IPC Client

| ID   | Status | Story | Task                                                                                                                                                                                                                   | Deliverable                            |
| ---- | ------ | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| T-39 | [x]    | US-A7 | Implement Tauri UI scaffold: `dlp-agent/src-tauri/` — `Cargo.toml`, `tauri.conf.json`, devtools enabled, system tray, multi-session IPC client per session                                                             | `dlp-agent/src-tauri/`                 |
| T-40 | [x]    | US-A7 | Implement UI Pipe 1 client: per-session pipe connection, send USER_CONFIRMED, USER_CANCELLED, CLIPBOARD_DATA, PASSWORD_SUBMIT, PASSWORD_CANCEL; handle BLOCK_NOTIFY, OVERRIDE_REQUEST, CLIPBOARD_READ, PASSWORD_DIALOG | `dlp-agent/src-tauri/src/ipc/pipe1.rs` |
| T-42 | [x]    | US-A7 | Implement UI Pipe 3 sender: send HEALTH_PONG, UI_READY, UI_CLOSING                                                                                                                                                     | `dlp-agent/src-tauri/src/ipc/pipe3.rs` |

---

## Sprint 11 — UI: Pipe 2 Listener + Block Dialog

| ID   | Status | Story | Task                                                                                                                                                      | Deliverable                                |
| ---- | ------ | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| T-41 | [x]    | US-A7 | Implement UI Pipe 2 listener: receive TOAST, STATUS_UPDATE, HEALTH_PING, UI_RESPAWN, UI_CLOSING_SEQUENCE per session; display Windows toast notifications | `dlp-agent/src-tauri/src/ipc/pipe2.rs`     |
| T-43 | [x]    | US-A7 | Implement block dialog: Windows toast + modal dialog showing policy info and classification; "Request Override" button opens justification dialog         | `dlp-agent/src-tauri/src/dialogs/block.rs` |

---

## Sprint 12 — UI: Clipboard + Stop Password Dialogs + System Tray

| ID   | Status | Story | Task                                                                                                                        | Deliverable                                        |
| ---- | ------ | ----- | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| T-44 | [x]    | US-A7 | Implement clipboard dialog: read clipboard via Windows API, return CLIPBOARD_DATA over Pipe 1                               | `dlp-agent/src-tauri/src/dialogs/clipboard.rs`     |
| T-45 | [x]    | US-A6 | Implement service stop password dialog: PASSWORD_SUBMIT / PASSWORD_CANCEL; DPAPI `CryptProtectData` before send             | `dlp-agent/src-tauri/src/dialogs/stop_password.rs` |
| T-46 | [x]    | US-A7 | Implement system tray: icon with agent status (Running / Stopped / Offline), context menu (Show Portal, Agent Status, Exit) | `dlp-agent/src-tauri/src/tray.rs`                  |

---

## Sprint 13 — File Interception Engine + HTTPS Client

| ID   | Status | Story | Task                                                                                                                                                                             | Deliverable                                  |
| ---- | ------ | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| T-11 | [x]    | US-07 | Implement `InterceptionEngine` trait + `file_monitor.rs`: detours/DllMain hooks for CreateFileW, WriteFile, NtWriteFile, DeleteFile, MoveFileEx, CopyFileEx                      | `dlp-agent/src/interception/file_monitor.rs` |
| T-12 | [x]    | US-10 | Implement `identity.rs`: SMB impersonation resolution — `ImpersonateSelf`, `QuerySecurityContextToken`, `GetTokenInformation(TokenUser)`, `RevertToSelf`; process token fallback | `dlp-agent/src/identity.rs`                  |
| T-16 | [x]    | US-08 | Implement HTTPS client to Policy Engine: reqwest client, TLS, `POST /evaluate` request/response, retry on failure                                                               | `dlp-agent/src/engine_client.rs`             |
| T-17 | [x]    | US-08 | Implement local policy decision cache: in-memory `HashMap` (resource_hash, subject_hash, TTL), fail-closed for T3/T4 on cache miss                                               | `dlp-agent/src/cache.rs`                     |

---

## Sprint 14 — USB + SMB Network Detection + ETW Bypass

| ID   | Status | Story | Task                                                                                                                                                              | Deliverable                                |
| ---- | ------ | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| T-13 | [x]    | US-09 | Implement `detection/usb.rs`: WMI `Win32_VolumeChangeEvent`, classify drive type (USB mass storage vs. internal), block T3/T4 writes                              | `dlp-agent/src/detection/usb.rs`           |
| T-14 | [x]    | US-10 | Implement `detection/network_share.rs`: ETW `Microsoft-Windows-SMBClient` trace for outbound SMB tree connect events; match against admin-configured whitelist    | `dlp-agent/src/detection/network_share.rs` |
| T-15 | [x]    | US-10 | Implement `detection/etw_bypass.rs`: ETW `Microsoft-Windows-FileSystem-ETW` subscriber; detect ops seen in ETW but not caught by hooks → emit `EVASION_SUSPECTED` | `dlp-agent/src/detection/etw_bypass.rs`    |

---

## Sprint 15 — Offline Mode + Audit

| ID   | Status | Story | Task                                                                                                                                                 | Deliverable                      |
| ---- | ------ | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| T-18 | [x]    | US-11 | Implement offline mode: detect Policy Engine unreachable, fall back to cache, fail-closed defaults, auto-reconnect on heartbeat                      | `dlp-agent/src/offline.rs`       |
| T-19 | [x]    | US-18 | Implement local append-only JSON audit log: `serde_json`, write-only file handle, `FsOptions::FILE_FLAG_BACKUP_SEMANTICS` for SERVICE account access | `dlp-agent/src/audit_emitter.rs` |
| T-25 | [x]    | US-18 | Define `AuditEvent` Rust types: serde serialization, all fields per F-AUD-02 schema (`access_context: local\|SMB`)                                   | `dlp-common/src/audit.rs`        |
| T-26 | [x]    | US-18 | Implement audit event emission: emit every intercepted file operation as JSON, no file content, real-time                                            | `dlp-agent/src/audit_emitter.rs` |
| T-27 | [x]    | US-18 | Implement append-only local audit log: write-only file handle, service account access via `FILE_FLAG_BACKUP_SEMANTICS`, log rotation (size-based)    | `dlp-agent/src/audit_emitter.rs` |

---

## Sprint 16 — Clipboard Hooks

| ID   | Status | Story | Task                                                                                                                                                                         | Deliverable                |
| ---- | ------ | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| T-20 | [x]    | US-07 | Implement `detection/clipboard/listener.rs`: `SetWindowsHookExW` for WH_GETMESSAGE, intercept `WM_PASTE`; `detection/clipboard/classifier.rs`: classify text content → T1–T4 | `dlp-agent/src/clipboard/` |

---

## Sprint 17 — Heartbeat + Integration Tests

| ID   | Status | Story        | Task                                                                                                                                 | Deliverable                      |
| ---- | ------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------- |
| T-21 | [ ]    | US-07, US-13 | Write integration tests: file interception → HTTPS call → local audit log (end-to-end, mock Policy Engine)                             | `dlp-agent/tests/`               |
| T-28 | [ ]    | US-19        | Phase 1: agent writes to local JSON log only. SIEM relay deferred to Phase 5 (dlp-server). Audit log queryable via direct file read. | `dlp-agent/src/audit_emitter.rs` |

---

## Sprint 18 — Performance Validation + Final Integration Review

| ID   | Status | Story | Task                                                                                 | Deliverable                        |
| ---- | ------ | ----- | ------------------------------------------------------------------------------------ | ---------------------------------- |
| T-24 | [x]    | US-14 | Performance validation: P95 latency ≤ 50ms on single request; ≥ 10k req/s throughput | `policy-engine/tests/benchmark.rs` |

---

## Progress Summary

| Metric      | Count |
| ----------- | ----- |
| Total tasks | 46    |
| Done        | 42    |
| In progress | 0     |
| Todo        | 4     |

### Per-Sprint Summary

| Sprint    | Tasks                        | Done |
| --------- | ---------------------------- | ---- |
| Sprint 1  | T-01, T-02, T-03, T-07       | 4/4  |
| Sprint 2  | T-04, T-05, T-06, T-08       | 4/4  |
| Sprint 3  | T-22, T-23, T-24             | 3/3  |
| Sprint 4  | T-09, T-10                   | 2/2  |
| Sprint 5  | T-30                         | 1/1  |
| Sprint 6  | T-31, T-32, T-33, T-34       | 4/4  |
| Sprint 7  | T-35, T-36                   | 2/2  |
| Sprint 8  | T-37                         | 1/1  |
| Sprint 9  | T-38                         | 1/1  |
| Sprint 10 | T-39, T-40, T-42             | 3/3  |
| Sprint 11 | T-41, T-43                   | 2/2  |
| Sprint 12 | T-44, T-45, T-46             | 3/3  |
| Sprint 13 | T-11, T-12, T-16, T-17       | 4/4  |
| Sprint 14 | T-13, T-14, T-15             | 3/3  |
| Sprint 15 | T-18, T-19, T-25, T-26, T-27 | 5/5  |
| Sprint 16 | T-20                         | 1/1  |
| Sprint 17 | T-21, T-28                   | 0/2  |
| Sprint 18 | T-24                         | 1/1  |
