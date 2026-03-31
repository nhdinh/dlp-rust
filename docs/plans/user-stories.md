# User Stories & Epics
## Enterprise DLP System — NTFS + Active Directory + ABAC

**Document Version:** 1.1
**Date:** 2026-03-31
**Status:** Draft
**Parent Document:** `docs/SRS.md`
**Changelog (v1.1):** Added EP-07 Agent-as-Service (US-A1–A8); added US-X×2 (On-Demand Scan, Agent Config); fixed story point totals; added terminology note

---

## How to Read This Document

- **Epic** = a large feature area containing multiple user stories
- **User Story** = a requirements card in the format: `As a [actor], I want [goal], so that [benefit]`
- **Story Points** = Fibonacci estimate (1, 2, 3, 5, 8, 13) — relative complexity/effort
- **MoSCoW** = Must have / Should have / Could have / Won't have (this release)
- **Acceptance Criteria** = concrete pass/fail conditions for the story to be "done"

---

> **⚠️ Terminology Note:** Throughout this document and the project, the following terms have specific, unambiguous meanings:
> - **`dlp-admin`** — the Active Directory user account (privileged, superuser) used for policy management and secure service stop. Never use this token to name a crate or directory.
> - **`dlp-admin-portal`** — the Tauri-based administrative UI crate (`dlp-admin-portal/` in code), used exclusively by `dlp-admin` for policy CRUD, dashboard, and audit log access.
> - **`dlp-endpoint-ui`** — the Tauri subprocess spawned by the DLP Agent into the interactive user desktop (`dlp-agent/src-tauri/` in code), used for toast notifications, override dialogs, clipboard, and system tray.
>
> Do not use `dlp-ui` or `DLP UI` alone — always qualify as above.

## Epic 1: Policy Management
**Epic ID:** EP-01 | **Story Points:** 34 | **MoSCoW:** Must

*As a DLP Admin, I need to define and manage ABAC policies so that the organization has precise, dynamic control over who can access what data under which conditions.*

---

### US-01: Create ABAC Policy
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to create a new ABAC policy with conditions and an action
**So that** I can enforce data protection rules specific to the organization's risk profile

**Acceptance Criteria:**
- [ ] Admin can create a policy with: name, description, conditions (subject/resource/environment attributes), action (ALLOW / DENY / ALLOW_WITH_LOG / DENY_WITH_ALERT), priority
- [ ] Policy is validated for syntax correctness at creation time; malformed policies are rejected with a descriptive error
- [ ] New policy is saved to the policy store and active within 5 seconds
- [ ] Policy is assigned a unique version ID on creation
- [ ] Policy appears in the policy list in the administrative UI immediately after creation

---

### US-02: Edit ABAC Policy
**Story Points:** 3 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to edit an existing ABAC policy's conditions or action
**So that** I can refine policies without deleting and recreating them

**Acceptance Criteria:**
- [ ] Admin can update any field of an existing policy (name, conditions, action, priority)
- [ ] Edits create a new version; previous version is retained for rollback
- [ ] Edited policy takes effect within 5 seconds of saving
- [ ] Audit log records who edited the policy and when

---

### US-03: Delete ABAC Policy
**Story Points:** 2 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to delete an ABAC policy
**So that** I can remove obsolete or superseded rules

**Acceptance Criteria:**
- [ ] Admin can delete a policy from the active set
- [ ] Deletion does not purge the version history
- [ ] Audit log records policy deletion with timestamp and admin identity
- [ ] Active enforcement immediately reflects the removal

---

### US-04: Rollback Policy Version
**Story Points:** 5 | **MoSCoW:** Should

**As a** DLP Admin
**I want** to roll back to a previous version of a policy
**So that** I can quickly revert a bad policy change

**Acceptance Criteria:**
- [ ] Admin can view the version history of any policy
- [ ] Admin can select a previous version and restore it as active
- [ ] Rollback creates a new version entry (non-destructive)
- [ ] Restored version takes effect within 5 seconds

---

### US-05: Assign Data Classification
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to assign a sensitivity tier (T1–T4) to a file or folder
**So that** ABAC policies have the classification data they need to make decisions

**Acceptance Criteria:**
- [ ] Admin can assign T1 (Public), T2 (Internal), T3 (Confidential), or T4 (Restricted) to any monitored path
- [ ] Classification can be applied to individual files or entire folder trees
- [ ] Classification metadata is stored persistently and survives agent restarts
- [ ] Classification change generates an audit event
- [ ] End users can see (but not modify) the classification label of files they access

---

### US-06: Define Exclusions
**Story Points:** 3 | **MoSCoW:** Should

**As a** DLP Admin
**I want** to define exclusion paths that bypass DLP enforcement
**So that** IT scan tools and approved processes can operate without triggering false positives

**Acceptance Criteria:**
- [ ] Admin can add, edit, and remove exclusion paths
- [ ] Exclusions are evaluated before the ABAC policy engine
- [ ] Exclusion rules are logged for audit purposes
- [ ] Exclusions are validated as valid paths

---

### US-X: Trigger On-Demand File Scan
**Story Points:** 3 | **MoSCoW:** May

**As a** DLP Admin
**I want** to trigger an on-demand scan of a file or directory for classification review
**So that** I can verify or update classification without waiting for the next scheduled scan

**Acceptance Criteria:**
- [ ] Admin can select a file or directory and trigger an immediate classification scan
- [ ] Scan results show: path, detected classification, scan timestamp
- [ ] Admin can confirm or override the detected classification
- [ ] Scan completion triggers an audit event
- [ ] Long-running scans show a progress indicator and can be cancelled

---

## Epic 2: Endpoint Enforcement
**Epic ID:** EP-02 | **Story Points:** 40 | **MoSCoW:** Must

*As a DLP Agent, I need to intercept file operations and enforce ABAC decisions on endpoints so that data is protected wherever it is stored or moved.*

---

### US-07: Intercept File Operations
**Story Points:** 8 | **MoSCoW:** Must

**As a** DLP Agent
**I want** to intercept file open, save, and copy operations on monitored paths
**So that** I can evaluate each operation against ABAC policy before allowing it to proceed

**Acceptance Criteria:**
- [ ] Agent intercepts CreateFile, WriteFile, ReadFile, and CopyFile operations on configured monitored paths
- [ ] Intercepted operations include the requesting user's SID, target file path, and operation type
- [ ] Operations on non-monitored paths are passed through without interception
- [ ] Intercepted operations incur no more than 50ms additional latency

---

### US-08: Enforce ABAC Decision
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Agent
**I want** to enforce the ABAC decision returned by the Policy Engine
**So that** ALLOW operations proceed and DENY operations are blocked

**Acceptance Criteria:**
- [ ] ALLOW → operation proceeds without interruption
- [ ] ALLOW_WITH_LOG → operation proceeds; audit event is emitted
- [ ] DENY → operation is blocked; user is notified; audit event is emitted
- [ ] DENY_WITH_ALERT → operation is blocked; user is notified; audit event emitted; alert is sent to SIEM and/or admin
- [ ] Critical Rule enforced: if NTFS allows but ABAC denies, final result is DENY

---

### US-09: Block USB Mass Storage Copy
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Agent
**I want** to detect when a classified file (T3 or T4) is being copied to a USB mass storage device
**So that** I can prevent data exfiltration via removable media

**Acceptance Criteria:**
- [ ] Agent detects USB mass storage device enumeration events
- [ ] Agent blocks the file write operation to the USB device when the file's classification is T3 or T4
- [ ] T1 and T2 file copies to USB are allowed with logging
- [ ] User receives a blocking notification with the reason (e.g., "Transfer blocked: T4 file to removable media")
- [ ] Audit event is emitted with device ID, file path, and classification

---

### US-10: Block Unauthorized Network Upload
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Agent
**I want** to detect and block file upload to unauthorized SMB shares, FTP servers, and web upload endpoints
**So that** I can prevent data exfiltration over the network

**Acceptance Criteria:**
- [ ] Agent detects outbound SMB write operations to shares not on the approved list
- [ ] Agent detects FTP PUT operations to unauthorized servers
- [ ] Agent detects HTTP POST to unauthorized upload endpoints for files with classification T3 or T4
- [ ] Unauthorized uploads are blocked and audit events are emitted
- [ ] Admin can configure the approved share/server whitelist

---

### US-11: Offline Mode (Cached Decisions)
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Agent
**I want** to continue enforcing cached ABAC decisions when the Policy Engine is unreachable
**So that** data protection is not dependent on network connectivity

**Acceptance Criteria:**
- [ ] Agent caches the last N policy decisions (configurable, default 10,000 entries)
- [ ] Cache entries have a configurable TTL (default 1 hour)
- [ ] When Policy Engine is unreachable, agent evaluates requests against the cache
- [ ] Cache miss in offline mode defaults to DENY for T3/T4 resources (fail-closed)
- [ ] Agent automatically resumes live Policy Engine queries when connectivity is restored
- [ ] Heartbeat mechanism detects Policy Engine availability within 30 seconds

---

### US-12: Notify User on Block
**Story Points:** 3 | **MoSCoW:** Must

**As a** DLP UI
**I want** to display a non-intrusive toast notification to the end user when the Agent blocks an operation
**So that** the user understands why the action was prevented and knows how to proceed through proper channels

**Acceptance Criteria:**
- [ ] Notification appears as a Windows toast notification (not a modal dialog)
- [ ] Notification includes: file name, action blocked, classification level, contact info for exceptions
- [ ] Notification auto-dismisses after 5 seconds or on user acknowledgement
- [ ] Notification is triggered by BLOCK_NOTIFY message received from Agent over Pipe 1
- [ ] User can click "Request Override" in the notification to open the override justification dialog

---

### US-13: Endpoint Health and Heartbeat
**Story Points:** 3 | **MoSCoW:** Must

**As a** DLP Agent
**I want** to send a heartbeat to the Policy Engine every 30 seconds
**So that** the admin can see which endpoints are online and the engine can track agent version and status

**Acceptance Criteria:**
- [ ] Agent sends gRPC heartbeat with: agent_id, hostname, OS version, agent version, timestamp
- [ ] Policy Engine marks agent as offline if heartbeat is missed for 3 consecutive intervals (90 seconds)
- [ ] Agent can be configured with primary and secondary Policy Engine endpoints
- [ ] Agent reconnects automatically when a previously unavailable engine becomes reachable

---

## Epic 3: Policy Engine Operations
**Epic ID:** EP-03 | **Story Points:** 26 | **MoSCoW:** Must

*As a Policy Engine, I need to evaluate ABAC policies accurately and at low latency so that every enforcement decision is correct and fast enough for production use.*

---

### US-14: Evaluate Policy Request
**Story Points:** 8 | **MoSCoW:** Must

**As a** Policy Engine
**I want** to receive an ABAC evaluation request and return a decision
**So that** DLP Agents know whether to allow or deny each file operation

**Acceptance Criteria:**
- [ ] Engine accepts gRPC EvaluateRequest with: subject (user_sid, groups, device_trust), resource (path, classification), environment (time, network_location), action (READ / WRITE / COPY / DELETE)
- [ ] Engine evaluates all applicable policies in priority order (first-match wins)
- [ ] Engine returns EvaluateResponse with: decision (ALLOW / DENY / ALLOW_WITH_LOG / DENY_WITH_ALERT), matched_policy_id, reason string
- [ ] Engine returns within 50ms at P95 for a single request
- [ ] Engine queries AD for current group membership if not provided by the agent

---

### US-15: Hot-Reload Policies
**Story Points:** 5 | **MoSCoW:** Should

**As a** Policy Engine
**I want** to reload policies from the policy store without restarting
**So that** policy changes take effect immediately without disrupting enforcement

**Acceptance Criteria:**
- [ ] Engine monitors the policy store directory for file changes
- [ ] On change detection, engine validates and reloads policies within 5 seconds
- [ ] In-flight evaluation requests complete against the pre-change policy set
- [ ] Malformed policies cause a reload failure with a logged error; previous valid policy set remains active

---

### US-16: AD Group Membership Lookup
**Story Points:** 5 | **MoSCoW:** Must

**As a** Policy Engine
**I want** to query Active Directory for a user's current group memberships and device trust attributes
**So that** ABAC policies can make context-aware decisions based on the live AD state

**Acceptance Criteria:**
- [ ] Engine accepts a user SID and returns all AD group SIDs the user is a member of
- [ ] Engine returns the device trust level (Managed / Unmanaged / Compliant) from AD
- [ ] Engine caches AD query results with a short TTL (default 5 minutes) to limit AD load
- [ ] Engine degrades gracefully if AD is temporarily unreachable (uses cached results)
- [ ] All AD queries are logged for audit purposes

---

### US-17: gRPC API for Policy CRUD
**Story Points:** 8 | **MoSCoW:** Must

**As a** DLP Admin (via UI) or automated system
**I want** to manage policies through a REST/gRPC API
**So that** I can integrate policy management into existing workflows and automation pipelines

**Acceptance Criteria:**
- [ ] REST API supports: GET /policies (list), POST /policies (create), PUT /policies/{id} (update), DELETE /policies/{id} (delete), GET /policies/{id}/versions (history)
- [ ] API authenticates callers via bearer token (dlp-admin session token)
- [ ] API returns structured error responses with error codes and messages
- [ ] API is documented in OpenAPI 3.0 / Swagger format
- [ ] All CRUD operations are audit-logged

---

## Epic 4: Audit & Compliance
**Epic ID:** EP-04 | **Story Points:** 24 | **MoSCoW:** Must

*As a DLP Admin or Auditor, I need a complete, tamper-evident audit trail of all enforcement events so that I can investigate incidents, demonstrate compliance, and meet regulatory requirements.*

---

### US-18: Emit Audit Events
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Agent or Policy Engine
**I want** to emit structured JSON audit events for every enforcement action
**So that** all security-relevant activity is recorded for investigation and compliance

**Acceptance Criteria:**
- [ ] Every intercepted file operation emits an AuditEvent in JSON format
- [ ] AuditEvent schema: `timestamp` (ISO 8601), `event_type` (ACCESS / BLOCK / ALERT / CONFIG_CHANGE), `user_sid`, `user_name`, `resource_path`, `classification` (T1–T4), `action_attempted`, `decision`, `policy_id`, `policy_name`, `agent_id`, `session_id`, `device_trust`, `network_location`
- [ ] File content (payload) is never included in audit events
- [ ] Events are emitted in real-time; no batching beyond 1 second

---

### US-19: SIEM Integration
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Agent
**I want** to send audit events to the SIEM platform (Splunk or ELK) over TLS
**So that** security analysts have centralized visibility into DLP activity

**Acceptance Criteria:**
- [ ] Agent sends events to Splunk via HTTP Event Collector (HEC) over TLS 1.3
- [ ] Agent sends events to ELK via HTTP Ingest over TLS 1.3
- [ ] Connection uses mTLS with a DLP-issued certificate
- [ ] SIEM endpoint and credentials are configurable in the agent config
- [ ] Events include the correct `sourcetype` / `index` fields for Splunk, or correct `_index` for ELK

---

### US-20: Local Encrypted Buffer
**Story Points:** 3 | **MoSCoW:** Should

**As a** DLP Agent
**I want** to write audit events to a local encrypted buffer when SIEM is unreachable
**So that** no audit events are lost during network outages

**Acceptance Criteria:**
- [ ] Buffer is stored on the local filesystem in an encrypted form (AES-256)
- [ ] Buffer is append-only; existing entries cannot be modified
- [ ] Buffer is drained automatically when SIEM connectivity is restored
- [ ] Buffer has a configurable maximum size; oldest events are evicted only after confirmed SIEM delivery
- [ ] Buffer overflow triggers an alert to the DLP Admin

---

### US-21: Query and Export Audit Logs
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to query and export audit logs from the administrative UI
**So that** I can investigate incidents and provide evidence for audits

**Acceptance Criteria:**
- [ ] Admin can filter logs by: date/time range, user (SID or name), resource path, classification, event type, decision, agent_id
- [ ] Admin can export filtered results as CSV or JSON
- [ ] Export is paginated (max 10,000 records per page)
- [ ] Audit log access is itself audit-logged (who queried what, when)

---

### US-22: Real-Time Alerts
**Story Points:** 3 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to receive real-time alerts when T3 or T4 policy violations occur
**So that** I can respond immediately to potential data exfiltration attempts

**Acceptance Criteria:**
- [ ] Every DENY_WITH_ALERT decision triggers an immediate alert
- [ ] Alert delivery channels: email (SMTP/TLS), webhook (HTTPS/TLS)
- [ ] Alert includes: user identity, file path, classification, action attempted, timestamp, agent hostname
- [ ] DLP Admin can configure alert thresholds (e.g., alert on every T4 block, or summarize T3 blocks every 5 minutes)
- [ ] Alert recipients are configurable in the administrative UI

---

## Epic 5: Administrative UI
**Epic ID:** EP-05 | **Story Points:** 24 | **MoSCoW:** Must

*As a DLP Admin, I need a dedicated administrative interface so that I can manage the entire DLP system from a single, role-appropriate UI without requiring command-line access.*

---

### US-23: Policy Management Panel
**Story Points:** 8 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to manage all ABAC policies from a single UI panel
**So that** I can create, view, edit, delete, and version-control policies without direct database access

**Acceptance Criteria:**
- [ ] Policy list displays: name, description, priority, status (active/inactive), last modified, version
- [ ] Policy editor allows full CRUD with condition builder (attribute dropdowns + operators)
- [ ] Syntax validation runs in real-time as the policy is edited
- [ ] Version history tab shows all previous versions with diff view
- [ ] All changes require confirmation before saving

---

### US-24: System Health Dashboard
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to view real-time system health at a glance
**So that** I can quickly identify outages, degraded performance, or anomalous activity

**Acceptance Criteria:**
- [ ] Dashboard shows: Policy Engine uptime and version, total connected agents, agents online vs. offline
- [ ] Dashboard shows: requests per second, P95 decision latency, cache hit rate
- [ ] Dashboard shows: T1–T4 block/allow counts for the last 24 hours (bar chart)
- [ ] Dashboard shows: top 5 users with most policy blocks (potential insider risk)
- [ ] Auto-refreshes every 30 seconds; admin can also force-refresh

---

### US-25: Incident Log Viewer
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to view, search, and filter the incident log
**So that** I can investigate specific policy violations and security events

**Acceptance Criteria:**
- [ ] Incident log displays all BLOCK and ALERT events in reverse chronological order
- [ ] Each entry shows: timestamp, user, file path, classification, action, policy name, agent hostname
- [ ] Full-text search across all fields
- [ ] Filter panel with all fields from the AuditEvent schema
- [ ] Clicking an entry opens a detail panel with the full event payload

---

### US-26: DLP Admin MFA Authentication
**Story Points:** 3 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to authenticate with MFA before accessing the administrative UI
**So that** unauthorized users cannot manage policies or view sensitive incident data

**Acceptance Criteria:**
- [ ] Login page requires: username + password + MFA code (TOTP)
- [ ] Supported MFA: TOTP (RFC 6238) — Google Authenticator, Microsoft Authenticator, hardware tokens
- [ ] Session expires after 8 hours of inactivity; re-authentication required
- [ ] Failed MFA attempts are logged and trigger an alert after 3 consecutive failures
- [ ] MFA enrollment is handled through a secure self-service portal or IT-issued secret

---

### US-27: Exception Request Workflow
**Story Points:** 3 | **MoSCoW:** Should

**As a** End User
**I want** to submit an exception request when I believe a DLP block is preventing legitimate work
**So that** the DLP Admin can review and approve legitimate exceptions

**Acceptance Criteria:**
- [ ] End user can submit exception request from the blocking notification or a self-service portal
- [ ] Request includes: user identity, file/resource, classification, business justification, duration requested
- [ ] DLP Admin receives notification of the pending request
- [ ] Admin can approve (temporary or permanent) or deny with a reason
- [ ] Approved exceptions create a temporary policy exemption (auto-expires)
- [ ] Exception approvals and denials are audit-logged

---

### US-X: Manage Endpoint Agent Configurations
**Story Points:** 3 | **MoSCoW:** Should

**As a** DLP Admin
**I want** to push configuration updates to deployed endpoint agents
**So that** I can change monitored paths, policy engine endpoints, or cache TTL without redeploying agents

**Acceptance Criteria:**
- [ ] Admin can view current configuration of each connected agent
- [ ] Admin can push configuration changes to selected agents
- [ ] Agent acknowledges config change and reloads within 30 seconds
- [ ] Config change is audit-logged with admin identity and timestamp
- [ ] Offline agents receive config on next connection

---

## Epic 6: Deployment & Operations
**Epic ID:** EP-06 | **Story Points:** 21 | **MoSCoW:** Must

*As an IT Operations team, I need reliable, automatable deployment and operational runbooks so that the DLP system can be installed, configured, monitored, and recovered without specialized knowledge.*

---

### US-28: Agent Deployment via MSI
**Story Points:** 5 | **MoSCoW:** Must

**As an** IT Operations team
**I want** to deploy the DLP Agent via MSI installer
**So that** I can use existing enterprise deployment tools (SCCM, Intune) to roll out the agent at scale

**Acceptance Criteria:**
- [ ] MSI installer accepts command-line arguments: Policy Engine endpoint, agent ID, monitored paths
- [ ] Agent installs silently without user interaction
- [ ] Agent registers with the Policy Engine on first launch
- [ ] Installer logs all steps to a log file for troubleshooting
- [ ] Uninstaller cleanly removes the agent and all configuration

---

### US-29: Policy Engine Failover
**Story Points:** 5 | **MoSCoW:** Should

**As an** IT Operations team
**I want** the Policy Engine to support active-passive failover
**So that** agent connectivity is maintained during planned maintenance or unplanned outages

**Acceptance Criteria:**
- [ ] Active Policy Engine instance is load-balanced; passive instance is on standby
- [ ] Agents are configured with primary and secondary engine endpoints
- [ ] Failover to passive instance occurs automatically within 60 seconds of primary failure
- [ ] No enforcement decisions are lost during failover (buffered by agents in offline mode)
- [ ] Failover and failback events are logged and alerted

---

### US-30: Operational Runbook
**Story Points:** 3 | **MoSCoW:** Must

**As an** IT Operations team
**I want** a documented runbook for common operational procedures
**So that** I can manage the DLP system without needing engineering support for routine tasks

**Acceptance Criteria:**
- [ ] Runbook covers: initial deployment, policy update procedures, agent upgrade, engine restart, failover trigger, backup/restore of policy store, log rotation
- [ ] Each procedure has step-by-step instructions with expected outputs
- [ ] Runbook is stored in `docs/OPERATIONAL.md` and version-controlled
- [ ] Runbook is reviewed and updated after each operational incident

---

### US-31: Policy Engine Scaling
**Story Points:** 5 | **MoSCoW:** Must

**As an** IT Operations team
**I want** the Policy Engine to support horizontal scaling
**So that** the system can handle 10,000+ agents without degrading latency

**Acceptance Criteria:**
- [ ] Multiple Policy Engine instances can run behind a load balancer
- [ ] Engine instances share no mutable state (stateless evaluation, policy store on shared NFS or database)
- [ ] Load balancer health checks remove unhealthy instances automatically
- [ ] System supports ≥ 10,000 decision requests per second at P95 latency ≤ 50ms with 4 engine instances
- [ ] Auto-scaling configuration (Terraform/Ansible) is documented

---

### US-32: Backup and Restore
**Story Points:** 3 | **MoSCoW:** Should

**As an** IT Operations team
**I want** to back up and restore the policy store and agent configuration
**So that** I can recover from data loss or a corrupted policy set

**Acceptance Criteria:**
- [ ] Policy store is backed up automatically every 24 hours to an encrypted, off-site location
- [ ] Agent configuration (monitored paths, engine endpoints) is backed up and versioned
- [ ] Restore procedure restores the most recent backup with a single command
- [ ] Restore does not require agent redeployment
- [ ] Backup integrity is verified with a SHA-256 checksum

---

## Epic 7: Agent-as-Service Operations
**Epic ID:** EP-07 | **Story Points:** 40 | **MoSCoW:** Must

*As a DLP system, the Agent must run as a Windows Service under the SYSTEM account and delegate all user-facing work to a separate UI process, while both processes remain protected from unauthorized termination.*

---

### US-A1: Run as Windows Service
**Story Points:** 5 | **MoSCoW:** Must

**As an** IT Operations team
**I want** the DLP Agent to run as a Windows Service under the SYSTEM account
**So that** it starts automatically at boot, survives user logoff, and runs with sufficient privilege to intercept file operations

**Acceptance Criteria:**
- [ ] Agent registers as a Windows Service via `sc create dlp-agent type= own start= auto binpath= "C:\Program Files\DLP\dlp-agent.exe"`
- [ ] Service starts automatically on Windows boot without user interaction
- [ ] Service survives logoff of the interactive user session without stopping
- [ ] Agent is single-instance: a second start attempt via `sc start` or `StartService` API is rejected with error code ERROR_SERVICE_ALREADY_RUNNING
- [ ] `sc query dlp-agent` shows correct state: RUNNING, STOPPED, or STOP_PENDING

---

### US-A2: Spawn UI on Service Startup
**Story Points:** 5 | **MoSCoW:** Must

**As the** DLP Agent
**I want** to spawn the Tauri DLP UI as a child subprocess on the interactive desktop when the service starts
**So that** the UI runs in the correct user session where it can interact with the end user

**Acceptance Criteria:**
- [ ] On service start, Agent calls `WTSGetActiveConsoleSessionId` to detect the active console session
- [ ] Agent calls `CreateProcessAsUser` with that session's token to launch the Tauri UI on the correct desktop
- [ ] The Tauri executable path and arguments are passed from Agent configuration
- [ ] If no interactive session exists (e.g., headless server), Agent starts without UI and logs a warning
- [ ] UI subprocess is owned by the Agent; if UI exits unexpectedly, Agent detects this within 15 seconds and respawns it

---

### US-A3: IPC via 3 Named Pipes
**Story Points:** 8 | **MoSCoW:** Must

**As the** DLP Agent and DLP UI
**We want** a reliable IPC channel so that the Agent can delegate all user-facing work to the UI without sharing a process
**So that** the Agent (running as SYSTEM) can display notifications and collect user input without direct desktop access

**Acceptance Criteria:**
- [ ] Exactly 3 named pipes are used: `\\.\pipe\DLPCommand` (2-way duplex), `\\.\pipe\DLPEventAgent2UI` (fire-and-forget Agent→UI), `\\.\pipe\DLPEventUI2Agent` (fire-and-forget UI→Agent)
- [ ] All pipes use `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE` mode
- [ ] All messages are UTF-8 JSON; no binary protocol
- [ ] Pipe 1 handles blocking request/response: BLOCK_NOTIFY, OVERRIDE_REQUEST, CLIPBOARD_READ
- [ ] Pipe 2 handles fire-and-forget Agent→UI: TOAST, STATUS_UPDATE, HEALTH_PING
- [ ] Pipe 3 handles fire-and-forget UI→Agent: HEALTH_PONG, UI_READY, UI_CLOSING
- [ ] Pipe connections are authenticated: UI must present a signed connect token; Agent validates before accepting

---

### US-A4: Mutual Health Monitoring
**Story Points:** 5 | **MoSCoW:** Must

**As the** DLP Agent
**I want** to monitor the UI's health and respawn it if it becomes unresponsive
**So that** the UI is always available when needed and a crashed UI cannot be used to disable DLP

**Acceptance Criteria:**
- [ ] Agent sends HEALTH_PING over Pipe 2 every 5 seconds
- [ ] If Agent receives no HEALTH_PONG over Pipe 3 within 15 seconds, Agent kills the UI process and respawnes it
- [ ] If Agent receives UI_CLOSING over Pipe 3 (e.g., user logs off), Agent respawns the UI when a new session is detected
- [ ] UI sends HEALTH_PONG over Pipe 3 every 5 seconds
- [ ] If UI receives no message from Agent over Pipe 2 for 15 seconds, UI terminates itself within 5 seconds
- [ ] UI sends UI_READY over Pipe 3 immediately after successfully connecting to all 3 pipes

---

### US-A5: Protect from Termination
**Story Points:** 5 | **MoSCoW:** Must

**As a** DLP System
**I want** both the Agent (service) and the UI process to be resistant to termination by unauthorized users
**So that** attackers cannot trivially bypass DLP controls by killing the agent or UI process

**Acceptance Criteria:**
- [ ] On startup, Agent applies a DACL to its own process denying `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` to Authenticated Users and non-dlp-admin Administrators
- [ ] Agent applies the same DACL to the UI subprocess after spawning it
- [ ] Only the dlp-admin SID (configured in registry) is granted an explicit exception allowing termination
- [ ] dlp-admin exception is verified before any process termination is accepted
- [ ] Non-dlp-admin administrators cannot kill Agent or UI via Task Manager, Process Explorer, or `taskkill /F`
- [ ] Normal users cannot kill Agent or UI via Task Manager or `taskkill`
- [ ] Protection applied via `SetSecurityInfo` / `SetKernelObjectSecurity` Windows APIs

---

### US-A6: Password-Protected Service Stop
**Story Points:** 8 | **MoSCoW:** Must

**As a** DLP Admin
**I want** to stop the DLP Agent only after entering the dlp-admin password
**So that** unauthorized or accidental service stops are prevented, including by compromised admin accounts

**Acceptance Criteria:**
- [ ] When `sc stop dlp-agent` is issued, the service does NOT stop immediately; it enters STOP_PENDING state
- [ ] Agent sends PASSWORD_DIALOG message over Pipe 1 to the UI
- [ ] UI displays a dialog: title "DLP Agent — Confirm Shutdown", text "Enter dlp-admin credentials to stop the DLP Agent", username field (pre-filled with dlp-admin), password field (masked), Submit and Cancel buttons
- [ ] On Submit: UI sends PASSWORD_SUBMIT over Pipe 1; Agent validates credentials via AD LDAP bind as the dlp-admin user DN
- [ ] On correct password: Agent sets service to STOP_PENDING, terminates UI cleanly, stops service cleanly within 30 seconds
- [ ] On wrong password: UI shows error "Incorrect password. Attempt X of 3"
- [ ] After 3 consecutive wrong attempts: Agent logs EVENT_DLP_ADMIN_STOP_FAILED (user, machine, timestamp, attempt count), cancels the stop, returns service to RUNNING state
- [ ] On Cancel: UI sends PASSWORD_CANCEL over Pipe 1; Agent returns service to RUNNING state
- [ ] Password field is protected by DPAPI (CryptProtectData) before transmission over Pipe 1

---

### US-A7: Clipboard Interaction via UI
**Story Points:** 5 | **MoSCoW:** Must

**As the** DLP Agent
**I want** the UI to handle clipboard operations on my behalf
**So that** clipboard content can be scanned for DLP classification without the SYSTEM account's clipboard isolation issues

**Acceptance Criteria:**
- [ ] Agent sends CLIPBOARD_READ over Pipe 1 (2-way), waits for response (timeout 10 seconds)
- [ ] UI calls Windows clipboard API to read current clipboard text content
- [ ] UI sends CLIPBOARD_DATA over Pipe 1 response with the clipboard text content (or empty if not text)
- [ ] Agent sends clipboard content to Policy Engine for content inspection
- [ ] If clipboard read fails or times out, Agent defaults to a conservative classification decision

---

### US-A8: User Logoff Handling
**Story Points:** 3 | **MoSCoW:** Must

**As the** DLP Agent
**I want** to detect when the interactive user logs off and cleanly shut down the UI
**So that** no orphaned UI processes remain after logoff

**Acceptance Criteria:**
- [ ] Agent monitors session change events (WTSRegisterSessionNotification)
- [ ] On Session_Logoff event for the active session: Agent sends UI_CLOSING_SEQUENCE over Pipe 2, waits up to 5 seconds for UI to exit
- [ ] If UI does not exit within 5 seconds, Agent terminates it forcefully
- [ ] Agent continues running (service is not stopped)
- [ ] When a new interactive session is detected (WTSSessionNotification), Agent respawns the UI in the new session
- [ ] Agent emits audit event SESSION_LOGOFF with session ID and timestamp

---

## Epic 8: dlp-server Central Management
**Epic ID:** EP-08 | **Story Points:** 42 | **MoSCoW:** Must

*As the DLP system, we need a central management server (dlp-server) that owns all administrative concerns — agent registry, audit storage, SIEM relay, admin auth, and policy sync — so that agents don't carry operational complexity and the admin portal has a single authoritative API to call.*

---

### US-S1: Agent Registry
**Story Points:** 5 | **MoSCoW:** Must

**As** dlp-server
**I want** to maintain a registry of all connected agents so that the admin can see which endpoints are online
**So that** the dlp-admin-portal can display agent health in the dashboard

**Acceptance Criteria:**
- [ ] Agents register on startup by calling POST /agents/register with: agent_id, hostname, IP, OS version, agent version
- [ ] dlp-server adds agent to the registry and returns the agent's configuration
- [ ] Agents send heartbeat to GET /agents/{id}/heartbeat every 30 seconds
- [ ] dlp-server marks an agent offline if no heartbeat is received for 3 consecutive intervals (90 seconds)
- [ ] dlp-admin-portal calls GET /agents to display agent health dashboard (online/offline/degraded count, per-agent detail)

---

### US-S2: Centralized Audit Ingestion
**Story Points:** 8 | **MoSCoW:** Must

**As** dlp-server
**I want** to receive audit events from all agents and store them centrally
**So that** the admin can query logs without accessing SIEM and all events are preserved for compliance

**Acceptance Criteria:**
- [ ] Agents call POST /audit/events with an AuditEvent JSON body over HTTPS
- [ ] dlp-server writes events to append-only storage (no update or delete API exposed)
- [ ] Query API GET /audit/events supports filtering by: date range, user_sid, resource_path, classification, event_type, decision, agent_id
- [ ] Export endpoint returns filtered results as CSV or JSON
- [ ] File content (payload) is never stored — only metadata

---

### US-S3: SIEM Relay
**Story Points:** 5 | **MoSCoW:** Must

**As** dlp-server
**I want** to forward audit events to SIEM so that agents don't need individual SIEM credentials
**So that** we can manage SIEM credentials in one place and reduce the attack surface

**Acceptance Criteria:**
- [ ] dlp-server batches events: max 1 second latency or max 1,000 events per batch
- [ ] dlp-server sends batched events to Splunk HEC over HTTPS/TLS 1.3
- [ ] dlp-server sends batched events to ELK HTTP Ingest over HTTPS/TLS 1.3
- [ ] When SIEM is unreachable, dlp-server buffers events locally (encrypted, append-only)
- [ ] Buffered events are automatically drained when SIEM connectivity is restored
- [ ] SIEM credentials are stored in dlp-server configuration only — agents hold only dlp-server credentials

---

### US-S4: Admin Auth Server
**Story Points:** 8 | **MoSCoW:** Must

**As** dlp-server
**I want** to validate admin credentials and issue JWT sessions so that the dlp-admin-portal has a secure auth backend
**So that** only authenticated admins can manage policies, view logs, or approve exceptions

**Acceptance Criteria:**
- [ ] Admin login via POST /auth/login with: username, password, TOTP code
- [ ] TOTP validation (RFC 6238) accepts any compliant authenticator app
- [ ] On success: dlp-server returns a JWT (8-hour expiry) and a refresh token
- [ ] dlp-server stores admin credentials using PBKDF2 + salt (not plaintext)
- [ ] All subsequent dlp-admin-portal API calls must include the JWT bearer token
- [ ] Every admin API call is logged with admin identity, action, timestamp, and client IP

---

### US-S5: Alert Router
**Story Points:** 5 | **MoSCoW:** Must

**As** dlp-server
**I want** to route DENY_WITH_ALERT events to configured destinations so that admins get immediate notification of serious violations
**So that** critical incidents are detected and responded to in real time

**Acceptance Criteria:**
- [ ] When a DENY_WITH_ALERT event arrives, dlp-server triggers the alert router
- [ ] Email delivery: SMTP/TLS to configured recipients with event details
- [ ] Webhook delivery: HTTPS/TLS POST to configured webhook URL with event payload
- [ ] Alert routing is asynchronous (does not block the audit event ingestion path)
- [ ] Alert routing failures are logged and retried up to 3 times

---

### US-S6: Policy Sync
**Story Points:** 5 | **MoSCoW:** Must

**As** dlp-server
**I want** to push policies to all policy-engine replicas so that horizontal scaling works correctly
**So that** new or updated policies take effect across all engines without manual intervention

**Acceptance Criteria:**
- [ ] When a policy is created or updated via dlp-admin-portal, dlp-server writes it to the policy DB
- [ ] dlp-server pushes the updated policy set to all connected policy-engine replicas
- [ ] New policy-engine replicas pull the full policy set on startup from dlp-server
- [ ] Policy sync completes within 5 seconds of policy change
- [ ] Sync failures are retried; replicas continue with last-known policy set

---

### US-S7: Exception Store
**Story Points:** 3 | **MoSCoW:** Should

**As** dlp-server
**I want** to store exception/override approval records so that the audit trail includes who approved what and for how long
**So that** compliance reviewers can trace every exception to an approver and justification

**Acceptance Criteria:**
- [ ] When an override is approved by dlp-admin, the record includes: approver, requesting user, resource, justification, timestamp, expiry duration
- [ ] Temporary exceptions auto-expire; expired exceptions stop being honored by the Policy Engine
- [ ] Exception records are queryable and exportable for audit purposes

---

### US-S8: Agent Config Push
**Story Points:** 3 | **MoSCoW:** Should

**As** dlp-server
**I want** to push configuration changes to deployed agents so that admins don't need to redeploy agents to change settings
**So that** operational changes (monitored paths, engine endpoints, cache TTL) can be made centrally and instantly

**Acceptance Criteria:**
- [ ] dlp-admin selects one or more agents in the portal and pushes new configuration
- [ ] dlp-server calls PUT /agents/{id}/config on the target agent over HTTPS
- [ ] Agent acknowledges config change and reloads within 30 seconds
- [ ] Config change is audit-logged with admin identity and timestamp
- [ ] Offline agents receive the new config on next registration

---

## Summary

> **Note:** EP-05 (Administrative UI) is **deferred** to a later phase. Phase 1–4 scope is shaded.

| Epic | Story Points | MoSCoW | Phase |
|------|-------------|--------|-------|
| EP-01: Policy Management | 23 | Must | Phase 1–4 |
| EP-02: Endpoint Enforcement | 34 | Must | Phase 1–4 |
| EP-03: Policy Engine Operations | 26 | Must | Phase 1–4 |
| EP-04: Audit & Compliance | 21 | Must | Phase 1–4 |
| EP-05: Administrative UI | 24 | Must | **Deferred** |
| EP-06: Deployment & Operations | 21 | Should | Phase 4 |
| EP-07: Agent-as-Service Operations | 44 | Must | Phase 1–4 |
| EP-08: dlp-server Central Management | 42 | Must | Phase 5 |
| **Total** | **235** | | |

### Sprint Planning Guide (18-Sprint Increment)

> **Note:** dlp-admin-portal (EP-05: US-05, US-21–27, US-X Agent Config) is **deferred** to a later phase. Sprint planning below reflects Phase 1–4 scope only. Audit logs are read directly from the local JSON file during Phase 1.

| Sprint | Stories | Focus |
|--------|---------|-------|
| Sprint 1 | US-01, US-02, US-03, US-04 | Policy CRUD (policy-engine, local JSON store) |
| Sprint 2 | US-06, US-X (On-Demand Scan) | Exclusions + scan trigger |
| Sprint 3 | US-05, US-14, US-16, US-17 | Classification + Policy Engine core (gRPC + AD) |
| Sprint 4 | US-A1, US-A2, US-A3 | Agent Windows Service + UI spawner + IPC pipe servers |
| Sprint 5 | US-A3, US-A4, US-A5 | IPC via 3 named pipes + mutual health monitoring + process protection |
| Sprint 6 | US-A6, US-A8 | Password-protected service stop + user logoff handling |
| Sprint 7 | US-A7, US-12 | Clipboard via UI + toast notifications |
| Sprint 8 | US-07, US-08, US-13 | Agent core (interception + enforcement + heartbeat) |
| Sprint 9 | US-09, US-10, US-11 | Advanced enforcement (USB, network, offline) |
| Sprint 10 | US-18, US-19, US-20 | Audit event emission + SIEM relay (local JSON, Phase 5 → dlp-server) |
| Sprint 11 | US-21 (deferred w/ portal), US-22 (deferred w/ portal) | Audit log viewer + real-time alerts — deferred with dlp-admin-portal |
| Sprint 12 | US-23, US-24, US-25 (deferred) | dlp-admin-portal UI panels — deferred |
| Sprint 13 | US-26, US-27, US-X (Agent Config) (deferred) | Auth + exception workflow + agent config push — deferred |
| Sprint 14 | US-28, US-30, US-29, US-31, US-32 | Deployment, scaling, failover, runbook, backup |
| Sprint 15 | US-S1, US-S4 | dlp-server: agent registry + admin auth (JWT/TOTP) |
| Sprint 16 | US-S2, US-S3 | dlp-server: audit store + SIEM relay |
| Sprint 17 | US-S5, US-S6, US-S7, US-S8 | dlp-server: alert router + policy sync + exceptions + config push |
