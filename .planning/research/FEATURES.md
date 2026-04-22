# Feature Landscape — v0.6.0 Endpoint Hardening

**Domain:** Enterprise DLP — Application-aware clipboard control, browser boundary enforcement, USB device identity
**Researched:** 2026-04-21
**Scope:** Three new feature areas from SEED-001, SEED-002, SEED-003. Existing features (policy CRUD, boolean engine, clipboard monitoring, USB write-block) are NOT in scope.

---

## Cross-Cutting Note: ABAC Integration Is the Unifying Theme

All three feature areas share one architectural move: promoting a new dimension (process identity, web origin, device identity) to a first-class ABAC `AbacContext` attribute. The evaluator already exists and works; the work in each area is (a) capture the attribute at the enforcement point, (b) wire it into `AbacContext`, and (c) surface it in the TUI for policy authoring. This is the repeating pattern that creates phase-level independence between the three areas once the ABAC extension is done.

---

## Feature Area 1: Application-Aware DLP (SEED-001)

**Goal:** Source and destination process identity become ABAC subject attributes so policies can allow Word→Excel and block Word→Notepad++ or Word→Gmail.

### Dependencies into this area

- `dlp-user-ui/src/clipboard_monitor.rs` — sole interception point for source app (via `GetClipboardOwner`) and destination app (via `GetForegroundWindow`). Both Win32 calls must happen in the user session; the dlp-agent SYSTEM service cannot reach them.
- `dlp-user-ui/src/ipc/pipe3.rs` — `ClipboardAlert` is the protocol contract between UI and agent. It must grow `source_application` and `destination_application` fields. This is a breaking wire-format change.
- `dlp-common/src/abac.rs` — `AbacContext` currently has no process-level fields.
- `dlp-common/src/audit.rs` — `AuditEvent` already has `application_path: Option<String>` and `application_hash: Option<String>` as stubs (always `None` today). Phase work populates them and adds `source_application`/`destination_application` distinction.

### Table Stakes

Features the area must have to be useful at all. Without these, app-aware DLP is not deployable.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Capture destination process image path at paste time | Core of the feature — without knowing destination there is nothing to enforce on | Medium | `GetForegroundWindow` → `GetWindowThreadProcessId` → `QueryFullProcessImageNameW` in clipboard monitor. Must handle NULL handle race (window closed between clipboard change and paste). |
| Capture source process image path at clipboard-change time | Must capture at WM_CLIPBOARDUPDATE — after this point the owner window may close | Medium | `GetClipboardOwner()` → PID → `QueryFullProcessImageNameW`. Synchronous in the clipboard message handler. |
| AppIdentity struct in dlp-common | Canonical type carrying image path, publisher name, signature state | Low | New `dlp-common::app_identity::AppIdentity` struct. Shared between UI, agent, and evaluator. |
| ABAC attributes: source_application, destination_application | Policy engine must be able to express "IF destination_app.publisher != Microsoft THEN DENY" | Low | Add `source_application: Option<AppIdentity>` and `destination_application: Option<AppIdentity>` to `AbacContext`. Add evaluator branches. |
| Pipe 3 protocol extension | ClipboardAlert must carry both app identity fields to the agent | Medium | Breaking change — increment protocol version. Existing integration tests in Phase 99 must be updated. |
| Audit event enrichment: both fields populated | Audit events must carry source and destination application on clipboard block | Low | Extend `AuditEvent` to populate the existing stub fields and add destination distinction. |
| TUI: author policies using app publisher condition | Admin must be able to write "destination_app.publisher = Google" without touching JSON | Medium | Extend the 3-step conditions builder in dlp-admin-cli with two new attribute variants: `SourceApplication` and `DestinationApplication`. Sub-picker selects field (publisher / image_path / trust_tier). |
| Authenticode signature verification (anti-spoofing) | A renamed `notepad.exe → excel.exe` must not bypass an allowlist | High | `WinVerifyTrust` via `windows-rs` or the `verifysign` crate (verified active on crates.io). Must NOT block hot path — verify once per process start, cache by (PID, exe-path). CVE-2013-3900 opt-in strict mode required. |

**Confidence:** HIGH — Microsoft Purview and Symantec DLP both implement source/destination process identity. Purview documents that "Copy to clipboard" is enforced at the source (copy time) with restricted-app-groups for destination. The Purview approach blocks copy when destination is on the restricted list; our approach intercepts at paste time, which is richer. Win32 APIs (`GetClipboardOwner`, `QueryFullProcessImageNameW`) are stable and well-documented.

### Differentiators

Features that reach competitive parity with Symantec DLP, Microsoft Purview endpoint DLP, and Forcepoint.

| Feature | Competitive Peer | Complexity | Notes |
|---------|-----------------|------------|-------|
| Per-process trust tier (corporate / personal / unknown) | Symantec DLP application control | Medium | Derive from signature state + publisher allowlist. Corporate = signed by recognized enterprise publisher. Allows "allow T3→trusted_app, deny T3→personal_app" without listing every executable. |
| Electron app detection via publisher (Slack, Teams, VSCode, Discord) | Symantec DLP application groups | Medium | Electron apps share the same runtime but sign with different publisher certs. Publisher check is the only reliable discriminator. Cache publisher→trust_tier at startup. |
| UWP app identity via AUMID | Microsoft Purview AUMID support | High | `IShellItem` / `GetApplicationUserModelId`. Needed for Store apps (e.g., Windows Terminal, Calculator). Separate code path from Win32 image path resolution. Defer to phase 2 of SEED-001 if timeline is tight. |
| Learn mode: record observed app pairs | Forcepoint adaptive DLP learning | High | Log all (source_app, dest_app, classification) tuples as informational audit events without blocking. Admin reviews and approves or denies each pair in the TUI. Significant UX complexity. Defer out of v0.6.0. |

### Anti-Features

Scope traps. Do not build these in v0.6.0.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Drag-and-drop interception | Different Win32 APIs (OLE IDataObject), much larger surface area. SEED-001 explicitly deferred this | Clipboard only in v0.6.0. Log a comment in the code for future work. |
| Print and Save-As interception | Requires hooking PrintDlg and COMDLG32 — separate attack surface, separate feature | File interception already handles Save-As to monitored paths via the existing file_monitor. No new work needed for that path. |
| Per-user app allowlists | App policy should be per-classification-tier, not per-user. Per-user would explode policy count | Use policy conditions that combine MemberOf (AD group) + destination_app together if user scoping is needed. |
| Block all paste into browsers | Symantec's blunt mode — destroys web workflows | SEED-002 handles browser origin distinction. In v0.6.0 treat the browser as a named publisher ("Google LLC", "Microsoft Corporation") and let SEED-002 in a later phase add origin-level granularity. |
| Binary (process_name = "notepad.exe") matching without signature | Trivially bypassed by renaming. Described as an anti-pattern in Symantec's own docs | Publisher/signature-based matching only. Image path as a supplemental hint, not as a trust anchor. |

### Minimum Viable Slice (v0.6.0)

This is the smallest useful increment that (a) blocks a real exfiltration path and (b) proves the architecture end-to-end.

1. Capture destination process image path at paste time (`GetForegroundWindow` → `QueryFullProcessImageNameW`) in `clipboard_monitor.rs`.
2. Capture source process image path at clipboard-change time (`GetClipboardOwner` → `QueryFullProcessImageNameW`) in the same file.
3. Add `AppIdentity { image_path, publisher, is_signed }` to `dlp-common`.
4. Extend `ClipboardAlert` (Pipe 3) with `source_application: Option<AppIdentity>` and `destination_application: Option<AppIdentity>`.
5. Extend `AbacContext` with both fields; add `SourceApplication` and `DestinationApplication` condition variants to evaluator.
6. Populate existing `AuditEvent.application_path` and add `destination_application_path` field.
7. Add Authenticode publisher extraction (no blocking verification yet — read publisher name from the cert chain using `windows-rs` or `verifysign`). Full `WinVerifyTrust` blocking enforcement ships in a hardening follow-up phase.
8. Extend conditions builder TUI with the two new attribute variants so admin can author rules.

**What this MVP defers:** UWP/AUMID paths, full `WinVerifyTrust` anti-spoofing enforcement, Electron publisher allowlist management screen, learn mode.

**Estimated effort for MVP:** 3-4 phases (Phase 22–25 range). Largest unknowns are the Pipe 3 protocol change (ripples into integration tests) and the Win32 race conditions.

---

## Feature Area 2: Protected Clipboard Browser Boundary (SEED-002)

**Goal:** Distinguish managed vs. unmanaged web origins inside the same browser process. Block paste from a managed SharePoint tab into ChatGPT or personal Gmail without blocking all browser paste.

### Dependencies into this area

- **Strong prerequisite:** SEED-001 (Feature Area 1) must be at least partially complete. The policy engine needs to know "destination is a browser" (process-identity level) before it can reason about what's inside the browser (origin level). SEED-002 is "SEED-001 drilling one level deeper for one specific app family."
- `dlp-server` — must expose a new HTTP endpoint that accepts Chrome's Content Analysis Connector payloads (named-pipe protobuf protocol, server-side exposed as a local agent endpoint, not a network endpoint).
- `dlp-server/src/db.rs` — needs a new `managed_origins` table and CRUD API routes. Follows the exact same pattern as `siem_config` / `alert_router_config`.
- `dlp-admin-cli` — needs a "Managed Origins" screen under the System menu. Follows the same TUI pattern as the SIEM config and Alert config screens.

### Delivery Path for v0.6.0

The SEED-002 brief documents two paths. Path B (Chrome Enterprise Connector integration) is the correct v0.6.0 choice:

- Path B is 3-5 phases vs. Path A's 6-10 phases plus a TypeScript browser extension build toolchain.
- Chrome Enterprise Connector uses the `content_analysis_sdk` — a named-pipe + protobuf protocol. Chrome sends clipboard paste events to a local agent. The agent (our `dlp-agent` native host) responds with ALLOW or BLOCK. No browser extension needed; Chrome must be deployed with enterprise policy `OnBulkDataEnteredEnterpriseConnector`.
- Path A (custom browser extension) is not recommended for v0.6.0 — it adds a TypeScript/esbuild build pipeline, Chrome Web Store review overhead, and MV3 clipboard interception complexity to a Rust-only project.

### Table Stakes

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Chrome Content Analysis Connector endpoint | Chrome's enterprise DLP integration point. Without this, there is no mechanism for the browser to consult our DLP at paste time | High | Implement `content_analysis_sdk` named-pipe server in Rust. Chrome connects via `\\.\pipe\brcm_chrm_cas` (system) or per-user path. Accept protobuf `ContentAnalysisRequest`, return `ContentAnalysisResponse`. |
| Managed origins list: DB table + admin API | Core data model — which web origins are "protected" (SharePoint, M365, Salesforce, internal apps) | Low | New SQLite table `managed_origins(id, origin TEXT, label TEXT, created_at TEXT)`. JWT-protected `GET/POST/DELETE /admin/managed-origins`. |
| Block paste from protected origin to unmanaged origin | The core enforcement rule | Medium | In the Content Analysis handler: check source origin (from Chrome's `ContentAnalysisRequest.request_token` or tab metadata) against managed list. If protected AND destination not in managed list AND classification >= threshold, respond BLOCK. |
| Audit event on browser clipboard block | Compliance requirement — every block must produce an audit event | Low | Emit `AuditEvent` with `source_origin` and `destination_origin` fields. Wire through existing audit pipeline. |
| Admin TUI: Managed Origins screen | Admin must be able to add/remove trusted domains without editing the DB directly | Low | Sixth System menu entry. List + add/remove pattern identical to the SIEM config screen. No new TUI patterns needed. |

**Confidence:** HIGH for Path B mechanics — Google's `content_analysis_sdk` GitHub repository is public, Symantec and Trellix both ship production integrations using it. The named-pipe protobuf protocol is stable since Chrome 118. LOW confidence on the exact protobuf schema field names for source origin — the proto files need to be read directly from the SDK repo; the public docs do not reproduce them.

### Differentiators

| Feature | Competitive Peer | Complexity | Notes |
|---------|-----------------|------------|-------|
| GenAI destination category | Netskope, Zscaler | Medium | Maintain a hardcoded list of GenAI hostnames (chatgpt.com, claude.ai, gemini.google.com, copilot.microsoft.com, etc.) as a named "GenAI" origin group. Policy can reference this group without admin maintaining the list manually. |
| Edge for Business connector | Microsoft Purview Endpoint DLP | High | Edge uses the same `OnBulkDataEnteredEnterpriseConnector` policy key as Chrome. The named-pipe path may differ. Test with Edge enterprise builds. Defer to follow-up phase if scope pressure is high. |
| Source origin tagging persists across tab switch | Island Browser, Netskope | High | Chrome's connector sends source context in the clipboard data itself. If the source tab closes before paste, the origin metadata may be lost. Full solution requires the browser to embed origin in the clipboard payload — this requires Chrome extension APIs, pushing us toward Path A. Defer for v0.6.0; document the limitation. |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Build a custom Chrome/Edge extension (Path A) in v0.6.0 | TypeScript build pipeline, store publication, MV3 constraints — full extra milestone on a solo Rust project | Path B first; document Path A as the v0.7.0 roadmap item for customers without enterprise browser management |
| Firefox and Safari support | Firefox uses WebExtensions (different store, different policy), Safari uses its own model. Neither supports the Chrome Enterprise Connector protocol | Document as out of scope. Windows enterprise environments use Edge or managed Chrome as primary. |
| Network-level URL inspection (SSL inspection) | Requires a proxy or kernel driver — completely different architecture | Out of scope. Path B covers managed Chrome without proxy infrastructure. |
| Origin allowlist with regex or wildcards in v0.6.0 | Adds policy evaluation complexity and a subtle edge-case surface for bypass | Exact-hostname matching only in v0.6.0. Subdomain wildcards (`*.sharepoint.com`) can be added in a follow-up phase with a clear test matrix. |
| Blocking non-enterprise Chrome installs | Personal Chrome (installed by the user) cannot be force-enrolled in Chrome Enterprise policy | Document the customer deployment requirement: Chrome must be managed via Google Admin Console or Intune. |

### Minimum Viable Slice (v0.6.0)

1. Implement `content_analysis_sdk` named-pipe server in Rust (`dlp-agent` or a new `dlp-browser-host` binary registered as a Native Messaging host). Accept `ContentAnalysisRequest`, parse source origin from the request fields, and return `ContentAnalysisResponse`.
2. Add `managed_origins` DB table and `GET/POST/DELETE /admin/managed-origins` admin API routes.
3. Implement enforcement logic: if source origin is in the managed list and the clipboard content classifies as T2+, respond BLOCK when destination origin is not in the managed list.
4. Emit audit events with `source_origin` and `destination_origin` populated.
5. Add "Managed Origins" TUI screen under System menu.
6. Write a customer-facing deployment note: how to configure `OnBulkDataEnteredEnterpriseConnector` Chrome policy to point at the local agent pipe.

**What this MVP defers:** Edge connector, GenAI category, wildcard origin matching, cross-tab origin persistence, Path A extension.

**Estimated effort for MVP:** 2-3 phases. The named-pipe protobuf server is the highest-risk item (unknown Rust ecosystem support — `prost` for protobuf, `tokio::net::windows::named_pipe` for the transport). Validate the protocol by reading the SDK demo agent source before committing to this phase.

**Critical dependency reminder:** Do not start SEED-002 phases until at least one SEED-001 phase has shipped and `AppIdentity` is available in `dlp-common`. The browser process must be identifiable as a browser (via publisher) before origin-level logic adds value.

---

## Feature Area 3: USB Device-Identity Whitelist (SEED-003)

**Goal:** Replace the coarse drive-letter write-block with a VID/PID/Serial-based device registry that supports three trust tiers (blocked, read_only, full_access), user toast notification on block, and ABAC device attributes.

### Dependencies into this area

- `dlp-agent/src/detection/usb.rs` — existing 385-line drive-letter implementation using `RegisterDeviceNotificationW`. All new work extends this file's `DBT_DEVICEARRIVAL` callback. The existing message-pump thread must not be changed in a way that causes the known shutdown-blocking issue (`GetMessageW` blocks forever — do not add join on shutdown).
- `dlp-agent/src/interception/file_monitor.rs` — where the existing write block consults `UsbDetector.blocked_drives`. The read-only tier enforcement hooks here.
- `dlp-common/src/audit.rs` — `AuditEvent` needs an optional `device: Option<DeviceIdentity>` field. Per the existing forward-compat rule (from Phase 4 TM-03), adding this field must be accompanied by updating `alert_router.rs::send_email` to explicitly handle the new field.
- `dlp-server/src/db.rs` — new `device_registry` table. Follows the `siem_config` pattern.
- `dlp-server/src/admin_api.rs` — new CRUD routes. Follows the existing JWT-protected handler pattern.
- `dlp-admin-cli` — new "Device Registry" TUI screen under System menu.
- `dlp-user-ui` — toast notification must run in the user session (same session-0 constraint as clipboard monitoring).

### Table Stakes

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| VID/PID/Serial capture on device arrival | Core of the feature — without device identity there is nothing to enforce on | Medium | `SetupDiGetClassDevsW` / `SetupDiEnumDeviceInfo` / `SetupDiGetDeviceRegistryPropertyW` on `DBT_DEVICEARRIVAL` inside the existing message pump. Use `windows-rs` `Win32::Devices::DeviceAndDriverInstallation` APIs. |
| Device registry: SQLite table + admin API | Where IT registers approved devices with trust tier | Low | New table `device_registry(vid INTEGER, pid INTEGER, serial TEXT, description TEXT, trust_tier TEXT CHECK(...), owner_user TEXT, registered_at TEXT, expires_at TEXT)`. Primary key `(vid, pid, serial)`. `GET/POST/PUT/DELETE /admin/device-registry` routes. |
| Enforcement: unknown device → blocked | Default-deny is the security posture. Unregistered USB must be blocked. | Low | On arrival, if device not in registry, add to blocked-drives set (existing behavior). Emit audit event with device identity fields. |
| Enforcement: trust_tier = read_only | Allow reads, deny writes | Medium | In `file_monitor.rs`, cache `(drive_letter → trust_tier)` in an `RwLock<HashMap<char, TrustTier>>`. On NtWriteFile / NtCreateFile with write access to a read_only drive, deny. On NtReadFile, allow. |
| Enforcement: trust_tier = full_access | Allow all I/O | Low | No interception needed; just do not add the drive to the blocked set. |
| User toast notification on block | Per SEED-003 original requirements: user receives popup with policy explanation. Reduces help-desk tickets. | Medium | `Shell_NotifyIconW` + `NIF_INFO` balloon (Win10/11 compatible) or `ToastNotificationManager` via `windows-rs` COM. Must run in the user session via the dlp-user-ui process (same pattern as clipboard monitoring). Pass block reason text from agent to UI via named pipe. |
| Audit event enrichment: device fields | Compliance requirement — every USB block must carry VID, PID, serial, description | Low | Add `device: Option<DeviceIdentity>` to `AuditEvent`. `DeviceIdentity { vid: u16, pid: u16, serial: String, description: String, manufacturer: String }`. |
| ABAC device attributes | Unifies USB control with the ABAC policy engine. Policies can express `IF device.trust_tier == blocked AND classification >= T3 THEN DenyWithAlert` | Medium | Add `device: Option<DeviceIdentity>` to `AbacContext`. Add `Device` condition variant to the evaluator and conditions builder. |
| Admin TUI: Device Registry screen | IT must be able to register/deregister devices and set trust tier without API calls | Low | System menu entry. List devices with VID/PID/serial/description/tier. `n` to add, `e` to edit tier, `d` to delete. Same TUI pattern as SIEM config. |

**Confidence:** HIGH — Symantec DLP, Forcepoint, and Microsoft Defender Device Control all implement VID/PID/Serial whitelisting with read-only trust tiers. The Windows `SetupDi*` API family is stable. The existing codebase already has the message pump, the RwLock<HashSet> pattern for blocking, and the network_share whitelist as a direct reference implementation.

### Differentiators

| Feature | Competitive Peer | Complexity | Notes |
|---------|-----------------|------------|-------|
| Trust tier expiry (expires_at) | Symantec DLP temporary access | Low | The DB schema already has the `expires_at` column in the SEED design. The agent checks expiry on arrival and on a periodic refresh (same pattern as agent config polling). Allows IT to grant temporary access without manual cleanup. |
| Last-seen timestamp in device list | Defender Device Control | Low | On each `DBT_DEVICEARRIVAL`, update `last_seen` in the registry for known devices. The TUI shows this to help IT audit which devices are actively used. |
| Per-owner-user scoping | Symantec per-user device policies | Medium | The `owner_user` column in the registry allows IT to register a device that is only full_access for a specific AD user. On arrival, check both (vid, pid, serial) AND the logged-on user SID. Complexity: the agent must know who is logged on in the current session. Already available via the existing `user_sid` context in the agent. |
| Device description auto-populated from Windows | Reduces admin data entry | Low | Populate `description` and `manufacturer` from `SetupDiGetDeviceRegistryProperty(SPDRP_DEVICEDESC)` and `SPDRP_MFG`. Show in the registration dialog pre-filled so admin only needs to set the trust tier. |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Mount-time blocking (filesystem filter driver) | Requires a kernel-mode filter driver (FltMgr minifilter or volume device stack attachment). Far outside the current architecture. Known failure mode: missed registrations can hard-crash the system. | I/O-time blocking using the existing `file_monitor.rs` detour. Document the UX trade-off (drive letter appears in Explorer but writes fail) in the user toast text. |
| BitLocker-to-Go encryption enforcement | Requires interop with the BitLocker WMI provider and the Trusted Platform Module. Entirely separate feature. | Out of scope. Mark as SEED-004 if enterprise customers require it. |
| USB-over-IP / RDP device redirection | Different attack surface (network redirectors, not physical USB). Different Win32 detection path. | Out of scope. Defender for Endpoint covers this vector for customers already on that platform. |
| Auto-approval grace period for unknown devices | "First-time seen" workflows where unknown devices get a temporary window before blocking violates the Default Deny principle in CLAUDE.md §3.1. | Block immediately, emit audit event. IT uses the audit event to identify the device and register it if legitimate. |
| Serial number spoofing protection (firmware-level) | USB serial numbers can be programmed by the drive firmware. Detecting forged serials requires hardware attestation (USB 3.2 authentication) which no OS DLP tool implements. | Document the limitation. The baseline (VID+PID+serial match) matches what Symantec and Defender Device Control provide. Full USB authentication is out of scope for the market. |

### Minimum Viable Slice (v0.6.0)

Follows the 6-phase structure described in SEED-003, executed as a coherent milestone group:

1. **Phase A: Device identity enumeration** — extend `usb.rs` to call `SetupDi*` APIs on `DBT_DEVICEARRIVAL`. Log VID/PID/serial/description alongside existing drive-letter event. No behavior change. Pure observability uplift.
2. **Phase B: Device registry DB + admin API** — `device_registry` table, `GET/POST/PUT/DELETE /admin/device-registry` JWT-protected routes.
3. **Phase C: Admin TUI "Device Registry" screen** — list/add/edit/delete with trust tier picker. System menu entry.
4. **Phase D: Read-only trust tier enforcement** — cache `(drive_letter → trust_tier)` in `RwLock<HashMap>`, enforce in `file_monitor.rs`. Blocked drives remain blocked. Full-access drives are no longer intercepted.
5. **Phase E: User toast notification** — pass block reason from agent to `dlp-user-ui` via named pipe. Show `Shell_NotifyIconW` balloon on USB block.
6. **Phase F: ABAC device attributes** — `DeviceIdentity` in `AbacContext`, `Device` condition variant in evaluator and conditions builder. `AuditEvent.device` field populated.

**What this MVP defers:** Per-owner-user scoping (Phase B/D extension), trust tier expiry enforcement (trivial addition once expiry column exists), last-seen timestamp updates, BitLocker integration.

**Estimated effort:** 4-5 phases. Phases A+B can be combined (both are pure server-side data plumbing). Phase D is the highest-risk item — the `file_monitor.rs` detour callback is on a hot path and adding a HashMap lookup must not introduce latency or lock contention. The existing `network_share.rs` RwLock pattern is the direct reference.

**No prerequisite on SEED-001 or SEED-002.** SEED-003 is the most self-contained of the three feature areas. The ABAC integration (Phase F) benefits from SEED-001 being done first (shared ABAC extension pattern) but is not blocked by it.

---

## Feature Dependency Map

```
SEED-001 (App-aware clipboard)
    |
    +---> SEED-002 (Browser boundary)
              [must know "destination is a browser" before caring about the origin inside it]

SEED-003 (USB device identity)
    [independent — can ship before or after SEED-001/002]

ABAC extension work (AbacContext, evaluator, conditions builder TUI)
    [SEED-001 does this first; SEED-003 Phase F reuses the same pattern]
```

**Ordering recommendation:**

Start SEED-001 and SEED-003 in parallel if developer bandwidth allows. SEED-001 unblocks SEED-002. SEED-003 is the most operationally critical (existing USB write-block has known bypass via drive-type spoofing) and has the highest compliance value (SOC 2 CC-6.1, ISO 27001 A.8.3.1). If only one area can ship first, ship SEED-003.

Do not start SEED-002 phases until at least Phase 22-24 of SEED-001 is complete (AppIdentity in dlp-common, Pipe 3 protocol updated, evaluator extended).

---

## Complexity Summary

| Feature Area | Minimum Phase Count | Riskiest Item | Independent of Others? |
|--------------|--------------------:|--------------|------------------------|
| SEED-001 App-aware DLP | 3-4 | Pipe 3 protocol breaking change + Win32 race conditions | Yes (start first) |
| SEED-002 Browser boundary | 2-3 | Named-pipe protobuf server (unknown Rust crate support) | No (needs SEED-001 AppIdentity) |
| SEED-003 USB device identity | 4-5 | file_monitor hot-path latency for read-only tier | Yes (fully independent) |

---

## Sources

- [Microsoft Purview Endpoint DLP — Learn about](https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about) — HIGH confidence (official docs, updated 2026-02-23)
- [Microsoft Purview — Block paste into restricted apps Q&A](https://learn.microsoft.com/en-us/answers/questions/5628325/how-to-block-paste-into-restricted-apps-using-endp) — MEDIUM confidence (community + official)
- [Symantec DLP Chrome Content Analysis Connector SDK](https://knowledge.broadcom.com/external/article/371085/configuring-the-chrome-sdk-connector-for.html) — MEDIUM confidence (vendor docs)
- [chromium/content_analysis_sdk — GitHub](https://github.com/chromium/content_analysis_sdk) — HIGH confidence (official Chromium repository, protobuf + named-pipe transport confirmed)
- [Chrome Enterprise Connectors Framework](https://support.google.com/chrome/a/answer/12166576?hl=en) — HIGH confidence (official Google docs)
- [Symantec DLP USB whitelist via Device Control](https://www.symantec.com/connect/articles/create-white-list-usb-disk-dlp-agent) — MEDIUM confidence (vendor knowledge base)
- [Microsoft Defender Device Control overview](https://learn.microsoft.com/en-us/defender-endpoint/device-control-overview) — HIGH confidence (official docs)
- [verifysign crate (Rust Authenticode)](https://crates.io/crates/verifysign) — MEDIUM confidence (active crate, last updated 2024)
- [pe-sign crate (Rust PE signature)](https://lib.rs/crates/pe-sign) — MEDIUM confidence (active, cross-platform)
- SEED-001, SEED-002, SEED-003 seed files — HIGH confidence (primary source documents for this milestone)
- `.planning/PROJECT.md` and `dlp-common/src/audit.rs` — HIGH confidence (direct codebase inspection)
