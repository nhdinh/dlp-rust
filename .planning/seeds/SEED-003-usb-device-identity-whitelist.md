---
id: SEED-003
status: active
planted: 2026-04-10
planted_during: v0.2.0 — Phase 4 (wire alert router into server)
trigger_when: next endpoint hardening / device control / removable media milestone
scope: Large
---

# SEED-003: USB Device-Identity-Aware Whitelist + Read-Only Mode + User Notification

Upgrade the existing `dlp-agent/src/detection/usb.rs` drive-letter
write-blocker into a full **device-identity-aware USB control subsystem**
that registers approved devices by Vendor ID (VID), Product ID (PID), and
Serial Number, supports a read-only ("connect allowed, write blocked")
trust tier, shows the user a policy popup on block, and emits
admin-console incident reports.

## Why This Matters

**USB is the #1 insider-threat exfiltration path, and the current
implementation is coarse enough to be bypassed.** Today
`dlp-agent/src/detection/usb.rs` only calls `GetDriveTypeW` and blocks
T3/T4 writes to any drive that reports as `DRIVE_REMOVABLE`. This means:

1. **Personally-owned drives are treated identically to corporate-issued
   encrypted drives.** There is no concept of a "registered" device. A
   user can plug in their own USB stick and the agent has no way to know
   it's not the one IT handed them.
2. **There is no "read-only" trust tier.** Many enterprise workflows
   need "allow connect and read from vendor-issued installers, block
   writes" — impossible today because the decision is binary at the
   drive-letter level.
3. **Blocks are silent.** The user gets no feedback that a write was
   denied by policy, so they copy the file three times, blame the file
   system, and file a help-desk ticket instead of learning the rule.
4. **No device-level incident report.** The audit event currently lacks
   VID/PID/Serial/device description. An admin investigating a suspicious
   alert cannot tell which physical device triggered it.
5. **The third enforcement point that bypasses ABAC entirely.** Per
   CLAUDE.md, ABAC is the fine-grained policy layer. Device identity
   (VID, PID, Serial, trust_tier) SHOULD be ABAC subject attributes so
   policies can express rules like `IF device.vid == 0x1234 AND
   classification == T3 THEN deny`. Today USB is a hard-coded binary
   check hidden inside the interception callback.

Closing this gap turns a known bypass into a compliance-grade
removable-media control and unifies the enforcement model around ABAC.

## When to Surface

**Trigger:** Next endpoint hardening / device control / removable media
milestone.

This seed should be presented during `/gsd-new-milestone` when the new
milestone scope mentions any of:

- Endpoint hardening
- Device control / removable media / USB
- Exfiltration prevention / data egress control
- Physical media / portable storage
- Compliance work referencing SOC 2, ISO 27001 CC-6.1, or NIST 800-53 MP-7
- Expanding ABAC subject attributes beyond user/classification
- User-facing policy notifications / toast UI
- Windows `SetupDi*` / device manager integration
- Insider threat program / DLP exfil vector coverage

A milestone named something like "v0.3.0 — endpoint hardening", "v0.4.0 —
removable media control", or "v0.5.0 — compliance baseline" is the
canonical trigger.

## Scope Estimate

**Large** — a full milestone-sized effort, likely 4-6 phases.

Rough phase shape (planner will refine when this seed activates):

1. **Phase A: Device identity enumeration.** Extend
   `dlp-agent/src/detection/usb.rs` to call Windows `SetupDiGetClassDevsW`
   / `SetupDiEnumDeviceInfo` / `SetupDiGetDeviceRegistryPropertyW` on
   `DBT_DEVICEARRIVAL` so the agent captures Hardware ID
   (`USB\VID_xxxx&PID_yyyy`), Serial Number, device description, and
   manufacturer for every inserted device. Log them alongside the
   existing drive-letter event. No behavior change yet — pure
   observability uplift.

2. **Phase B: Device registry DB table + admin API.** Mirror the Phase
   3.1 / Phase 4 pattern: new SQLite table `device_registry` with columns
   `vid INTEGER`, `pid INTEGER`, `serial TEXT`, `description TEXT`,
   `trust_tier TEXT CHECK (trust_tier IN ('blocked', 'read_only',
   'full_access'))`, `owner_user TEXT`, `registered_at TEXT`,
   `expires_at TEXT`. JWT-protected `GET/POST/DELETE
   /admin/device-registry` routes. Hot-reload on every arrival.

3. **Phase C: dlp-admin-cli "Device Registry" TUI screen.** Mirror the
   Phase 4 AlertConfig TUI pattern under the System menu: list registered
   devices, add/edit/remove, set trust tier, view last-seen timestamp.
   Generic `get::<serde_json::Value>("admin/device-registry")` client
   pattern (NOT typed client methods — see Phase 4 gotcha G8).

4. **Phase D: Read-only trust tier enforcement.** Extend the interception
   layer so `trust_tier == 'read_only'` mounts are allowed to mount and
   allow `NtReadFile` but deny `NtWriteFile` / `NtCreateFile` with write
   access. Requires plumbing the trust tier decision from the device
   registry lookup into the file_monitor detour callback without adding
   latency on the hot read path (cache device→tier in an RwLock
   HashMap, invalidated on `DBT_DEVICEREMOVECOMPLETE` and on admin
   registry updates).

5. **Phase E: User notification toast.** Add a Win32 shell notification
   (`Shell_NotifyIconW` + `NIF_INFO` balloon, or the modern
   `ToastNotificationManager` via `windows-rs`) that shows on every
   block with text like "DLP policy blocked writing to 'Kingston
   DataTraveler' — contact IT if you need this device registered." Must
   run in the user session, not session 0 (same pattern as the clipboard
   monitoring fix documented in STATE.md).

6. **Phase F: ABAC integration + admin incident report.** Promote device
   attributes (vid, pid, serial, trust_tier, device_description,
   owner_user) to first-class ABAC subject attributes so policies can
   express rules like `IF device.trust_tier == 'blocked' AND
   classification >= T3 THEN DenyWithAlert`. Extend the existing
   `AuditEvent` in `dlp-common/src/audit.rs` with a nested `device`
   struct (nullable). Admin incident report arrives via the Phase 4
   alert router, so this phase hooks into existing infrastructure.

Out-of-scope for this seed (may become their own seeds):

- Per-device encryption enforcement (requires BitLocker-to-Go policy
  interop — separate feature)
- USB-over-IP / virtualized USB (Parallels, Hyper-V enhanced session,
  RDP device redirection) — different attack surface
- macOS / Linux device control — Windows-only today per the scope in
  CLAUDE.md
- Auto-discovery / "first-time seen" grace period for unknown devices —
  ratified as blocked-by-default per security principles

## Breadcrumbs

**Existing code to extend:**

- `dlp-agent/src/detection/usb.rs` (385 lines) — current drive-letter
  implementation using `RegisterDeviceNotificationW` + `GetDriveTypeW`.
  Has the message-only window, the `DBT_DEVICEARRIVAL` handler, and the
  blocked-drives `RwLock<HashSet<char>>`. All future device-identity
  enumeration hooks into the same `WM_DEVICECHANGE` callback.
- `dlp-agent/src/detection/mod.rs` — module-level docstring
  cross-references `network_share` which also uses an RwLock whitelist
  pattern this seed can mirror.
- `dlp-agent/src/detection/network_share.rs` (lines 73-99) — reference
  implementation of an `Arc<RwLock<HashSet<String>>>` whitelist with
  hot-reload. SEED-003 copies this pattern for the device registry.
- `dlp-agent/src/interception/file_monitor.rs` — where the write block
  currently consults the drive-letter blocked set. The read-only tier
  hooks in here.
- `dlp-common/src/audit.rs` — `AuditEvent` struct. Phase F adds an
  optional `device` field here. Per Phase 4 TM-03 forward-compat rule,
  the PR adding the field MUST simultaneously update
  `dlp-server/src/alert_router.rs::send_email` to redact or include
  the new field explicitly.
- `dlp-agent/src/audit_emitter.rs` — where audit events are built. New
  device fields are populated here on block.
- `dlp-agent/src/config.rs` — current config surface. Device registry
  will NOT live in agent config; it lives in server DB per the
  operator-config-in-DB pattern ratified in Phase 3.1 and reinforced in
  Phase 4 (see memory obs 448).

**Reference patterns from Phase 3.1 / Phase 4 to mirror:**

- `dlp-server/src/db.rs` — `siem_config` and (once Phase 4 executes)
  `alert_router_config` tables. Device registry uses the same
  single-row-per-device pattern (but with a real primary key `(vid, pid,
  serial)` instead of `CHECK (id=1)`).
- `dlp-server/src/admin_api.rs` — JWT-protected GET/PUT handlers for
  siem-config. Device registry adds POST (add) and DELETE (remove)
  in addition to GET (list) and PUT (update).
- `dlp-admin-cli/src/screens/dispatch.rs` — `handle_siem_config` +
  System menu dispatch pattern. Device Registry will be a 6th System
  menu entry (after Alert Config which Phase 4 adds as the 5th).
- `dlp-agent/src/detection/usb.rs` docstring "Startup integration"
  section — pattern for owning Win32 HWND resources through agent
  lifecycle.

**Related documentation:**

- `docs/SRS.md` — existing USB/removable media requirements (check if
  R-13 / T-13 / F-AGT-13 already promise device-identity whitelisting;
  if so, this seed is a REQUIREMENT GAP not a new feature, and should
  be escalated earlier).
- `docs/THREAT_MODEL.md` — existing USB exfil threat enumeration; this
  seed mitigates the T-13 residual risk.
- `docs/SECURITY_ARCHITECTURE.md` — will need a new section on device
  identity as an ABAC subject attribute class.

**Related seeds:**

- `SEED-001-application-aware-dlp.md` — related "subject attribute"
  expansion (process identity → device identity is a parallel track).
  Both seeds should probably activate in the same endpoint-hardening
  milestone since they share the ABAC integration work.

**Related STATE.md decisions:**

- `2026-04-10: Skip USB thread join on shutdown` — the existing USB
  thread uses `GetMessageW` which blocks forever; this seed must not
  regress that property. Any new enumeration code still runs inside
  the same message pump thread.
- `2026-04-10: Clipboard monitoring in UI process` — the user
  notification toast (Phase E) has the same session-0 constraint and
  must be hosted in the UI companion process, not dlp-agent service.

## Notes

**User's original problem statement (capture verbatim — do not
paraphrase when activating the seed):**

> When a user inserts an unregistered USB, the DLP agent typically
> performs the following actions:
>
> 1. **Device Identification:** The agent checks the USB's Vendor ID
>    (VID), Product ID (PID), and Serial Number against a whitelist of
>    "registered" devices.
> 2. **Instant Blocking:** If not whitelisted, the device is immediately
>    blocked, preventing it from mounting in the file system.
> 3. **File Transfer Restriction:** If the device is authorized to
>    connect but not to store data, DLP allows "Read" access but blocks
>    "Write" or "Copy" actions.
> 4. **User Notification:** The user receives a popup notification,
>    often explaining that the action is against policy.
> 5. **Incident Reporting:** A security alert is sent to the admin
>    console containing the user name, machine name, and device
>    details.

**Design-phase questions to surface when this seed activates** (do not
pre-decide — these become the `/gsd-discuss-phase` questions for the
first phase of the milestone):

- Do we block at mount time (prevents the volume from appearing in
  Explorer at all) or at I/O time (volume mounts, writes fail)?
  Mount-time is cleaner UX but requires a filesystem filter driver;
  I/O-time reuses the existing file_monitor detour. Trade-off: driver
  complexity vs user confusion when they see a drive letter but can't
  write to it.
- How does a user request registration of their own device? Self-service
  admin-approval workflow in dlp-admin-cli, or purely IT-driven?
- What is the policy for a device that was registered yesterday but the
  Serial Number changed (user reformatted / firmware update)? Treat as
  new device or trust?
- Should the device registry be per-user (owner_user) or per-machine?
  Per-user supports "take your USB home" workflows; per-machine supports
  shared kiosks.
- Notification toast: Win32 balloon (legacy, deprecated but works on
  Win 10/11) vs modern `ToastNotificationManager` (Win 10+, requires
  COM activator registration at install time) — which does the
  installer support?

**Compliance anchors** (to include in the milestone's REQUIREMENTS.md
when this seed activates):

- SOC 2 CC-6.1 (logical access — removable media)
- ISO 27001 A.8.3.1 (management of removable media)
- NIST 800-53 MP-7 (media use)
- CIS Critical Control 13.7 (removable media restriction)

**Do not** activate this seed before the ABAC policy engine is capable
of consuming nested subject attributes. Check the state of the ABAC
engine milestone before scheduling the device-identity phase.
