# Feature Landscape: Disk Exfiltration Prevention (v0.7.0)

**Domain:** Enterprise Endpoint DLP — Fixed Disk Control & Encryption Verification
**Researched:** 2026-04-30
**Research Mode:** Ecosystem

---

## Table Stakes

Features users expect from any enterprise endpoint DLP product with disk control capabilities. Missing these makes the product feel incomplete.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Install-time disk enumeration** | Every competing product establishes a device baseline at agent deployment. Admins expect a known-good starting state. | Medium | Must enumerate all `DRIVE_FIXED` volumes, not just `DRIVE_REMOVABLE`. USB-bridged SATA/NVMe enclosures report as fixed. |
| **Persistent disk allowlist** | Without persistence, a reboot or agent restart loses enforcement state. Table stakes for any security agent. | Low | Store in `agent-config.toml` (existing pattern) + server-side registry. Must survive agent restarts and system reboots. |
| **BitLocker encryption status check** | BitLocker is the dominant Windows FDE. Every enterprise DLP product checks it. Microsoft Purview, Symantec, Forcepoint all integrate. | Medium | Use WMI `Win32_EncryptableVolume` (admin required, `PktPrivacy`) or undocumented `System.Volume.BitLockerProtection` property (no admin). |
| **Runtime blocking of unregistered disks** | The core value proposition. If a new fixed disk appears post-install and is not on the allowlist, block it. | High | Must handle both mount-time detection (volume arrival) and I/O-time enforcement (file interception layer). |
| **Audit events for disk actions** | Compliance frameworks (NIST 800-171, CMMC, HIPAA) require audit trails for all access control decisions. | Low | Reuse existing audit event pipeline. Add `DiskIdentity` fields (serial, model, bus type, encryption status). |
| **Admin override/registry for post-install additions** | IT replaces failed drives, adds storage. Admins need a supported path to update the allowlist without reinstalling the agent. | Medium | Admin TUI screen + server API endpoint. Must require authentication and log the override. |

### Sources — Table Stakes
- [Microsoft Purview Endpoint DLP — Removable Storage Policy](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/effectively-protect-sensitive-data-in-cloud-and-devices-using/ba-p/3733599)
- [Symantec DLP Device Control — USB/Fixed Disk Blocking](https://knowledge.broadcom.com/external/article/155346/how-to-block-usb-hard-drives-but-allow-r.html)
- [Forcepoint DLP Endpoint — Removable Media Control](https://help.forcepoint.com/F1E/en-us/v20/ep_install/C899EA85-ABE0-4EAE-85C0-0EA1409B2059.html)
- [Lake Ridge — NIST/CMMC DLP + MDM Configuration](https://lakeridge.io/how-to-configure-mdm-and-dlp-to-meet-nist-sp-800-171-rev2-cmmc-20-level-2-control-mpl2-388-and-prevent-unowned-usb-use)
- [BitLocker WMI Documentation — Win32_EncryptableVolume](https://itm4n.github.io/bitlocker-little-secrets-the-undocumented-fve-api/)

---

## Differentiators

Features that set a product apart. Not universally expected, but highly valued when present.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **USB-bridged fixed disk detection** | Most DLP products only handle `DRIVE_REMOVABLE`. Detecting USB-bridged SATA/NVMe enclosures (which report as `DRIVE_FIXED`) is a genuine gap in commercial products. | High | Requires PnP tree walking (`SetupDi` + `CM_Get_Parent`) or `Win32_DiskDrive.InterfaceType` WMI query to distinguish USB bus from internal SATA/NVMe. |
| **Dual enforcement: mount-time + I/O-time** | Mount-time blocking prevents volume mount entirely (best UX — drive never appears). I/O-time blocking catches races and bypass attempts. Defense in depth. | High | Mount-time: `WM_DEVICECHANGE` / `RegisterDeviceNotification` + volume lock. I/O-time: existing file interception filter already handles this. |
| **Encryption verification beyond BitLocker** | Check for self-encrypting drives (SED/Opal), third-party FDE (VeraCrypt, McAfee), or hardware-encrypted USB enclosures. | Medium-High | SED/Opal via `IOCTL_SCSI_MINIPORT` or `StorageDeviceEncryptionProperty`. Third-party FDE is harder — no unified API. |
| **Grace period / quarantine mode for new disks** | Instead of immediate hard-block, allow a configurable grace period (e.g., 24h) during which the disk is read-only, giving IT time to review and allowlist. Reduces helpdesk tickets. | Medium | Requires temporary policy state + timer. Must not be default — default must be deny. |
| **Disk discovery toast notification with admin request flow** | When a new disk is blocked, user gets a toast with "Request Access" button. Admin gets a pending approval in TUI. Low-friction exception workflow. | Medium | Reuse existing toast notification infrastructure (Phase 27). Add new admin TUI screen for pending approvals. |
| **Per-disk trust tier (like USB trust tiers)** | Extend the existing `UsbTrustTier` pattern to disks: `blocked`, `read_only`, `full_access`. A disk can be allowlisted but restricted to read-only. | Low-Medium | Reuse existing trust tier enum and evaluator logic. Add `DiskTrustTier` to ABAC subject attributes. |
| **SIEM-enriched disk identity fields** | Send disk serial, model, firmware, bus type, encryption method, and protection status to SIEM. Enables correlation across the fleet. | Low | Extend existing `AuditEvent` struct. Reuse SIEM relay pipeline. |

### Sources — Differentiators
- [Black Hat EU 2015 — Bypassing SEDs in Enterprise](https://blackhat.com/docs/eu-15/materials/eu-15-Boteanu-Bypassing-Self-Encrypting-Drives-SED-In-Enterprise-Environments.pdf)
- [Usb.Events Library — Cross-Platform USB Detection](https://github.com/Jinjinov/Usb.Events)
- [Symantec DLP Known Issues — Virtual Drive / I/O Blocking](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/26-1/new-and-changed/release-notes/dlp-known-issues.html)
- [Endpoint Protector — USB Enforced Encryption](https://www.endpointprotector.com/solutions/enforced-encryption)

---

## Anti-Features

Features to explicitly NOT build. These create operational pain, security holes, or scope creep.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **User self-allowlist** | End users cannot be trusted to assess disk security. Self-allowlisting defeats the purpose of enterprise DLP. | All allowlist changes must flow through admin TUI or server API with authenticated admin session. |
| **Automatic allowlist of all disks at install time** | If the agent auto-allowlists everything it sees at install, an attacker can pre-stage a malicious USB-bridged disk before agent deployment. | Enumerate at install, but require admin explicit approval to populate the allowlist. Default-deny is the secure default. |
| **Blocking only at mount time** | Race conditions exist: a disk can be connected before the agent starts, or the agent can miss a volume arrival event. I/O-time enforcement is the reliable backstop. | Implement both mount-time (best UX) and I/O-time (reliable) blocking. |
| **Supporting non-Windows encryption APIs** | macOS FileVault and Linux LUKS are out of scope for this Windows-first DLP product. Checking them adds complexity with no value. | Scope encryption checks to Windows BitLocker only. Document that third-party FDE detection is best-effort. |
| **Drive letter as disk identifier** | Drive letters are volatile (D: today, E: tomorrow). Using them as allowlist keys creates false positives and false negatives. | Use persistent identifiers: disk serial number, PnP device instance ID, or volume GUID path (`\\?\Volume{GUID}\`). |
| **Grace period as default behavior** | A default grace period creates a window of vulnerability. New disks should be blocked immediately unless explicitly configured otherwise. | Make grace period opt-in per policy. Default is immediate block. |

---

## Feature Dependencies

```
Install-Time Disk Enumeration
    --> Persistent Disk Allowlist (needs something to persist)
    --> BitLocker Encryption Check (per-disk property to store)
    --> Audit Events (discovery events to emit)

Persistent Disk Allowlist
    --> Runtime Blocking (needs allowlist to check against)
    --> Admin Override/Registry (needs allowlist to mutate)

Runtime Blocking
    --> Mount-Time Blocking (volume arrival detection)
    --> I/O-Time Blocking (file interception integration)

USB-Bridged Fixed Disk Detection
    --> Install-Time Enumeration (must classify bus type)
    --> Runtime Blocking (must apply blocking logic)

Grace Period / Quarantine Mode
    --> Runtime Blocking (temporary policy override)
    --> Admin Override (conversion from quarantine to allowlist)

Disk Discovery Toast + Admin Request
    --> Runtime Blocking (trigger condition)
    --> Existing Toast Infrastructure (Phase 27)
    --> Admin TUI Screen (new screen for pending approvals)

Per-Disk Trust Tier
    --> Persistent Disk Allowlist (trust tier per entry)
    --> ABAC Evaluator (disk trust tier as subject attribute)
    --> Existing USB Trust Tier Pattern (reuse)
```

---

## MVP Recommendation

### Prioritize (Phase 1 of v0.7.0)

1. **Install-time enumeration of fixed disks** — Establish the baseline. Must detect USB-bridged enclosures (the whole point of this milestone).
2. **BitLocker encryption status check** — Table stakes. Use WMI `Win32_EncryptableVolume` with `PktPrivacy`.
3. **Persistent disk allowlist in agent-config.toml** — Reuse existing TOML persistence pattern.
4. **Runtime blocking of unregistered fixed disks at I/O time** — Most reliable enforcement point. Integrate with existing file interception.
5. **Audit events for disk block/discovery** — Compliance requirement. Extend existing `AuditEvent`.

### Defer (Phase 2+ of v0.7.0 or later milestones)

- **Mount-time blocking**: Higher complexity, race-condition prone. I/O-time blocking catches all cases.
- **Grace period / quarantine mode**: Nice-to-have operational convenience. Can be added without breaking existing behavior.
- **Disk discovery toast with admin request flow**: Requires new TUI screen and async approval workflow. Significant UX work.
- **Encryption beyond BitLocker**: SED/Opal detection is niche; third-party FDE has no unified API. Best-effort documentation only.
- **Per-disk trust tier**: Extends the model but is not required for the core "block unregistered disks" use case.

### Rationale

The core threat model is: "attacker plugs in a USB-bridged SATA/NVMe enclosure and copies sensitive data." The MVP must:
- Detect these devices (they look like fixed disks)
- Know which were present at install (the baseline)
- Block new ones (the enforcement)
- Log everything (compliance)

Everything else is optimization and operational convenience.

---

## Competitor Capability Matrix

| Capability | Microsoft Purview | Symantec DLP | Forcepoint DLP | Digital Guardian | DLP-RUST (Target) |
|------------|-------------------|--------------|----------------|------------------|-------------------|
| Fixed disk blocking | Indirect (via Defender Device Control) | Yes (Device Control tab) | Yes (Endpoint Removable Media) | Yes (Removable Media Control) | **Yes (MVP)** |
| USB-bridged fixed disk detection | No (treats as fixed disk) | Limited | Limited | Limited | **Yes (Differentiator)** |
| BitLocker integration | Native (same vendor) | Via SEE RME | No | No | **Yes (MVP)** |
| Install-time baseline | Yes (policy deployment) | Yes (agent config) | Yes (endpoint profile) | Yes (agent deployment) | **Yes (MVP)** |
| Admin override post-install | Yes (Intune/Compliance Portal) | Yes (Enforce Server) | Yes (DLP Console) | Yes (DGMC) | **Yes (MVP)** |
| Grace period for new devices | No | No | No | No | **Defer (Differentiator)** |
| Mount-time + I/O-time dual block | No (primarily I/O-time) | No (primarily I/O-time) | No (primarily I/O-time) | No (primarily I/O-time) | **Defer (Differentiator)** |
| SED/Opal detection | No | No | No | No | **Defer (Differentiator)** |

**Confidence:** MEDIUM — based on product documentation and community discussions. Vendor implementations may have undocumented capabilities.

---

## Key Questions Answered

### Should the feature block at mount time, I/O time, or both?

**Answer: Both, but I/O-time first.**

- **I/O-time blocking** is the reliable backstop. The existing file interception layer already inspects every file operation. Adding a "is the target volume on the disk allowlist?" check is a natural extension. This catches all cases, including races and agent restart scenarios.
- **Mount-time blocking** provides better UX (the drive letter never appears to the user) but is less reliable. Volume arrival events can be missed, and filter drivers have race conditions during fast mount/unmount cycles.
- **Recommendation:** Implement I/O-time blocking in the MVP. Add mount-time blocking as a Phase 2 enhancement for improved UX.

### What encryption standards beyond BitLocker should be checked?

**Answer: BitLocker is the MVP. SED/Opal is a differentiator. Third-party FDE is out of scope.**

- **BitLocker**: Native Windows API, well-documented, dominant enterprise standard. Must support.
- **Self-Encrypting Drives (SED/Opal)**: Hardware encryption at the drive controller. Can be detected via `IOCTL_SCSI_MINIPORT` or `StorageDeviceEncryptionProperty`. However, USB-bridged SEDs lose Opal manageability — the USB bridge chip does not pass TCG Opal commands. Detection is possible; enforcement is limited.
- **Third-party FDE (VeraCrypt, McAfee, etc.)**: No unified API. Each product modifies the boot process and disk stack differently. Checking for them reliably requires product-specific heuristics. Not worth the complexity for a Windows-first product.
- **Recommendation:** BitLocker check in MVP. Document SED/Opal as a future research item. Explicitly exclude third-party FDE from scope.

### What is the UX for "admin wants to add a new disk after install"?

**Answer: Two paths — proactive admin TUI and reactive user request.**

- **Proactive (Admin TUI):** Admin navigates to a "Disk Registry" screen in `dlp-admin-cli`. Sees a list of disks discovered across the fleet (populated by agent audit events). Selects a disk, reviews its encryption status and bus type, and clicks "Add to Allowlist." The server pushes the updated allowlist to the agent via existing config polling.
- **Reactive (User Request):** User plugs in a new disk, gets blocked, sees a toast notification with "Request Access." The request appears in the admin TUI as a pending approval. Admin approves → disk is added to allowlist and user is notified.
- **Recommendation:** Implement the proactive path in MVP. The reactive path requires significant TUI and async workflow work — defer to Phase 2.

### Should there be a grace period or quarantine mode for new disks?

**Answer: Yes, but opt-in and not default.**

- **Grace period** (e.g., 24 hours read-only access) reduces helpdesk load in organizations where users legitimately need to connect new storage frequently. The disk is detected, blocked from writes, and an admin notification is sent.
- **Quarantine mode** is a stronger variant: the disk is mounted but all I/O is redirected to a contained temporary storage (Forcepoint uses this pattern with a default 500MB containment buffer).
- **Risk:** Any grace period is a window of vulnerability. Default must be immediate block.
- **Recommendation:** Add a policy-configurable grace period as a Phase 2 feature. Default is `0` (immediate block). Document the security trade-off clearly.

---

## Sources

### Official Documentation
- [Microsoft Purview Endpoint DLP Documentation](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/effectively-protect-sensitive-data-in-cloud-and-devices-using/ba-p/3733599)
- [Broadcom Symantec DLP Device Control](https://knowledge.broadcom.com/external/article/155346/how-to-block-usb-hard-drives-but-allow-r.html)
- [Broadcom Symantec Endpoint Encryption RME FAQs](https://knowledge.broadcom.com/external/article/222689/symantec-endpoint-encryption-removable-m.html)
- [Forcepoint DLP Endpoint Supported Removable Media](https://help.forcepoint.com/F1E/en-us/v20/ep_install/C899EA85-ABE0-4EAE-85C0-0EA1409B2059.html)
- [Forcepoint DLP Endpoint Settings — Disk Space](https://help.forcepoint.com/dlp/90/dlphelp/CD069C77-5BB9-458D-86EE-485AD3E425B1.html)
- [Digital Guardian Agent for Windows Release Notes](https://hstechdocs.helpsystems.com/releasenotes/Content/_ProductPages/Digital%20Guardian/Digital%20Guardian_windows_agent.htm)

### Technical References
- [BitLocker's Undocumented FVE API](https://itm4n.github.io/bitlocker-little-secrets-the-undocumented-fve-api/)
- [WMI-rs Rust Crate for BitLocker](https://github.com/ohadravid/wmi-rs)
- [Black Hat EU 2015 — Bypassing SEDs in Enterprise](https://blackhat.com/docs/eu-15/materials/eu-15-Boteanu-Bypassing-Self-Encrypting-Drives-SED-In-Enterprise-Environments.pdf)
- [TCG Opal 2.0 SED Specification](https://computingworlds.com/blog/post/opal-2.0-sed)

### Compliance & Best Practices
- [Lake Ridge — NIST SP 800-171 / CMMC 2.0 DLP + MDM](https://lakeridge.io/how-to-configure-mdm-and-dlp-to-meet-nist-sp-800-171-rev2-cmmc-20-level-2-control-mpl2-388-and-prevent-unowned-usb-use)
- [Lake Ridge — Endpoint DLP + USB Whitelisting for NIST](https://lakeridge.io/how-to-configure-endpoint-dlp-and-usb-whitelisting-to-meet-nist-sp-800-171-rev2-cmmc-20-level-2-control-mpl2-387)

### Community & Implementation
- [Usb.Events — Cross-Platform USB Detection (.NET)](https://github.com/Jinjinov/Usb.Events)
- [Tim Golden — Detect Device Insertion in Python](https://timgolden.me.uk/python/win32_how_i/detect-device-insertion.html)
- [Ravichaganti — Monitoring Volume Change Events in PowerShell](https://ravichaganti.com/blog/monitoring-volume-change-events-in-powershell-using-wmi/)

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Competitor capabilities | MEDIUM | Based on public documentation and community discussions. Vendor implementations may have undocumented features. |
| BitLocker API | HIGH | Well-documented WMI API. Rust `wmi-rs` crate verified. |
| USB-bridged fixed disk detection | MEDIUM-HIGH | PnP tree walking (`SetupDi` + `CM_Get_Parent`) is a known technique. Already implemented in Phase 31 of this project. |
| SED/Opal detection | LOW | Limited public documentation on programmatic detection. USB bridge chips break Opal manageability. |
| Third-party FDE compatibility | LOW | No unified API. Product-specific heuristics required. |
| Grace period UX patterns | MEDIUM | Observed in EDR/EPP products (quarantine). Less common in DLP specifically. |
