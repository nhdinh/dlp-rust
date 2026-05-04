# Requirements -- v0.7.0 Disk Exfiltration Prevention

**Milestone:** v0.7.0
**Status:** Active (roadmap created)
**Last updated:** 2026-04-30

---

## Active Requirements

### DISK -- Disk Enumeration, Allowlist, and Blocking

- [x] **DISK-01**: Agent can enumerate all fixed disks (`DRIVE_FIXED`) at install time or first startup, capturing device instance ID, bus type, model, and drive letter.
- [x] **DISK-02**: Agent can distinguish USB-bridged fixed disks (SATA/NVMe in USB enclosures) from genuine internal SATA/NVMe disks via `IOCTL_STORAGE_QUERY_PROPERTY` or PnP tree walk.
- [x] **DISK-03**: Agent persists the disk allowlist to `agent-config.toml` with device instance ID as canonical key; drive letter is informational only.
- [ ] **DISK-04**: Agent blocks I/O (`FileAction::Create`/`Write`/`Move`) to unregistered fixed disks at runtime via pre-ABAC enforcement in `run_event_loop`.
- [ ] **DISK-05**: Agent handles `WM_DEVICECHANGE` `DBT_DEVICEARRIVAL`/`DBT_DEVICEREMOVECOMPLETE` for `GUID_DEVINTERFACE_DISK` to detect new fixed disk arrivals and removals.

### CRYPT -- Encryption Verification

- [x] **CRYPT-01**: Agent can query BitLocker encryption status via WMI `Win32_EncryptableVolume` for each enumerated fixed disk.
- [x] **CRYPT-02**: Unencrypted disks are flagged in the audit log with a warning; the admin decides whether to allow or block via the allowlist (not hard-coded block).

### ADMIN -- Server-Side Registry and Management

- [ ] **ADMIN-01**: Server stores disk registry in SQLite with `agent_id`, `instance_id`, `bus_type`, `encrypted`, `model`, and `registered_at`.
- [ ] **ADMIN-02**: Admin can list all registered disks across the fleet via `GET /admin/disk-registry`.
- [ ] **ADMIN-03**: Admin can add a disk to the allowlist via `POST /admin/disk-registry` and remove via `DELETE /admin/disk-registry/{id}`.
- [ ] **ADMIN-04**: Admin TUI shows a "Disk Registry" screen under the System menu for listing, adding, and removing disk entries.
- [ ] **ADMIN-05**: Admin TUI has an "LDAP Config" screen under the System menu for configuring AD connection parameters (`ldap_url`, `base_dn`, `require_tls`, `cache_ttl_secs`, `vpn_subnets`) via `GET`/`PUT /admin/ldap-config`.

### AUDIT -- Audit Events and Compliance

- [x] **AUDIT-01**: Disk discovery events are emitted at install time, capturing all enumerated disks with their identity and encryption status.
- [ ] **AUDIT-02**: Disk block events include disk identity fields (instance_id, bus_type, model, drive letter) when an unregistered fixed disk is blocked.
- [ ] **AUDIT-03**: Admin override actions (add/remove disk from registry) are emitted as `EventType::AdminAction` audit events.

---

## Deferred Requirements (v0.7.1+ or later milestones)

- **DISK-F1**: Mount-time blocking (volume lock) in addition to I/O-time blocking -- improves UX but not reliability.
- **DISK-F2**: Grace period / quarantine mode for new disks -- configurable read-only window before hard block.
- **DISK-F3**: Disk discovery toast with admin request flow -- user requests access, admin approves via TUI.
- **DISK-F4**: Per-disk trust tier (`blocked`, `read_only`, `full_access`) extending the USB trust tier pattern.
- **CRYPT-F1**: SED/Opal self-encrypting drive detection via `StorageDeviceEncryptionProperty`.
- **CRYPT-F2**: Third-party FDE detection (VeraCrypt, McAfee) -- no unified API, product-specific heuristics.

---

## Out of Scope

- **Non-Windows encryption APIs** (macOS FileVault, Linux LUKS) -- Windows-first product per PROJECT.md.
- **User self-allowlist** -- all allowlist changes require authenticated admin.
- **Drive letter as disk identity** -- device instance ID is canonical; drive letters are volatile.
- **CM_Disable_DevNode on internal fixed disks** -- unsafe; causes BSOD on boot disk.

---

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| DISK-01 | 33 | Complete |
| DISK-02 | 33 | Complete |
| DISK-03 | 35 | Complete |
| DISK-04 | 36 | Pending |
| DISK-05 | 36 | Pending |
| CRYPT-01 | 34 | Complete |
| CRYPT-02 | 34 | Complete |
| ADMIN-01 | 37 | Pending |
| ADMIN-02 | 37 | Pending |
| ADMIN-03 | 37 | Pending |
| ADMIN-04 | 38 | Pending |
| AUDIT-01 | 33 | Complete |
| AUDIT-02 | 36 | Pending |
| AUDIT-03 | 37 | Pending |

---

*Requirements defined: 2026-04-30*
*Roadmap created: 2026-04-30*
*Next: /gsd-plan-phase 33*
