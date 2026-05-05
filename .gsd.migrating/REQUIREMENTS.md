# Requirements

## Active

### ADMIN-04 — Admin TUI shows a "Disk Registry" screen under the System menu for listing, adding, and removing disk entries.

- Status: active
- Class: core-capability
- Source: inferred
- Primary Slice: S01

Admin TUI shows a "Disk Registry" screen under the System menu for listing, adding, and removing disk entries. The server-side API (GET/POST/DELETE /admin/disk-registry) is implemented; the TUI screen to consume it is not yet built.

## Validated

### DISK-01 — Agent enumerates all fixed disks at install time or first startup.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 33)

Agent can enumerate all fixed disks (`DRIVE_FIXED`) at install time or first startup, capturing device instance ID, bus type, model, and drive letter. Implemented in `dlp-common/src/disk.rs` via `enumerate_fixed_disks()`.

### DISK-02 — Agent distinguishes USB-bridged fixed disks from genuine internal disks.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 33)

Agent can distinguish USB-bridged fixed disks (SATA/NVMe in USB enclosures) from genuine internal SATA/NVMe disks via `IOCTL_STORAGE_QUERY_PROPERTY` and PnP tree walk. Implemented in `dlp-common/src/disk.rs`.

### DISK-03 — Agent persists disk allowlist to agent-config.toml.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 35)

Agent persists the disk allowlist to `agent-config.toml` with device instance ID as canonical key; drive letter is informational only. Implemented in `dlp-agent/src/config.rs` and `dlp-agent/src/detection/disk.rs`.

### DISK-04 — Agent blocks I/O to unregistered fixed disks at runtime.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 36)

Agent blocks I/O (`FileAction::Create`/`Write`/`Move`) to unregistered fixed disks at runtime via pre-ABAC enforcement in `run_event_loop`. Implemented in `dlp-agent/src/disk_enforcer.rs`.

### DISK-05 — Agent handles WM_DEVICECHANGE for disk arrivals and removals.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 36)

Agent handles `WM_DEVICECHANGE` `DBT_DEVICEARRIVAL`/`DBT_DEVICEREMOVECOMPLETE` for `GUID_DEVINTERFACE_DISK` to detect new fixed disk arrivals and removals. Wired in `dlp-agent/src/detection/device_watcher.rs` and `dlp-agent/src/detection/disk.rs`.

### CRYPT-01 — Agent queries BitLocker encryption status via WMI.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 34)

Agent can query BitLocker encryption status via WMI `Win32_EncryptableVolume` for each enumerated fixed disk. Implemented in `dlp-common/src/disk.rs` with PktPrivacy CoSetProxyBlanket FFI.

### CRYPT-02 — Unencrypted disks flagged in audit log with warning.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 34)

Unencrypted disks are flagged in the audit log with a warning; the admin decides whether to allow or block via the allowlist (not hard-coded block).

### ADMIN-01 — Server stores disk registry in SQLite.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 37)

Server stores disk registry in SQLite with `agent_id`, `instance_id`, `bus_type`, `encrypted`, `model`, and `registered_at`. Implemented in `dlp-server/src/db/repositories/disk_registry.rs`.

### ADMIN-02 — Admin can list all registered disks via API.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 37)

Admin can list all registered disks across the fleet via `GET /admin/disk-registry`. Implemented in `dlp-server/src/admin_api.rs`.

### ADMIN-03 — Admin can add/remove disks from allowlist via API.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 37)

Admin can add a disk to the allowlist via `POST /admin/disk-registry` and remove via `DELETE /admin/disk-registry/{id}`. Implemented in `dlp-server/src/admin_api.rs`.

### ADMIN-05 — Admin TUI has an LDAP Config screen.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 38.1)

Admin TUI has an "LDAP Config" screen under the System menu for configuring AD connection parameters (`ldap_url`, `base_dn`, `require_tls`, `cache_ttl_secs`, `vpn_subnets`) via `GET`/`PUT /admin/ldap-config`. Completed in Phase 38.1.

### AUDIT-01 — Disk discovery events emitted at install time.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 33)

Disk discovery events are emitted at install time, capturing all enumerated disks with their identity and encryption status.

### AUDIT-02 — Disk block events include disk identity fields.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 36)

Disk block events include disk identity fields (instance_id, bus_type, model, drive letter) when an unregistered fixed disk is blocked. Carried in `DiskBlockResult` struct.

### AUDIT-03 — Admin override actions emitted as audit events.

- Status: validated
- Class: core-capability
- Source: inferred
- Primary Slice: none (Phase 37)

Admin override actions (add/remove disk from registry) are emitted as `EventType::AdminAction` audit events. Implemented in `dlp-server/src/admin_api.rs`.

## Deferred

## Out of Scope
