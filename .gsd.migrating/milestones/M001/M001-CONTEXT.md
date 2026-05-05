# M001: v0.7.0 Disk Exfiltration Prevention

## Goal

Prevent data exfiltration via unregistered fixed disks by establishing an install-time disk allowlist with encryption verification. The core threat is USB-bridged SATA/NVMe enclosures that report as `DRIVE_FIXED` to Windows, bypassing traditional removable-media controls.

## Scope

- Install-time enumeration of all fixed disks with device instance ID, bus type, model, and drive letter
- USB-bridged fixed disk detection via `IOCTL_STORAGE_QUERY_PROPERTY` and PnP tree walk
- Persistent disk allowlist in `agent-config.toml` (device instance ID as canonical key)
- BitLocker encryption status query via WMI `Win32_EncryptableVolume`
- Runtime I/O blocking of unregistered fixed disks (pre-ABAC enforcement layer)
- WM_DEVICECHANGE handling for disk arrival/removal
- Server-side disk registry in SQLite with admin CRUD API
- Admin TUI "Disk Registry" screen for fleet-wide disk management
- Audit events for disk discovery, block, and admin override actions

## Key Decisions

- Disk identity uses device instance ID as canonical key; drive letters are volatile metadata only
- Blocking uses volume-level I/O filtering (FileAction drop), NOT `CM_Disable_DevNode` (BSOD risk on boot disk)
- Disk enforcement is a pre-ABAC layer, evaluated before USB enforcement and ABAC evaluation
- Allowlist semantics: install-time enumerated disks are trusted; post-install disks are blocked by default
- PktPrivacy upgrade via raw CoSetProxyBlanket FFI (wmi 0.14 lacks set_proxy_blanket)
- 30-second per-drive cooldown on toast notifications

## Requirements Coverage

- DISK-01 through DISK-05: Enumeration, USB-bridged detection, persistence, I/O blocking, device change handling
- CRYPT-01, CRYPT-02: BitLocker status query, unencrypted disk flagging
- ADMIN-01 through ADMIN-05: Server registry, list/add/remove API, TUI screens
- AUDIT-01 through AUDIT-03: Discovery events, block events with identity, admin action events

## Constraints

- Must not misidentify or block the system boot disk
- Must handle USB bridge chips that don't pass through disk serial numbers
- Must integrate with existing file interception pipeline without regression
- Windows-only (NTFS enforcement, SetupDi API, WMI)

## Status

Most implementation is complete (Phases 33-38.2). Remaining work is primarily the Disk Registry TUI screen (ADMIN-04) and any integration testing gaps.
