---
sliceId: S07
title: USB enforcement fix
status: complete
completedAt: 2026-05-05
tasksCompleted: 3
---

# S07: USB enforcement fix

## What was delivered

Fixed USB enforcement gap where Blocked-tier devices logged DENY but writes still succeeded. Implemented two-layer enforcement: PnP CM_Disable_DevNode (primary) + Volume DACL deny-all (secondary). Fixed drive-letter mislabel in disk enumeration. Resolved USB_DEVICE/VOLUME arrival race with pending_identity reconciliation.

## Key files

- `dlp-agent/src/usb_enforcer.rs` — enforcement logic with set_volume_deny_all
- `dlp-agent/src/device_controller.rs` — PnP disable + DACL deny-all machinery
- `dlp-agent/src/detection/usb.rs` — handler wiring, tier application
- `dlp-agent/src/detection/disk.rs` — drive-letter resolution fix (find_drive_letter_for_instance_id)

## Decisions made

- Two independent OS-enforced layers (D-02/D-03): both fire independently for defense-in-depth
- Tier changes require physical re-plug (D-07/D-08): no hot-reload via poll
- Drive-letter fix uses kernel-authoritative volume-to-disk mapping
- pending_identity explicitly cleared after reconciliation to prevent double-processing
- scan_existing_usb_identities uses existing enumerate_connected_usb_devices
