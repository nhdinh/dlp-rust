---
status: investigating
trigger: "Phase 31 UAT Test 6 rework — Blocked USB device still writable after 31-02 gap closure"
created: "2026-04-29T16:54:00Z"
updated: "2026-04-29T16:54:00Z"
phase: "31-usb-cm-blocking"
test: "6"
---

## Symptom

Device registered as BLOCKED in Device Registry:
- VID: 0bda, PID: 9210, SER: 012345678904
- Description: "Realtek RTL9210 NVME USB Device"

When plugged in:
- Device remains writable in Windows Explorer
- No device disable occurs

## Log Evidence

```
2026-04-29T16:54:16.641363Z DEBUG ThreadId(02) dlp_agent::detection::usb: initial USB drive scan complete blocked={}
2026-04-29T16:54:16.642402Z  INFO ThreadId(02) dlp_agent::detection::usb: USB device notifications registered (volume + device + disk interface)
2026-04-29T16:54:16.642457Z  INFO ThreadId(02) dlp_agent::service: USB notifications registered thread_id=ThreadId(31)
2026-04-29T16:54:22.840178Z  INFO ThreadId(31) dlp_agent::detection::usb: USB device arrived — identity captured (no drive letter yet) vid=0bda pid=9210 serial=012345678904 description=USB Mass Storage Device
```

## Observations

1. `GUID_DEVINTERFACE_USB_DEVICE` notification DOES fire — `on_usb_device_arrival` runs
2. Identity is correctly parsed (vid=0bda, pid=9210, serial=012345678904 matches registry)
3. No drive letter was available at USB_DEVICE notification time ("no drive letter yet")
4. No subsequent log about:
   - VOLUME notification → `handle_volume_event` → drive letter assignment
   - DISK notification → `on_disk_device_arrival` → PnP tree walk
   - `apply_tier_enforcement` → `disable_usb_device`
5. This is an NVMe USB bridge (Realtek RTL9210), not a standard USB flash drive

## Hypothesis

The `GUID_DEVINTERFACE_USB_DEVICE` path parks the identity in `pending_identity` but the VOLUME notification never arrives (or arrives before USB_DEVICE), so `handle_volume_event` never reconciles it. The DISK path (31-02) should handle this but may not be firing for NVMe bridges, or the PnP tree walk fails to find a USB ancestor.

## Current Focus

next_action: "Verify whether DISK notification fires and what on_disk_device_arrival does"
hypothesis: "NVMe USB bridge presents differently in PnP tree — DISK notification fires but CM_Get_Parent walk finds no USB\\ ancestor, or disk_path_to_instance_id parsing fails for this device path format"

## Evidence

- 2026-04-29T16:54:22Z: USB_DEVICE notification fires, identity captured correctly
- Missing: Any DISK notification log, any apply_tier_enforcement log, any CM_Disable_DevNode log

## Eliminated

- hypothesis: "GUID_DEVINTERFACE_USB_DEVICE not firing"
  reason: "Log shows 'USB device arrived — identity captured' with correct VID/PID/serial"

## Resolution

root_cause: "[pending]"
fix: "[pending]"
verification: "[pending]"
