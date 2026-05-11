---
slug: usb-not-triggering-enforcement
status: resolved
trigger: "USB arrival notifications are not triggering DeviceController enforcement (CM_Disable_DevNode / DACL modification)"
created: "2026-04-29"
updated: "2026-04-29"
source_phase: 31-usb-cm-blocking
---

# Debug Session: USB Arrival Not Triggering Enforcement

## Symptoms

<!-- DATA_START -->

- expected: When a USB device is plugged in, the agent's usb_wndproc should receive a WM_DEVICECHANGE notification (DBT_DEVICEARRIVAL). For a device registered as "Blocked" in the device registry, DeviceController::disable_usb_device should be called via CM_Disable_DevNode, disabling the device. For "ReadOnly", the volume DACL should be modified.
- actual: USB device plugged in while agent is running. Device remains visible in Windows Explorer and is writable. No arrival-related logs from detection::usb or device_controller modules. No audit events for USB enforcement.
- error_messages: No ERROR-level logs. No arrival logs at all. The only USB-related log is "initial USB drive scan complete blocked={}" and "USB device notifications registered (volume + device interface)".
- timeline: Discovered during Phase 31 UAT on 2026-04-29. Phase 31 added DeviceController with CM_* APIs and wired it into usb_wndproc arrival/removal handlers.
- reproduction: 1. Start dlp-agent in console mode (or as service). 2. Ensure USB notifications are registered (log: "USB device notifications registered"). 3. Plug in a USB device (registered as Blocked in device registry, or unregistered). 4. Observe: no arrival log, device not disabled, no DACL modification. 5. Device remains fully accessible in Windows Explorer.
<!-- DATA_END -->

## Current Focus

- hypothesis: CONFIRMED — Window thread-affinity violation: the HWND is created on the tokio caller thread but GetMessageW pumps a different thread's queue on the spawned usb-notification thread.
- test: N/A — root cause confirmed by code inspection.
- next_action: Apply fix — move CreateWindowExW, RegisterDeviceNotificationW, and GetMessageW message loop all onto the same dedicated spawned thread.

## Evidence

- timestamp: 2026-04-29T09:54:00Z
  file: dlp-agent/src/detection/usb.rs
  lines: 826-938
  observation: >
    register_usb_notifications() calls CreateWindowExW on the calling thread
    (a tokio worker thread inside run_loop), then RegisterDeviceNotificationW on
    that same thread, then spawns a new std::thread and runs GetMessageW inside it.
    Windows HWND thread affinity means WM_DEVICECHANGE messages are queued to the
    MESSAGE QUEUE OF THE THREAD THAT CREATED THE WINDOW — the tokio worker thread.
    The spawned usb-notification thread's GetMessageW call returns only messages
    posted to ITS OWN queue, which is always empty. No WM_DEVICECHANGE messages
    are ever dequeued or dispatched. usb_wndproc is never called.

- timestamp: 2026-04-29T09:54:00Z
  file: dlp-agent/src/detection/usb.rs
  lines: 919-934
  observation: >
    The spawned thread runs GetMessageW(&mut msg, None, 0, 0) with hwnd=None
    (all messages for this thread). Since the window was not created on this
    thread, no messages ever arrive here. The loop blocks indefinitely without
    processing any device change events.

## Eliminated

- "wndproc registered but failing silently" — wndproc is never reached because GetMessageW never returns a WM_DEVICECHANGE message
- "RegisterDeviceNotificationW failing" — the success log fires and no error is returned; registration succeeds but targets the wrong thread's window
- "DEVICE_CONTROLLER static not set" — set_device_controller is called before register_usb_notifications in service.rs (lines 495-496); the static is populated

## Resolution

- root_cause: "Windows HWND thread-affinity violation: CreateWindowExW and RegisterDeviceNotificationW are called on the tokio caller thread, but the message pump (GetMessageW/DispatchMessageW) runs on a separate spawned thread. WM_DEVICECHANGE is posted to the creating thread's queue, not the pumping thread's queue — so usb_wndproc is never invoked."
- fix: "Move CreateWindowExW, RegisterDeviceNotificationW calls, and the GetMessageW message loop all inside the spawned usb-notification thread. Use a oneshot channel (or similar) to return the HWND to the caller after the window is created on the correct thread."
- verification: "cargo build -p dlp-agent and cargo clippy -p dlp-agent -- -D warnings both pass clean. Runtime verification: plug in USB device and observe arrival log from on_usb_device_arrival, and DeviceController enforcement log (disable or DACL modification)."
- fix_applied: "2026-04-29"
- files_changed: ["dlp-agent/src/detection/usb.rs"]
