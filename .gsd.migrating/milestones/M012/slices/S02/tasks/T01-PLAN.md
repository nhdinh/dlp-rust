---
estimated_steps: 1
estimated_files: 4
skills_used: []
---

# T01: USB enumeration and device registry

Implement UsbDetector with device_identities field and parse_usb_device_path helper. Add GUID_DEVINTERFACE_USB_DEVICE device notification. Wire WM_DEVICECHANGE in usb_wndproc. SetupDi description fetch. Create device_registry table and DeviceRegistryRepository. Implement admin API GET/POST/DELETE /admin/device-registry. Agent DeviceRegistryCache with 30s poll.

## Inputs

- `SetupDi API`
- `Existing admin API patterns`

## Expected Output

- `UsbDetector module`
- `Device notification wiring`
- `Device registry table`
- `Admin API handlers`
- `Agent cache poll loop`

## Verification

cargo test --package dlp-agent usb:: && cargo test --package dlp-server admin_api::
