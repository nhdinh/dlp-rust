---
estimated_steps: 1
estimated_files: 1
skills_used: []
---

# T01: SetupDi description exact path matching

Implement exact path matching in setupdi_description_for_device to avoid returning Bluetooth instead of SanDisk. Match device interface path more precisely in SetupDi enumeration. Add unit tests.

## Inputs

- `Old setupdi_description_for_device implementation`
- `SetupDi API docs`

## Expected Output

- `dlp-agent/src/detection/usb.rs updated`
- `Unit tests for path matching`

## Verification

cargo test --package dlp-agent usb::
