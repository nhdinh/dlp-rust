# Milestone v0.8.1 — Deferred Items & Issue Debt

## USB Fixes

- [ ] **USB-07**: Fix CM instance ID resolution for PnP device disable. `DeviceController::disable_usb_device` must resolve the actual CM instance ID from the device interface path via SetupDi, not construct it from VID/PID/serial. Pass the real instance ID to `CM_Disable_DevNode`. (dlp-rust-1vk)
- [ ] **USB-08**: Fix `setupdi_description_for_device` matching wrong device. Match device path more precisely in SetupDi enumeration to avoid returning Bluetooth instead of SanDisk. (dlp-rust-sek)
- [ ] **USB-09**: Surface hard failures when both PnP disable and DACL deny-all fail. Neither enforcement layer may fail silently; return a hard error to the caller so the agent can emit a proper audit event.

## Disk Enforcement

- [ ] **DISK-06**: Implement mount-time volume lock for unregistered disks (DISK-F1). In addition to I/O-time blocking, lock the volume at mount time so the drive letter does not appear in Explorer at all for unregistered devices.
- [ ] **DISK-07**: Configurable read-only grace period before hard block for new disk arrivals (DISK-F2). Allow a time-bounded read-only window (configurable in `agent-config.toml`) after an unregistered disk arrives, during which reads are allowed and writes are blocked with a user notification, before escalating to full mount-time block.

## UAT & Validation

- [ ] **UAT-05**: Complete SanDisk re-registration with full 128-char serial for ReadOnly/FullAccess enforcement test. Verify the per-user device registry correctly stores and enforces trust tier for devices with long serial numbers. (dlp-rust-l79)

## Future Requirements (deferred beyond v0.8.1)

- None. All deferred items and issue debt are targeted for this milestone.

## Out of Scope

- Native browser extension (SEED-002 Path A) — remains deferred to future milestone
- macOS / Linux support — Windows-only per project scope
- Cloud-native policy engine — on-prem DLP with enterprise AD dependency

## Traceability

| Requirement | Phase | Plan | Status |
|-------------|-------|------|--------|
| USB-07 | 43 | TBD | Planned |
| USB-08 | 43 | TBD | Planned |
| USB-09 | 43 | TBD | Planned |
| DISK-06 | 44 | TBD | Planned |
| DISK-07 | 45 | TBD | Planned |
| UAT-05 | 46 | TBD | Planned |
