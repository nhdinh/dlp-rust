---
sliceId: S02
title: BitLocker verification
status: complete
completedAt: 2026-05-02
tasksCompleted: 2
---

# S02: BitLocker verification

## What was delivered

BitLocker encryption status detection for all enumerated volumes using WMI Win32_EncryptableVolume class. Agent checks protection status and encryption percentage at startup and on configurable periodic interval. Results flow into audit events (DiskDiscovery).

## Key files

- `dlp-agent/src/detection/encryption.rs` — BitLocker WMI queries
- `dlp-agent/src/service.rs` — periodic re-check wiring (encryption block at line 637-655)

## Decisions made

- PktPrivacy upgrade via raw CoSetProxyBlanket FFI (wmi 0.14 lacks set_proxy_blanket)
- windows-core = 0.59 added as direct dep for Interface::as_raw() on wmi-returned IWbemServices
- Encryption block inserted after disk enumeration spawn, before offline_ev binding
