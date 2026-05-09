# M008: v0.8.1 Deferred Items & Issue Debt

**Vision:** Close all deferred feature gaps and outstanding issue debt from v0.8.0 Application-Aware DLP. Deliver PnP USB enforcement that actually works, mount-time blocking for unregistered disks, a configurable grace period before hard block, and complete UAT validation for the full 128-char SanDisk serial registration flow.

## Success Criteria

- All 6 deferred requirements (USB-07..09, DISK-06..07, UAT-05) are validated
- PnP USB enforcement works with real CM instance IDs
- Mount-time blocking prevents drive letter assignment for unregistered disks
- Grace period configurable via agent-config.toml with correct escalation behavior
- All workspace tests pass with no regressions

## Slices

- [x] **S01: S01** `risk:Medium — Win32 SetupDi API surface is large; path matching must distinguish similar devices (e.g., Bluetooth vs SanDisk).` `depends:[]`
  > After this: Blocked USB devices are disabled at the PnP level with real CM instance IDs. Both PnP disable and DACL deny-all return hard errors on failure. Devices with (none) serial handled gracefully.

- [x] **S02: S02** `risk:Low — builds on existing disk enumeration and DeviceController patterns.` `depends:[]`
  > After this: Unregistered fixed disk inserted → no drive letter appears in Explorer. I/O-time blocking remains as fallback. Audit event emitted on mount-time block.

- [x] **S03: S03** `risk:Low — timer-based state machine; primary complexity is config propagation and user notification.` `depends:[]`
  > After this: agent-config.toml accepts disk_grace_period_seconds (default 0 = immediate block). During grace period: reads allowed, writes blocked with toast. After expiry: full mount-time block engages.

- [x] **S04: S04** `risk:Low — validation-only slice; no new code.` `depends:[]`
  > After this: SanDisk re-registered with full 128-char serial. ReadOnly and FullAccess trust tiers enforced correctly. All workspace tests pass. SonarQube gate clean.

## Boundary Map

Not provided.
