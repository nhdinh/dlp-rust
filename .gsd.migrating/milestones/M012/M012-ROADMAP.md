# M012: v0.6.0 Endpoint Hardening

**Vision:** Extend the enforcement layer with application identity, browser boundary control, and USB device control — all surfaced as first-class ABAC subject attributes.

## Success Criteria

- All 13 requirements validated (APP-01..06, BRW-01..03, USB-01..04)
- Application-aware DLP working
- Browser boundary control working
- USB device control with toast working
- Automated UAT infrastructure working

## Slices

- [x] **S01: S01** `risk:Low — shipped 2026-04-29.` `depends:[]`
  > After this: Shared types (AppIdentity, DeviceIdentity, UsbTrustTier) available across all five crates.

- [x] **S02: S02** `risk:Low — shipped 2026-04-29.` `depends:[]`
  > After this: USB device arrival detected with VID/PID/serial/description. Device registry DB with trust tiers.

- [x] **S03: S03** `risk:Low — shipped 2026-04-29.` `depends:[]`
  > After this: Clipboard operations carry source and destination process identity with Authenticode verification. ABAC evaluator honors app-identity and USB trust-tier conditions.

- [x] **S04: S04** `risk:Low — shipped 2026-04-29.` `depends:[]`
  > After this: Users receive toast notification on USB block with policy explanation. Admin manages devices, origins, and app-identity policies via TUI. Chrome paste blocked between managed/unmanaged origins.

- [x] **S05: S05** `risk:Low — shipped 2026-04-29.` `depends:[]`
  > After this: Headless TUI tests, E2E agent TOML write-back, hot-reload verification, CI build gates.

## Boundary Map

Not provided.
