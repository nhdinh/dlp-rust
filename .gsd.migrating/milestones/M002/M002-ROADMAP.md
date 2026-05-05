# M002: Endpoint Hardening (v0.6.0)

**Vision:** Harden the endpoint agent with app identity, USB control, Chrome integration, and automated UAT to close the major exfiltration vectors via removable media and browser downloads.

## Success Criteria

- Agent captures app identity for every file operation event
- USB devices are detected, classified, and controlled per policy
- Chrome Enterprise Connector enforces DLP on downloads
- UAT scripts validate USB block/allow scenarios end-to-end

## Slices

- [x] **S01: App identity capture** `risk:high` `depends:[]`
  > After this: Audit events include the originating application's identity
- [x] **S02: USB device detection** `risk:high` `depends:[]`
  > After this: Agent detects USB plug/unplug and identifies device type
- [x] **S03: USB device control** `risk:high` `depends:[S02]`
  > After this: Agent can block/allow USB device access based on policy tier
- [x] **S04: Chrome Enterprise Connector** `risk:medium` `depends:[S01]`
  > After this: Chrome file downloads are intercepted and classified by DLP
- [x] **S05: Device registry (server-side)** `risk:medium` `depends:[S02,S03]`
  > After this: Server tracks all known USB devices with tier assignments
- [x] **S06: Automated UAT infrastructure** `risk:low` `depends:[S03,S05]`
  > After this: PowerShell UAT scripts validate USB scenarios without manual testing
