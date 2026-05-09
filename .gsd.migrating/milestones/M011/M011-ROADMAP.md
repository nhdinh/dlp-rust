# M011: v0.7.0 Disk Exfiltration Prevention

**Vision:** Prevent data exfiltration via unregistered fixed disks by establishing an install-time disk allowlist with encryption verification, runtime I/O blocking, and centralized admin management.

## Success Criteria

- All 15 requirements validated (DISK-01..05, CRYPT-01..02, ADMIN-01..05, AUDIT-01..03)
- Disk enumeration working
- BitLocker verification working
- Disk allowlist persistence working
- Runtime disk enforcement working
- Server-side disk registry and admin TUI working
- USB enforcement fix working

## Slices

- [x] **S01: S01** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: All fixed disks discovered at install time with device identity, bus type, and encryption status.

- [x] **S02: S02** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: BitLocker status verified via WMI for all enumerated fixed disks. Unencrypted disks flagged in audit.

- [x] **S03: S03** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: Disk allowlist persisted to agent-config.toml and loaded across restarts.

- [x] **S04: S04** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: I/O to unregistered fixed disks blocked at runtime. WM_DEVICECHANGE handled for arrivals/removals.

- [x] **S05: S05** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: Admin manages disk allowlist via REST API and TUI. Server stores fleet-wide disk registry in SQLite.

- [x] **S06: S06** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: Blocked USB devices disabled at PnP level with Volume DACL deny-all fallback.

## Boundary Map

Not provided.
