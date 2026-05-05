# M001: v0.7.0 Disk Exfiltration Prevention

**Vision:** Prevent data exfiltration via unregistered fixed disks. Install-time disk allowlist with encryption verification, runtime I/O blocking, server-side registry, and admin TUI management. 14 of 15 requirements validated through Phases 33-38.2; one remaining: ADMIN-04 (Disk Registry TUI screen).

## Success Criteria

- All 15 disk exfiltration requirements validated (DISK-01..05, CRYPT-01..02, ADMIN-01..05, AUDIT-01..03)
- Disk Registry TUI screen operational: list, add, remove disks from the admin CLI
- No regressions in existing disk enforcement pipeline (208+ disk-related unit tests pass)
- Admin can manage disk allowlist end-to-end: API + TUI

## Slices

- [ ] **S01: S01** `risk:low` `depends:[]`
  > After this: Admin navigates to System > Disk Registry, sees fleet-wide disk list, can add/remove entries

## Boundary Map

Not provided.
