# M010: v0.7.1 Operational Hardening

**Vision:** Close gaps in audit schema, support multi-user device registration, upgrade WMI crate, and harden operational behavior across the v0.7.0 codebase.

## Success Criteria

- All 7 requirements validated (AUDIT-05, USB-06, TECH-01, OP-01..04)
- AGENT-UNKNOWN remediation working
- Per-user device registry working
- WMI crate upgraded
- Operational hardening bundle delivered

## Slices

- [x] **S01: S01** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: All audit events include non-null app identity fields with AGENT-UNKNOWN sentinel and remediation path.

- [x] **S02: S02** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: Multi-user machines support per-user USB device registration with most-restrictive tier merge.

- [x] **S03: S03** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: BitLocker queries use typed wmi 0.18+ interface with no raw CoSetProxyBlanket FFI.

- [x] **S04: S04** `risk:Low — shipped 2026-05-06.` `depends:[]`
  > After this: Disk enumeration handles IOCTL failures gracefully. USB enforcement emits structured traces. Agent config validates at load time. Service shutdown cancels in-flight tasks within 10s.

## Boundary Map

Not provided.
