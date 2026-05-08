# M009: v0.8.0 Application-Aware DLP

**Vision:** Extend the DLP enforcement layer with application identity, browser boundary control, and comprehensive audit enrichment — all surfaced as first-class ABAC subject attributes.

## Success Criteria

- All 18 requirements validated (APP-07..08, BRW-04, AUDIT-04)
- UWP AUMID resolution working
- Drag-and-drop enforcement working
- Browser origin clipboard policies working
- All audit events enriched with app identity

## Slices

- [x] **S01: S01** `risk:Low — all phases shipped 2026-05-07.` `depends:[]`
  > After this: UWP app identity resolved via AUMID, drag-and-drop blocked by ABAC, browser origin clipboard policies enforced, all audit events enriched with app identity.

- [x] **S02: S02** `risk:Low — shipped 2026-05-07.` `depends:[]`
  > After this: Drag-and-drop operations from unauthorized sources are blocked before drop completes, with toast notification and audit event.

- [x] **S03: S03** `risk:Low — shipped 2026-05-07.` `depends:[]`
  > After this: Paste from managed origin to unmanaged origin blocked inside Chrome with origin fields in audit.

- [x] **S04: S04** `risk:Low — shipped 2026-05-07.` `depends:[]`
  > After this: All interception paths emit audit events with populated app identity and origin fields. AGENT-UNKNOWN sentinel for unresolvable identity.

## Boundary Map

Not provided.
