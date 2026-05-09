# M014: v0.4.0 Policy Authoring

**Vision:** Deliver the full admin policy-authoring workflow in dlp-admin-cli — list, create, edit, delete, simulate, import, and export — all as typed forms with inline validation, no raw JSON editing.

## Success Criteria

- All 8 requirements validated (POLICY-01..08)
- Conditions builder working
- Policy create/edit/delete working
- Policy list and simulation working
- Import/export working

## Slices

- [x] **S01: S01** `risk:Low — shipped 2026-04-20.` `depends:[]`
  > After this: Admin builds typed conditions via 3-step picker (attribute → operator → value). No raw JSON.

- [x] **S02: S02** `risk:Low — shipped 2026-04-20.` `depends:[]`
  > After this: Multi-field form creates new policy with conditions. Form validates inline and submits to admin API.

- [x] **S03: S03** `risk:Low — shipped 2026-04-20.` `depends:[]`
  > After this: Admin edits existing policies and deletes with confirmation. Form pre-fills from loaded record.

- [x] **S04: S04** `risk:Low — shipped 2026-04-20.` `depends:[]`
  > After this: Scrollable policy table with priority sort. Standalone evaluate-request simulation form renders decision and matched policy.

- [x] **S05: S05** `risk:Low — shipped 2026-04-20.` `depends:[]`
  > After this: Export full policy set to JSON. Import with conflict detection and abort-on-error.

## Boundary Map

Not provided.
