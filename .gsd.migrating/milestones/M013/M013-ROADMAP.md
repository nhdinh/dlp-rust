# M013: v0.5.0 Boolean Logic

**Vision:** Upgrade the ABAC engine and admin TUI from implicit-AND to flat boolean composition with expanded per-attribute operators and in-place condition editing.

## Success Criteria

- All 4 requirements validated (POLICY-09..12)
- Boolean mode engine working
- TUI mode picker working
- Operator expansion working
- In-place editing working

## Slices

- [x] **S01: S01** `risk:Low — shipped 2026-04-21.` `depends:[]`
  > After this: ABAC evaluator supports ALL/ANY/NONE boolean modes per policy. Legacy policies default to ALL.

- [x] **S02: S02** `risk:Low — shipped 2026-04-21.` `depends:[]`
  > After this: Admin can choose boolean mode in Create/Edit forms. Export/import round-trips mode field.

- [x] **S03: S03** `risk:Low — shipped 2026-04-21.` `depends:[]`
  > After this: Conditions builder shows attribute-type-aware operators (gt, lt, ne, contains). Evaluator honors expanded operators.

- [x] **S04: S04** `risk:Low — shipped 2026-04-21.` `depends:[]`
  > After this: Press 'e' on pending condition to pre-fill 3-step picker and replace at original index.

## Boundary Map

Not provided.
