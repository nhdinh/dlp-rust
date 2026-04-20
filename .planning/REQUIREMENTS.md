# v0.5.0 Boolean Logic — Requirements

**Milestone:** v0.5.0 Boolean Logic
**Started:** 2026-04-20
**Continues from:** v0.4.0 Policy Authoring (shipped 2026-04-20, phases 13–17)
**Starting phase:** 18

## Goal

Upgrade the ABAC policy engine and admin TUI from implicit-AND-over-typed-conditions
to flat boolean composition with expanded per-attribute operators, and close the
delete-and-recreate gap left by Phase 13.

## v0.5.0 Requirements (Active)

### Boolean Composition

- [ ] **POLICY-09**: Admin can select a top-level boolean **mode** per policy —
  `ALL` (every condition matches), `ANY` (at least one matches), or `NONE`
  (no condition matches). The mode is chosen from the Policy Create and Policy
  Edit forms in the admin TUI. The server's ABAC evaluator (`PolicyStore::evaluate`)
  honors the mode across the condition list and returns the selected policy when
  the mode predicate is satisfied. Wire format gains a `mode` field on
  `PolicyPayload` and `PolicyResponse`. Export/import round-trips the mode.

- [ ] **POLICY-12**: Existing v0.4.0 policies loaded from storage without a `mode`
  field are treated as `ALL` (backward compatibility). `policies.mode` column has
  a `NOT NULL DEFAULT 'ALL'` constraint or equivalent migration. Export output
  always includes the mode field. Import tolerates files that omit it (defaults
  to `ALL`) and includes it on re-export.

### Conditions Builder UX

- [ ] **POLICY-10**: Admin can edit an existing pending condition in-place in
  the conditions builder. From the pending-conditions list, selecting a condition
  and pressing `e` (edit) re-enters the 3-step picker pre-filled with the
  existing attribute, operator, and value, and on save replaces the condition
  at its original list position (no delete-and-recreate). Delete is still
  available via the existing key.

### Operator Expansion

- [ ] **POLICY-11**: Admin can pick an operator per condition from an
  attribute-type-aware set:
  - `Classification` (ordered tier T1..T4): `eq`, `ne`, `gt`, `lt`
  - `MemberOf` (group string): `eq`, `ne`, `contains`
  - `DeviceTrust` / `NetworkLocation` / `AccessContext` (enum): `eq`, `ne`
  The conditions builder's step 2 (operator picker) shows only operators valid
  for the attribute chosen in step 1. The ABAC evaluator honors the new
  operators. Existing `eq`-only conditions keep working unchanged.

## Traceability (filled by roadmap)

| REQ-ID | Requirement | Phase | Status |
|--------|-------------|-------|--------|
| POLICY-09 | Top-level boolean mode (ALL/ANY/NONE) | TBD | Active |
| POLICY-10 | In-place condition editing | TBD | Active |
| POLICY-11 | Attribute-type-aware operator expansion | TBD | Active |
| POLICY-12 | v0.4.0 policy backward compatibility (default mode = ALL) | TBD | Active |

## Future Requirements (Deferred)

- **POLICY-F4**: TOML export format — blocked by `toml` crate incompatibility
  with `#[serde(tag = "attribute")]` PolicyCondition. Candidate for v0.5.x
  Server Hardening.
- **POLICY-F5**: Batch import endpoint (`POST /admin/policies/import`) —
  reduces cache invalidations on bulk import. Candidate for v0.5.x.
- **POLICY-F6**: Typed `Decision` action field on the server (eliminates
  silent `_ => DENY` fallback). Candidate for v0.5.x.

## Out of Scope (explicit)

- **Nested boolean expression trees** — flat top-level mode only in v0.5.0.
  Rationale: rule-builder UX and wire-format simplicity. Users needing
  nested AND-of-ORs can author two policies and rely on priority ordering
  (standard ABAC pattern).
- **Mixed AND/OR within a single policy's condition list** — explicitly
  subsumed by the flat-mode decision above.
- **SEED-001 application-aware DLP** — triggers on "policy engine
  expressiveness" but scoped LARGE (~1 full milestone on Win32 process
  detection, signing verification, Pipe 3 protocol change, ABAC attribute
  extension). Revisit in a dedicated endpoint-hardening milestone.
- **SEED-002 "Protected Clipboard" browser boundary** — depends on SEED-001.
- **SEED-003 USB device-identity whitelist** — different domain (device
  control), not policy expressiveness.
- **Migration tooling for DB-at-rest policies** — covered inline by
  POLICY-12's default-on-read strategy, no explicit migration script
  required.

---

*REQ-IDs POLICY-09, -10, -11, -12 continue from the v0.4.0 POLICY-01..08
series. POLICY-F1..F3 (the deferred future items from v0.4.0) are
resolved by POLICY-09/10/11 respectively; POLICY-F4..F6 remain deferred.*
