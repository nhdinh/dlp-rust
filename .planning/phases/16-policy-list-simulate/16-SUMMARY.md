---
phase: 16-policy-list-simulate
status: complete
completed: 2026-04-20
requirements: [POLICY-01, POLICY-06]
commits:
  - d23180c Phase 16: PolicyList polish + PolicySimulate screen
  - 7d743d2 docs(16-UAT.md): Phase 16 UAT complete — 10/11 passed, 1 issue (Esc clears field)
  - e1afee3 fix(dispatch.rs): PolicySimulate Esc preserves field value instead of clearing buffer
---

# Phase 16 Summary — PolicyList Polish + PolicySimulate Screen

## What Shipped

- **PolicyList polish** (POLICY-01): scrollable policy table refinement
  with column width balancing and the `n` key binding to create a new
  policy directly from the list.
- **PolicySimulate screen** (POLICY-06): a 10-row form for evaluating a
  hypothetical access-request against the current policy set. Fields
  include principal SID, classification (T1-T4), device trust,
  network location, access context, and action. Pressing submit
  calls the admin simulate endpoint and renders the inline
  `SimulateOutcome` result block (ALLOW / ALLOW_WITH_LOG / DENY with
  matched-policy preview).
- **Shared Simulate supporting types** in `app.rs`: `SimulateCaller`,
  `SimulateFormState`, `SimulateOutcome`, `SIMULATE_ROW_COUNT`,
  `SIMULATE_SUBMIT_ROW`, and the option arrays for classification,
  device trust, network location, access context, and action.
- **Route integration**: `Screen::PolicySimulate` arm added to
  `dispatch.rs` and `render.rs`; accessible from MainMenu row 3 and
  PolicyMenu row 5 (the `SimulateCaller` drives Esc return).

## Verification

- `cargo check`, `cargo build`, `cargo clippy -- -D warnings`, and
  `cargo test` all passed at commit `e1afee3`.
- UAT: 11/11 tests passed after the Esc-buffer fix. See `16-UAT.md`.

## Deviations

- One gap surfaced in UAT (test 7): pressing Esc while editing a
  PolicySimulate text field cleared the field value instead of
  preserving it. Fixed in `e1afee3` by keeping the committed buffer
  intact on Esc and only exiting edit mode.

## Next

Phase 17 (Import + Export) consumed this phase's Screen dispatch
pattern for its ImportConfirm screen. No further work required on
PolicyList or PolicySimulate.
