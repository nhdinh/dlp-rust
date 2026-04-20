# Phase 20: Operator Expansion - Context

**Gathered:** 2026-04-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Extend the conditions builder's operator picker from `eq`-only to an
attribute-type-aware set. The ABAC evaluator honors the new operators;
the conditions builder's step 2 surfaces only operators valid for the
attribute chosen in step 1. Existing `eq`-only conditions keep working
unchanged.

**Operator map:**

| Attribute | Operators |
|-----------|-----------|
| Classification | `eq`, `ne`, `gt`, `lt` |
| MemberOf | `eq`, `ne`, `contains` |
| DeviceTrust | `eq`, `ne` |
| NetworkLocation | `eq`, `ne` |
| AccessContext | `eq`, `ne` |

**Explicitly in scope:**
1. `operators_for()` in `dlp-admin-cli/src/screens/dispatch.rs` grows
   the per-attribute operator list.
2. `compare_op()` in `dlp-server/src/policy_store.rs` gains `gt`/`lt`
   branches for Classification using ordinal comparison.
3. `memberof_matches()` in `policy_store.rs` gains a `contains` branch
   for substring match on group SID.
4. Step 2 of the conditions builder renders the correct operator list
   for the chosen attribute — no other UI changes.
5. Unit tests covering all new operators and per-attribute operator sets.

**Explicitly out of scope:**
- No new `PartialOrd` derive on `Classification`. Ordinal comparison
  uses a local helper function, not the enum derive list.
- No AD lookup for MemberOf. `contains` is substring on the SID string.
- No new wire format field. `PolicyCondition.op` is already a String.
- No in-place condition editing. That's Phase 21.
- No new DB schema. No operator persistence beyond the JSON conditions blob.

</domain>

<decisions>
## Implementation Decisions

### Classification `gt`/`lt` Semantics (D-01)

- **D-01:** `gt`/`lt` use **ordinal position** (tier number). T1 is the
  lowest sensitivity, T4 is the highest. `gt T2` matches T3 or T4.
  Mapping: T1 → 1, T2 → 2, T3 → 3, T4 → 4. Ordinal comparison means
  `T3 > T2` is true, `T1 > T4` is false.
- **D-02:** `compare_op()` gains a new match arm for `"gt"` and `"lt"`
  on Classification conditions. A private `fn classification_ord(c:
  &Classification) -> u8` maps the enum to its tier number for the
  comparison. `ne` stays as `!=` (already works correctly).
- **D-03:** `Classification` does NOT get `#[derive(PartialOrd)]`. The
  ordinal helper is a plain function. This avoids adding a new derive
  to the shared `dlp-common` enum, which could have unintended side
  effects on other consumers.
- **D-04:** Wire format strings are `"gt"` and `"lt"`. No quoting, no
  numeric values. `condition_display()` renders `Classification gt T3`
  as today (`{op} {value}` format, which already works verbatim for
  the new operators).

### MemberOf `contains` Semantics (D-05)

- **D-05:** `contains` performs a **case-sensitive substring match**
  on the group SID string. `contains "S-1-5-21"` matches any SID
  containing that substring anywhere. This is the chosen semantics
  because:
  - SIDs are the canonical identifier in the system (used throughout
    ABAC evaluation).
  - Substring match is deterministic and fast — no AD round-trip.
  - Display-name matching was rejected: group names aren't globally
    unique, require an AD lookup, and users who write DLP conditions
    already know the SIDs they're targeting.
- **D-06:** `memberof_matches()` gains a `"contains"` arm:
  `subject_groups.iter().any(|sid| sid.contains(target_sid))`.
  `ne` remains `!=`. `eq` and `in`/`not_in` are unchanged.
- **D-07:** UX consideration: the Step 3 input prompt for MemberOf
  should be updated to hint at the substring semantics, e.g.,
  "Enter group SID (supports partial match)". Planner adds a note to
  the task for `handle_conditions_step3` copy. No structural UI change.

### Enum-Only Attributes: `eq`/`ne` (D-08)

- **D-08:** DeviceTrust, NetworkLocation, and AccessContext get `ne`
  added to their `operators_for()` list alongside the existing `eq`.
  No evaluator changes — `compare_op` already handles `"neq"` for all
  types. Wire strings: `"eq"`, `"neq"`. Display labels: "equals",
  "not equals" (shown in the step 2 picker).
- **D-09:** No changes to `value_count_for()` or the step 3 value
  pickers for these three attributes. Their value sets are unchanged.

### TUI: Step 2 Operator Picker (D-10)

- **D-10:** The operator list in Step 2 is driven entirely by
  `operators_for(attr)`. Extending the arrays is the only change
  needed — no new UI components or layout changes. The picker
  auto-sizes to the number of options (1-4 depending on attribute).

### Test Coverage (D-11)

- **D-11:** Unit tests added:
  - `test_compare_op_gt_lt` — ordinal comparison for Classification
  - `test_compare_op_gt_boundary` — T1 > T4 is false, T4 > T3 is true
  - `test_memberof_matches_contains` — SID substring match
  - `test_memberof_matches_contains_no_match` — absent substring returns false
  - `test_operators_for_all_attributes` — `operators_for` returns correct
    list per attribute (regression guard: Classification now returns 4,
    MemberOf 3, others 2)
  - `test_condition_display_with_gt_lt` — pending list renders `gt`/`lt`
    operators cleanly

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` § POLICY-11 — attribute-type-aware operator expansion contract
- `.planning/milestones/v0.5.0-ROADMAP.md` § Phase 20 — goal and dependency on Phase 19
- `.planning/STATE.md` § Decisions — Phase 18/19 pattern decisions

### Phase 18 Foundation (boolean mode engine)
- `.planning/phases/18-boolean-mode-engine-wire-format/18-CONTEXT.md` — all 26 decisions, especially D-17 (evaluate switch on mode), D-20/D-21 (wire `mode` through create/update handlers), D-24/D-25 (wire serde defaults)
- `.planning/phases/18-boolean-mode-engine-wire-format/SUMMARY.md` — what was actually shipped

### Phase 19 TUI (most recent pattern)
- `.planning/phases/19-boolean-mode-tui-import-export/19-CONTEXT.md` — TUI pattern decisions (cycle-on-Enter, advisory-only hints, row-index renumber risk)
- `.planning/phases/19-boolean-mode-tui-import-export/SUMMARY.md` — UAT results

### ABAC Core Types (dlp-common)
- `dlp-common/src/classification.rs` — `Classification` enum (T1/T2/T3/T4) — D-01/D-03 relate to this
- `dlp-common/src/abac.rs` §213-247 — `PolicyCondition` enum (the wire format, `op` is already a String)
- `dlp-common/src/abac.rs` §249-268 — `PolicyMode` enum (Phase 18 pattern for enum-in-abac)

### Evaluator (dlp-server)
- `dlp-server/src/policy_store.rs` §237-249 — `compare_op` (extend with gt/lt per D-01/D-02)
- `dlp-server/src/policy_store.rs` §251-265 — `memberof_matches` (extend with contains per D-05/D-06)
- `dlp-server/src/policy_store.rs` §217-235 — `condition_matches` (entry point, no changes needed)

### Conditions Builder TUI (dlp-admin-cli)
- `dlp-admin-cli/src/screens/dispatch.rs` §2020-2028 — `operators_for` (the one-change-per-attribute function to extend)
- `dlp-admin-cli/src/screens/dispatch.rs` §2360-2437 — `handle_conditions_step2` (uses `operators_for`, no changes needed)
- `dlp-admin-cli/src/screens/dispatch.rs` §2120-2131 — `condition_display` (renders `{op} {value}`, works for gt/lt unchanged)
- `dlp-admin-cli/src/app.rs` §68-88 — `ConditionAttribute` enum + `ATTRIBUTES` const (the anchor `operators_for` matches against)
- `dlp-admin-cli/src/screens/render.rs` §374-493 — `draw_conditions_builder` (Step 2 picker, driven by `operators_for` output, no structural changes)

</canonical_refs>

<specifics>
## Specific Ideas

- The `classification_ord` helper (D-02/D-03) should live in
  `policy_store.rs` as a plain `fn`, not in `dlp-common` — it's a
  comparison implementation detail, not a shared type method.
- The Step 3 MemberOf prompt update (D-07) is a copy change in
  `handle_conditions_step3` only — no layout or widget change.
- The new operator labels for display in Step 2: `"eq"` → "equals",
  `"neq"` → "not equals", `"gt"` → "greater than", `"lt"` → "less
  than", `"contains"` → "contains". These are display-only strings,
  not wire strings.
- A `#[derive(PartialOrd)]` on `Classification` would be the "clever"
  path but creates coupling risk — any code that uses `Classification`
  in a generic context could pick up unexpected `>` behavior. The
  ordinal helper is explicit and auditable.

</specifics>

<deferred>
## Deferred Ideas

- **AD group name resolution for MemberOf display** — substring-on-SID
  is the pragmatic choice for v0.5.0. A future phase could resolve
  SIDs to display names for the pending list's `condition_display`
  output, but that requires AD async lookups in the TUI render path.
  Deferred until needed.
- **Group name `contains`** — matching on group display names (e.g.,
  "contains Finance") instead of SID substring. Same deferral reason
  as above.
- **In-place condition editing** — Phase 21.

</deferred>

---

*Phase: 20-operator-expansion*
*Context gathered: 2026-04-21*
