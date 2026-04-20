---
phase: 20
plan: 02
name: "TUI: attribute-type-aware operator picker + MemberOf prompt copy"
wave: 2
depends_on:
  - "20-01-evaluator-operators-PLAN.md"
files_modified:
  - dlp-admin-cli/src/screens/dispatch.rs
  - dlp-admin-cli/src/screens/render.rs
requirements_addressed:
  - POLICY-11
type: execute
autonomous: true
must_haves:
  truths:
    - "operators_for(Classification) returns exactly 4 operators: eq, neq, gt, lt"
    - "operators_for(MemberOf) returns exactly 3 operators: eq, neq, contains"
    - "operators_for(DeviceTrust/NetworkLocation/AccessContext) returns exactly 2 operators: eq, neq"
    - "Step 2 picker shows only the operators returned by operators_for for the attribute chosen in Step 1"
    - "Switching attribute in Step 1 resets selected_operator if it is not valid for the new attribute (SC-1)"
    - "MemberOf Step 3 block title reads 'AD Group SID (partial match)' to hint at substring semantics"
  artifacts:
    - dlp-admin-cli/src/screens/dispatch.rs
    - dlp-admin-cli/src/screens/render.rs
  key_links:
    - "pick_operators in render.rs delegates to operators_for in dispatch.rs — operators_for must be pub(crate)"
    - "picker_items step 2 arm passes selected_attribute to pick_operators to build the correct operator list"
---

## Overview

Wave 2 extends the TUI conditions builder so the Step 2 operator picker shows only the
operators valid for the attribute chosen in Step 1. Wave 1 (`compare_op_classification`
and `contains` in `memberof_matches`) must be complete before this wave begins.

Three changes:

1. `operators_for()` in `dispatch.rs` returns the correct operator list per attribute
2. `OPERATOR_EQ` constant in `render.rs` is replaced with a `OPERATORS` map driven by `operators_for`
3. Step 3 MemberOf prompt copy is updated to hint at substring semantics (per D-07)

---

## Step 1 — Read source-of-truth files first

<read_first>

- `dlp-admin-cli/src/screens/dispatch.rs` lines 2020–2028 — `operators_for` (the function being extended)
- `dlp-admin-cli/src/screens/dispatch.rs` lines 2439–2531 — `handle_conditions_step3_text` (MemberOf text input; the prompt copy lives here)
- `dlp-admin-cli/src/screens/render.rs` lines 254–322 — `OPERATOR_EQ` constant and `picker_items` Step 2 path
- `.planning/phases/20-operator-expansion/20-CONTEXT.md` — decisions D-07, D-08, D-10

</read_first>

---

## Step 2 — Extend `operators_for` in `dispatch.rs`

Replace the current `operators_for` function (lines 2020–2028) with:

```rust
/// Returns the operator list (wire string + enforcement flag) valid for the given attribute.
///
/// Per D-08: DeviceTrust, NetworkLocation, AccessContext get `neq` added.
/// Per D-10: each attribute's list is fixed; the Step 2 picker auto-sizes to the count.
/// Display labels are: "equals" (eq), "not equals" (neq), "greater than" (gt),
/// "less than" (lt), "contains" (contains).
pub(crate) fn operators_for(attr: ConditionAttribute) -> &'static [(&'static str, bool)] {
    match attr {
        ConditionAttribute::Classification => &[
            ("eq", true),
            ("neq", true),
            ("gt", true),
            ("lt", true),
        ],
        ConditionAttribute::MemberOf => &[
            ("eq", true),
            ("neq", true),
            ("contains", true),
        ],
        ConditionAttribute::DeviceTrust => &[
            ("eq", true),
            ("neq", true),
        ],
        ConditionAttribute::NetworkLocation => &[
            ("eq", true),
            ("neq", true),
        ],
        ConditionAttribute::AccessContext => &[
            ("eq", true),
            ("neq", true),
        ],
    }
}
```

<acceptance_criteria>

- `grep -n "pub(crate) fn operators_for" dlp-admin-cli/src/screens/dispatch.rs` returns exactly one match
- `grep -n '"gt"' dlp-admin-cli/src/screens/dispatch.rs` matches inside `operators_for` for Classification branch
- `grep -n '"lt"' dlp-admin-cli/src/screens/dispatch.rs` matches inside `operators_for` for Classification branch
- `grep -n '"contains"' dlp-admin-cli/src/screens/dispatch.rs` matches inside `operators_for` for MemberOf branch
- `grep -n '"neq"' dlp-admin-cli/src/screens/dispatch.rs` shows `neq` for DeviceTrust, NetworkLocation, AccessContext

</acceptance_criteria>

---

## Step 2b — SC-1: defensive operator reset in `handle_conditions_step1`

In `handle_conditions_step1` (`dispatch.rs`), update the `KeyCode::Enter` arm so that when the
user picks a new attribute and advances to Step 2, any stale `selected_operator` that is
not valid for the new attribute is cleared.

Find the `KeyCode::Enter` block in `handle_conditions_step1` (the block that sets
`*selected_attribute = Some(attr)` and `*step = 2`). Add a visibility guard to the
destructure pattern to also access `selected_operator`, then add the reset check:

```rust
KeyCode::Enter => {
    if let Screen::ConditionsBuilder {
        step,
        selected_attribute,
        selected_operator,   // add this field
        picker_state,
        ..
    } = &mut app.screen
    {
        let idx = picker_state.selected().unwrap_or(0);
        let attr = ATTRIBUTES
            .get(idx)
            .copied()
            .unwrap_or(ConditionAttribute::Classification);
        *selected_attribute = Some(attr);
        // SC-1: clear a stale operator when it is not valid for the new attribute.
        // In normal navigation the operator is already None here (Esc from Step 2
        // always clears it), but this guard is an explicit safety net per ROADMAP SC-1.
        if let Some(prev_op) = selected_operator.as_deref() {
            if !operators_for(attr).iter().any(|(op, _)| *op == prev_op) {
                *selected_operator = None;
            }
        }
        *step = 2;
        picker_state.select(Some(0));
    }
}
```

<acceptance_criteria>

- `grep -n "SC-1" dlp-admin-cli/src/screens/dispatch.rs` returns exactly one match (the comment)
- `grep -n "operators_for(attr)" dlp-admin-cli/src/screens/dispatch.rs` shows the call inside `handle_conditions_step1`'s Enter arm

</acceptance_criteria>

---

## Step 3 — Replace `OPERATOR_EQ` with `OPERATORS` in `render.rs`

In `render.rs`, first add the import for `operators_for` and `ConditionAttribute` from dispatch
(if not already in scope). Add near the top of the file with the other `use` imports:

```rust
use crate::screens::dispatch::operators_for;
```

Then replace the `OPERATOR_EQ` constant (line 255) with a `pick_operators` helper
that delegates to `operators_for`:

```rust
/// Step 2 operator list — driven by the attribute chosen in Step 1.
///
/// The list is built by calling `operators_for`, which returns the correct
/// operators for the attribute. Enforced operators are shown verbatim;
/// advisory-only operators are annotated "(not enforced)".
fn pick_operators(attr: ConditionAttribute) -> Vec<ListItem<'static>> {
    operators_for(attr)
        .iter()
        .map(|(op, enforced)| {
            if *enforced {
                ListItem::new(op.to_string())
            } else {
                ListItem::new(Line::from(vec![
                    Span::raw(op.to_string()),
                    Span::styled("  (not enforced)", Style::default().fg(Color::DarkGray)),
                ]))
            }
        })
        .collect()
}
```

Then in `picker_items` (line 310), replace:

```rust
2 => OPERATOR_EQ
```

with:

```rust
2 => {
    let attr = match selected_attribute {
        Some(a) => a,
        None => return vec![],
    };
    pick_operators(*attr)
}
```

Remove the `OPERATOR_EQ` constant (it is replaced by the function above).

<acceptance_criteria>

- `grep -n "use crate::screens::dispatch::operators_for" dlp-admin-cli/src/screens/render.rs` returns exactly one match
- `grep -n "OPERATOR_EQ" dlp-admin-cli/src/screens/render.rs` returns zero matches after the change
- `grep -n "fn pick_operators" dlp-admin-cli/src/screens/render.rs` returns exactly one match
- `grep -n "operators_for" dlp-admin-cli/src/screens/render.rs` returns at least one match in `pick_operators`
- Step 2 in `picker_items` passes `selected_attribute` to `pick_operators`

</acceptance_criteria>

---

## Step 4 — Update Step 3 MemberOf prompt copy (per D-07)

In `handle_conditions_step3_text` (`dispatch.rs`), update the `KeyCode::Enter` error message
to hint at substring semantics.

Find this line (line 2509):

```rust
app.set_status("AD group SID cannot be empty", StatusKind::Error);
```

**No change needed there** — that is the error case.

Update the block title in `render.rs` inside the `is_member_of_step3` branch (around line 500).
Find the `Block::default().title(" AD Group SID ")` and update it to:

```rust
Block::default()
    .title(" AD Group SID (partial match) ")
```

This is the visible prompt the admin sees while typing. The copy change reflects that
`contains` is now a supported operator for MemberOf (per D-07).

<acceptance_criteria>

- `grep -n "partial match" dlp-admin-cli/src/screens/render.rs` returns exactly one match
- `grep -n "AD Group SID (partial match)" dlp-admin-cli/src/screens/render.rs` returns exactly one match (the renamed title; the old bare "AD Group SID" title must not exist)

</acceptance_criteria>

---

## Step 5 — Add regression test for `operators_for`

Add a test to `dispatch.rs` inside the `#[cfg(test)]` module (or a new `#[cfg(test)]` module
at the bottom of the file). If the file does not yet have a test module, add one.

```rust
#[cfg(test)]
mod operator_tests {
    use super::*;

    #[test]
    fn test_operators_for_classification() {
        let ops = operators_for(ConditionAttribute::Classification);
        assert_eq!(ops.len(), 4);
        let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
        assert!(wire.contains(&"eq"));
        assert!(wire.contains(&"neq"));
        assert!(wire.contains(&"gt"));
        assert!(wire.contains(&"lt"));
    }

    #[test]
    fn test_operators_for_memberof() {
        let ops = operators_for(ConditionAttribute::MemberOf);
        assert_eq!(ops.len(), 3);
        let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
        assert!(wire.contains(&"eq"));
        assert!(wire.contains(&"neq"));
        assert!(wire.contains(&"contains"));
    }

    #[test]
    fn test_operators_for_device_trust() {
        let ops = operators_for(ConditionAttribute::DeviceTrust);
        assert_eq!(ops.len(), 2);
        let wire: Vec<_> = ops.iter().map(|(w, _)| *w).collect();
        assert!(wire.contains(&"eq"));
        assert!(wire.contains(&"neq"));
    }

    #[test]
    fn test_operators_for_network_location() {
        let ops = operators_for(ConditionAttribute::NetworkLocation);
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_operators_for_access_context() {
        let ops = operators_for(ConditionAttribute::AccessContext);
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_condition_display_with_gt_lt() {
        // Regression guard: condition_display renders {op} {value} verbatim,
        // so "gt" and "lt" operators must appear unchanged in the display string.
        let display_gt = condition_display(ConditionAttribute::Classification, "gt", "T3");
        assert!(display_gt.contains("gt"), "expected 'gt' in display: {display_gt}");
        assert!(display_gt.contains("T3"), "expected 'T3' in display: {display_gt}");

        let display_lt = condition_display(ConditionAttribute::Classification, "lt", "T2");
        assert!(display_lt.contains("lt"), "expected 'lt' in display: {display_lt}");
        assert!(display_lt.contains("T2"), "expected 'T2' in display: {display_lt}");
    }
}
```

<acceptance_criteria>

- `grep -n "test_operators_for_classification" dlp-admin-cli/src/screens/dispatch.rs` returns exactly one match
- `grep -n "test_operators_for_memberof" dlp-admin-cli/src/screens/dispatch.rs` returns exactly one match
- `grep -n "test_operators_for_device_trust" dlp-admin-cli/src/screens/dispatch.rs` returns exactly one match
- `grep -n "test_condition_display_with_gt_lt" dlp-admin-cli/src/screens/dispatch.rs` returns exactly one match

</acceptance_criteria>

---

## Step 6 — Verify build and tests

```sh
cargo fmt --check -p dlp-admin-cli
cargo build -p dlp-admin-cli --all-features
cargo test -p dlp-admin-cli
cargo clippy -p dlp-admin-cli -- -D warnings
```

<acceptance_criteria>

- `cargo fmt --check -p dlp-admin-cli` exits 0 (no formatting violations)
- All four commands complete with exit code 0
- `grep -n "fn operators_for" dlp-admin-cli/src/screens/dispatch.rs` finds the updated function
- `grep -n "fn pick_operators" dlp-admin-cli/src/screens/render.rs` finds the new helper
- `grep -n "partial match" dlp-admin-cli/src/screens/render.rs` finds the updated prompt
- `cargo test -p dlp-admin-cli -- operator_tests` passes all 5 regression tests

</acceptance_criteria>
