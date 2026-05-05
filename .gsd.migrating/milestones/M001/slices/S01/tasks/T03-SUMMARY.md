---
id: T03
parent: S01
milestone: M001
key_files:
  - dlp-admin-cli/src/screens/render.rs
key_decisions:
  - Used Table widget (matching draw_usb_scan pattern) instead of List widget for proper columnar display
  - Empty-state renders as centered Paragraph with early return rather than a single-row table, matching the task plan requirement for a centered message
  - Percentage-based column widths: 20/25/12/13/30 to balance readability across typical terminal widths
duration: 
verification_result: passed
completed_at: 2026-05-05T20:52:51.218Z
blocker_discovered: false
---

# T03: Replaced placeholder List-based draw_disk_registry_list with a 5-column Table (Agent ID, Instance ID, Bus Type, Encrypted, Model) including header row, row highlighting, centered empty-state message, and keybinding hints

**Replaced placeholder List-based draw_disk_registry_list with a 5-column Table (Agent ID, Instance ID, Bus Type, Encrypted, Model) including header row, row highlighting, centered empty-state message, and keybinding hints**

## What Happened

The prior session left `draw_disk_registry_list` as a placeholder using ratatui's `List` widget with a single concatenated line per entry (noted by the doc comment "T03 will flesh out full table rendering"). This task upgraded it to a proper `Table` widget following the `draw_usb_scan` pattern already established in the codebase.

Changes made to `render.rs`:

1. **Empty-state handling** — When `disks` is empty, renders a centered `Paragraph` with "No disk registry entries." inside a bordered block titled "Disk Registry (0)". Shows only "a: Add   Esc: Back" hints (no delete option when empty). Returns early to avoid rendering a table with no rows.

2. **Table header** — Bold `Row` with 5 column labels: "Agent ID", "Instance ID", "Bus Type", "Encrypted", "Model", with a bottom margin separator.

3. **Data rows** — Each disk entry maps its JSON fields (`agent_id`, `instance_id`, `bus_type`, `encryption_status`, `model`) into a `Row`, using `"-"` as fallback for missing string fields (empty string for model).

4. **Column widths** — Percentage-based constraints: 20% Agent ID, 25% Instance ID, 12% Bus Type, 13% Encrypted, 30% Model.

5. **Row highlighting** — Uses `row_highlight_style` (black text on cyan background, bold) with `"> "` highlight symbol, matching the existing `draw_usb_scan` pattern.

6. **Selection state** — Uses `TableState` (not `ListState`) with `select(Some(selected))`.

7. **Hint bar** — "a: Add   d: Delete   Esc: Back" via `draw_hints`.

8. **Doc comment** — Updated from placeholder language to accurate description of the table columns.

## Verification

Ran `cargo build --package dlp-admin-cli` — compiled with no errors or warnings. Ran `cargo clippy --package dlp-admin-cli -- -D warnings` — passed clean with no lints.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo build --package dlp-admin-cli` | 0 | pass | 3540ms |
| 2 | `cargo clippy --package dlp-admin-cli -- -D warnings` | 0 | pass | 1230ms |

## Deviations

None — the placeholder was upgraded to a full Table as planned.

## Known Issues

None

## Files Created/Modified

- `dlp-admin-cli/src/screens/render.rs`
