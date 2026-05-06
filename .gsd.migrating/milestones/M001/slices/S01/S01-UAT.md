# S01: Disk Registry TUI Screen — UAT

**Milestone:** M001
**Written:** 2026-05-06T00:04:07.671Z

# S01: Disk Registry TUI Screen — UAT

**Milestone:** M001
**Written:** 2026-05-06

## UAT Type

- UAT mode: artifact-driven
- Why this mode is sufficient: The TUI screen is exercised through unit tests that construct Screen states and simulate keypress dispatch. The underlying API (GET/POST/DELETE /admin/disk-registry) was already validated in Phase 37. Live-runtime UAT would require a running server; unit tests confirm all navigation, rendering, and dispatch paths.

## Preconditions

- `cargo test --package dlp-admin-cli` passes all 77 tests
- `cargo build --package dlp-admin-cli` compiles with no warnings

## Smoke Test

Run `cargo test --package dlp-admin-cli -- disk_registry` — all 6 tests pass, confirming the screen variant exists, renders, and handles key dispatch.

## Test Cases

### 1. DevicesMenu shows Disk Registry as 4th item

1. Render DevicesMenu screen
2. **Expected:** Menu displays 4 items including "Disk Registry"; both "Scan & Register USB" and "Disk Registry" text appear in rendered output

### 2. DevicesMenu navigation wraps at 4 items

1. Start at DevicesMenu index 0
2. Press Up
3. **Expected:** Selected index wraps to 3 (Disk Registry)

### 3. Selecting index 3 routes to Disk Registry

1. Set DevicesMenu selected=3
2. Press Enter
3. **Expected:** App transitions to DiskRegistryList screen (or shows error status if no server, confirming the route was reached)

### 4. Esc from DiskRegistryList returns to DevicesMenu

1. Navigate to DiskRegistryList screen
2. Press Esc
3. **Expected:** App returns to DevicesMenu with selected=3

### 5. Up/Down navigation in disk list

1. Construct DiskRegistryList with 3 disk entries, selected=0
2. Press Down three times
3. **Expected:** Selected wraps: 0→1→2→0
4. Press Up from index 0
5. **Expected:** Selected wraps to 2

### 6. Navigation on empty list is safe

1. Construct DiskRegistryList with 0 entries, selected=0
2. Press Down
3. **Expected:** No panic, selected remains 0

### 7. Empty list rendering

1. Render DiskRegistryList with empty disk slice
2. **Expected:** Title shows "(0)", body shows "No disk registry entries.", hints show "a: Add" and "Esc: Back" (no delete hint)

### 8. Non-empty list rendering

1. Render DiskRegistryList with 2 disk entries
2. **Expected:** All 5 column headers rendered (Agent ID, Instance ID, Bus Type, Encrypted, Model), both data rows present, hints include "a: Add", "d: Delete", "Esc: Back"

## Edge Cases

### Empty list delete safety
- Pressing 'd' on an empty list should not panic (guarded by empty-list check in dispatch handler)

### Missing JSON fields
- Disk entries with missing fields render "-" fallback (model renders empty string)

## Not Proven By This UAT

- **Live API integration**: The TUI's HTTP calls to GET/POST/DELETE /admin/disk-registry are not tested end-to-end against a running server. The API itself was validated in Phase 37.
- **Visual layout**: Column widths, alignment, and highlight styling are not visually verified — only that the render function executes without panic and produces expected text content.
- **Concurrent access**: Multiple admins modifying the disk registry simultaneously is not tested.
- **Large dataset performance**: Scrolling behavior with hundreds of disk entries is not tested.
