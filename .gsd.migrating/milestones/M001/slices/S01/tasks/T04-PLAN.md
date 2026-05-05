---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T04: Add unit tests for disk registry TUI screen

Add unit tests in dispatch.rs and render.rs test modules covering: (1) DevicesMenu now has 4 items and index 3 opens DiskRegistryList, (2) DiskRegistryList Esc returns to DevicesMenu { selected: 3 }, (3) DevicesMenu nav wraps at 4 (update existing wrap test), (4) draw_disk_registry_list renders without panic for empty and non-empty disk lists, (5) handle_disk_registry_list Up/Down navigation. Follow existing test patterns (make_test_app, simulate_key).

## Inputs

- `Existing DevicesMenu test patterns at dispatch.rs:4973`
- `Existing render test patterns`
- `make_test_app helper`

## Expected Output

- `Test: devices_menu_idx_3_opens_disk_registry`
- `Test: disk_registry_esc_returns_to_devices_menu`
- `Test: devices_menu_nav_wraps_with_four_items (updated)`
- `Test: draw_disk_registry_list_empty and draw_disk_registry_list_nonempty`
- `Test: disk_registry_nav_up_down`

## Verification

cargo test --package dlp-admin-cli passes all tests including new ones
