---
estimated_steps: 1
estimated_files: 1
skills_used: []
---

# T03: Implement draw_disk_registry_list render function

Add draw_disk_registry_list(frame, area, disks, selected) to render.rs. Display a table with columns: Agent ID, Instance ID, Bus Type, Encrypted, Model. Use the same table rendering pattern as draw_device_list or draw_managed_origin_list. Highlight the selected row. Show hints: 'a: Add  d: Delete  Esc: Back'. Handle empty list with a centered message. Wire the DiskRegistryList match arm in draw_screen() to call this function.

## Inputs

- `draw_device_list pattern in render.rs`
- `draw_managed_origin_list pattern in render.rs`
- `DiskRegistryResponse fields: id, agent_id, instance_id, bus_type, encryption_status, model, registered_at`

## Expected Output

- `draw_disk_registry_list() function in render.rs`
- `Table with 5 columns rendering disk entries`
- `Hint bar showing available keybindings`
- `Empty-state message when no disks exist`

## Verification

cargo build --package dlp-admin-cli compiles; cargo clippy --package dlp-admin-cli -- -D warnings passes
