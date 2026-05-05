---
estimated_steps: 1
estimated_files: 2
skills_used: []
---

# T02: Implement load, delete, and add actions with dispatch handlers

Implement action_load_disk_registry_list() calling client.get('admin/disk-registry'). Implement handle_disk_registry_list() dispatching Up/Down for navigation, 'd' for delete (client.delete with row's id field, then reload), 'a' to enter TextInput chain for adding a disk (5 fields: agent_id, instance_id, bus_type, encryption_status, model), Esc to return to DevicesMenu { selected: 3 }. Implement the TextInput completion handler for AddDisk* purposes that chains fields then POSTs to admin/disk-registry. Follow the ManagedOriginList add/delete pattern closely.

## Inputs

- `action_load_device_list pattern at dispatch.rs:3838`
- `action_load_managed_origin_list pattern at dispatch.rs:3856`
- `handle_managed_origin_list delete/add pattern`
- `POST /admin/disk-registry expects: agent_id, instance_id, bus_type, encryption_status, model`

## Expected Output

- `action_load_disk_registry_list() function`
- `handle_disk_registry_list() function with Up/Down/d/a/Esc handlers`
- `TextInput completion arms for AddDiskAgentId through AddDiskModel`
- `POST body construction and reload on success`

## Verification

cargo build --package dlp-admin-cli compiles with no warnings; cargo clippy --package dlp-admin-cli -- -D warnings passes
