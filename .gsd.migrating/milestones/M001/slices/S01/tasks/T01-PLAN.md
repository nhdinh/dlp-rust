---
estimated_steps: 1
estimated_files: 3
skills_used: []
---

# T01: Add DiskRegistryList screen variant and InputPurpose variants

Add Screen::DiskRegistryList { disks: Vec<serde_json::Value>, selected: usize } to the Screen enum in app.rs. Add InputPurpose variants for the multi-field add flow (AddDiskAgentId, AddDiskInstanceId, AddDiskBusType, AddDiskModel). Add the new screen to DevicesMenu as index 3, update nav() count from 3 to 4. Wire the new variant into the exhaustive matches in dispatch.rs and render.rs with placeholder arms.

## Inputs

- `Existing Screen enum pattern`
- `DevicesMenu handler at dispatch.rs:3816`

## Expected Output

- `Screen::DiskRegistryList variant in app.rs`
- `InputPurpose::AddDisk* variants in app.rs`
- `DevicesMenu index 3 wired to action_load_disk_registry_list stub`
- `Placeholder match arms in render.rs and dispatch.rs`

## Verification

cargo build --package dlp-admin-cli compiles with no warnings
