# S01: Disk Registry TUI Screen

**Goal:** Admin can navigate to Devices > Disk Registry in the TUI, see a table of fleet-wide disk entries (agent_id, instance_id, bus_type, encryption, model), add new entries via text input, and delete selected entries. Backed by existing GET/POST/DELETE /admin/disk-registry API.
**Demo:** Admin navigates to System > Disk Registry, sees fleet-wide disk list, can add/remove entries

## Must-Haves

- 1. DevicesMenu shows 4 items including "Disk Registry" as index 3
- 2. Selecting Disk Registry fetches GET /admin/disk-registry and renders a scrollable table
- 3. Pressing 'a' opens a multi-field text input flow to POST a new disk entry
- 4. Pressing 'd' on a selected row sends DELETE and refreshes the list
- 5. Esc returns to DevicesMenu with correct selected index
- 6. All existing TUI tests pass with no regressions
- 7. New unit tests cover navigation, key dispatch, and render for the disk registry screen

## Proof Level

- This slice proves: unit-tests + manual TUI verification

## Verification

- Run the task and slice verification checks for this slice.

## Tasks

- [x] **T01: Add DiskRegistryList screen variant and InputPurpose variants** `est:20min`
  Add Screen::DiskRegistryList { disks: Vec<serde_json::Value>, selected: usize } to the Screen enum in app.rs. Add InputPurpose variants for the multi-field add flow (AddDiskAgentId, AddDiskInstanceId, AddDiskBusType, AddDiskModel). Add the new screen to DevicesMenu as index 3, update nav() count from 3 to 4. Wire the new variant into the exhaustive matches in dispatch.rs and render.rs with placeholder arms.
  - Files: `dlp-admin-cli/src/app.rs`, `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo build --package dlp-admin-cli compiles with no warnings

- [x] **T02: Implement load, delete, and add actions with dispatch handlers** `est:45min`
  Implement action_load_disk_registry_list() calling client.get('admin/disk-registry'). Implement handle_disk_registry_list() dispatching Up/Down for navigation, 'd' for delete (client.delete with row's id field, then reload), 'a' to enter TextInput chain for adding a disk (5 fields: agent_id, instance_id, bus_type, encryption_status, model), Esc to return to DevicesMenu { selected: 3 }. Implement the TextInput completion handler for AddDisk* purposes that chains fields then POSTs to admin/disk-registry. Follow the ManagedOriginList add/delete pattern closely.
  - Files: `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/app.rs`
  - Verify: cargo build --package dlp-admin-cli compiles with no warnings; cargo clippy --package dlp-admin-cli -- -D warnings passes

- [x] **T03: Implement draw_disk_registry_list render function** `est:30min`
  Add draw_disk_registry_list(frame, area, disks, selected) to render.rs. Display a table with columns: Agent ID, Instance ID, Bus Type, Encrypted, Model. Use the same table rendering pattern as draw_device_list or draw_managed_origin_list. Highlight the selected row. Show hints: 'a: Add  d: Delete  Esc: Back'. Handle empty list with a centered message. Wire the DiskRegistryList match arm in draw_screen() to call this function.
  - Files: `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo build --package dlp-admin-cli compiles; cargo clippy --package dlp-admin-cli -- -D warnings passes

- [ ] **T04: Add unit tests for disk registry TUI screen** `est:30min`
  Add unit tests in dispatch.rs and render.rs test modules covering: (1) DevicesMenu now has 4 items and index 3 opens DiskRegistryList, (2) DiskRegistryList Esc returns to DevicesMenu { selected: 3 }, (3) DevicesMenu nav wraps at 4 (update existing wrap test), (4) draw_disk_registry_list renders without panic for empty and non-empty disk lists, (5) handle_disk_registry_list Up/Down navigation. Follow existing test patterns (make_test_app, simulate_key).
  - Files: `dlp-admin-cli/src/screens/dispatch.rs`, `dlp-admin-cli/src/screens/render.rs`
  - Verify: cargo test --package dlp-admin-cli passes all tests including new ones

## Files Likely Touched

- dlp-admin-cli/src/app.rs
- dlp-admin-cli/src/screens/dispatch.rs
- dlp-admin-cli/src/screens/render.rs
