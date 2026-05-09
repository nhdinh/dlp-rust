---
estimated_steps: 24
estimated_files: 3
skills_used: []
---

# T03: Add sync-client process watcher loop to service.rs

Add a background watcher loop in `service.rs` that periodically discovers sync-client processes by exe name, checks if the hook DLL is loaded (via `HookInjector::is_module_loaded()`), and injects if not. Wire it into the existing `run_loop_init` / `run_loop_shutdown` lifecycle. Add `Win32_System_Diagnostics_ToolHelp` feature to `dlp-agent/Cargo.toml`.

**Steps:**
1. In `dlp-agent/Cargo.toml`, add `"Win32_System_Diagnostics_ToolHelp"` to the `windows` crate features list (alongside existing `Win32_System_ProcessStatus`).
2. Add a `sync_process_names()` helper that returns `&'static [(&'static str, CloudProvider)]` mapping exe names to providers: `[("OneDrive.exe", OneDrive), ("googledrivesync.exe", GoogleDrive), ("GoogleDriveFS.exe", GoogleDrive), ("Dropbox.exe", Dropbox), ("Box.exe", Box), ("BoxSync.exe", Box)]`. Place this in `cloud_enforcer.rs` as a `pub fn` so it can be reused and tested.
3. Implement `pub fn enumerate_sync_client_pids() -> Vec<(u32, &'static str)>` in `cloud_enforcer.rs` using `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` + `Process32FirstW` / `Process32NextW`. Returns `(pid, exe_name)` pairs for any process whose exe name matches `sync_process_names()`. Handle snapshot failure (log WARN, return empty vec).
4. In `service.rs`, inside `run_loop_init`, after constructing `hook_injector_opt`, add watcher logic only when `hook_injector_opt.is_some()`. Spawn a `std::thread::spawn` (not Tokio task — avoids async context complexity) that loops:
   ```
   loop {
       let pids = enumerate_sync_client_pids();
       for (pid, exe) in pids {
           match HookInjector::is_module_loaded(pid, "dlp_hook_dll.dll") {
               Ok(false) => { injector.inject(pid); log inject result }
               Ok(true) => {} // already hooked
               Err(e) => warn!(pid, exe, err=?e, "module check failed")
           }
       }
       std::thread::sleep(Duration::from_secs(30));
   }
   ```
   Pass a `Arc<AtomicBool>` shutdown flag into the thread; check it at the top of each loop iteration to support clean shutdown.
5. Store the thread join handle in `RunLoopContext` (or as a local in `run_loop_shutdown`) and signal the `AtomicBool` during shutdown before joining.
6. Add unit tests: `test_sync_process_names_covers_all_providers` (verifies all four providers have at least one entry), `test_enumerate_sync_client_pids_returns_vec` (smoke test — calls the function and verifies it returns without panic; does not assert specific PIDs since no sync clients run in CI).
7. Run `cargo build --workspace` and `cargo clippy --workspace -- -D warnings` clean.

**Key constraint:** The watcher thread must not panic if `HookInjector::inject()` fails (e.g., access denied for elevated processes). Wrap each inject call in a `match` and log errors at WARN without propagating.

## Inputs

- `dlp-agent/src/service.rs`
- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/src/hook_injector.rs`
- `dlp-agent/Cargo.toml`

## Expected Output

- `dlp-agent/src/service.rs`
- `dlp-agent/src/cloud_enforcer.rs`
- `dlp-agent/Cargo.toml`

## Verification

cargo build --workspace 2>&1 | tail -5 && cargo test -p dlp-agent cloud_enforcer 2>&1 | tail -5 && cargo clippy --workspace -- -D warnings 2>&1 | tail -10

## Observability Impact

Watcher loop logs each injection attempt at INFO (pid, exe, success) and each skip (already-hooked) at TRACE. Injection failures log at WARN with pid, exe, and error. Shutdown signal logged at INFO. Thread panic is caught at the thread boundary and logged at ERROR.
