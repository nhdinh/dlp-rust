# Knowledge

## Windows API Patterns

- `SETUP_DI_REGISTRY_PROPERTY(property)` newtype wrapper required at call site for SetupDiGetDeviceRegistryPropertyW; SPDRP constants kept as u32
- `DBT_DEVTYP_DEVICEINTERFACE` used directly (not `.0`) in windows crate 0.58+ due to DEV_BROADCAST_HDR_DEVICE_TYPE newtype
- `STORAGE_PROPERTY_ID(0)` / `STORAGE_QUERY_TYPE(0)` newtype constructors required for windows 0.61+ (raw u32 no longer accepted)
- `GENERIC_READ` passed as raw u32 `0x8000_0000` for CreateFileW dwDesiredAccess (windows 0.61 expects u32, not FILE_ACCESS_RIGHTS)
- PktPrivacy upgrade requires raw CoSetProxyBlanket FFI because wmi 0.14 lacks `set_proxy_blanket`/`AuthLevel` (wmi 0.18 has these but is not pinned)
- `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` parsed manually via byte offsets (struct not available in windows crate)
- Use `GetVolumePathNamesForVolumeNameW` (not `GetVolumePathNamesForVolumeMountPointW`) for drive letter resolution from volume GUID path
- `windows-core = 0.59` added as direct dep to make `Interface::as_raw()` callable on wmi 0.14-returned IWbemServices

## Architecture Patterns

- Device watcher owns all Win32 window/registration/loop code; per-event handlers are pub fns in their respective modules (usb.rs, disk.rs)
- Disk enforcement is a pre-ABAC layer: evaluated before USB enforcement and before ABAC in `run_event_loop`; uses `continue` to skip ABAC (mirrors USB short-circuit)
- Chrome module NOT gated with `#[cfg(windows)]` at lib.rs level because proto types and cache are platform-agnostic; only handler.rs and registry.rs use `#[cfg(windows)]` internally
- Agent runs as SYSTEM in session 0; UI spawned into user sessions because SYSTEM cannot access user clipboard
- `agent_config` is moved into `InterceptionEngine::with_config` — capture any needed values (like `recheck_interval`) into locals before the move

## Testing Patterns

- Integration tests use `CARGO_TARGET_DIR=target-test` to bypass Windows file-lock on dlp-server.exe held by elevated process
- Use in-process axum router for server side (avoids binary locking and port discovery issues)
- `DLP_SKIP_HARDENING` env var allows `Child::kill()` in tests (DACL blocks PROCESS_TERMINATE)
- `DLP_SKIP_IPC` env var avoids named pipe conflicts with stale agent processes
- `DLP_LOG_DIR` override directs agent logs to temp dir instead of `C:\ProgramData\DLP\logs`
- `CARGO_BIN_EXE_dlp-agent` env var used instead of `cargo run` to avoid EXE file locks

## Rust Idioms

- Clippy prefers `is_none_or` over `map_or(true, ...)` — updated accordingly throughout
- `PartialEq` derives added to result types (`PolicyCondition`, `UsbBlockResult`, `DiskBlockResult`) to enable `assert_eq!` in tests
- `OnceLock<Arc<T>>` pattern for global singletons where T is non-Clone
- Use `\\u{2014}` for em-dash — CLAUDE.md prohibits emoji/unicode emoji but not typographic punctuation; escape avoids source encoding issues

## Operational Conventions

- Axum 0.7+ `.route()` calls for the same path do NOT merge methods — consolidate all HTTP verbs into one `.route()` call
- StatusCode::CREATED (201) for POST endpoints, not 200
- ManagedOriginsCache uses HashSet (not HashMap) — only membership matters
- `is_managed` returns false for unknown origins (fail-open) unlike DeviceRegistryCache which defaults to Blocked (fail-closed)
- Disk enforcement on_disk_arrival heuristic: only fires for exactly one unmapped drive; zero or multiple = ambiguous, park the identity
