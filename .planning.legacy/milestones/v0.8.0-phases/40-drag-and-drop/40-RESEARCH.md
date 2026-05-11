# Phase 40 Research: OLE Drag-and-Drop Enforcement

## Objective

Research how to implement OLE drag-and-drop interception in Rust for the DLP agent.

## Key APIs

### Windows APIs (windows-rs 0.62)

| API | Module | Purpose |
|-----|--------|---------|
| `SetWindowsHookEx` | `Win32_UI_WindowsAndMessaging` | Global message hook for WM_DROPFILES |
| `CallNextHookEx` | `Win32_UI_WindowsAndMessaging` | Chain to next hook |
| `GetMessage` | `Win32_UI_WindowsAndMessaging` | Message loop integration |
| `RegisterDragDrop` | `Win32_System_Ole` | Register window as drop target |
| `RevokeDragDrop` | `Win32_System_Ole` | Unregister drop target |
| `IDropTarget` | `Win32_System_Ole` | COM interface for drop targets |
| `DoDragDrop` | `Win32_System_Ole` | Initiate drag operation |
| `GetWindowThreadProcessId` | `Win32_UI_WindowsAndMessaging` | Get PID from HWND |
| `OpenProcess` | `Win32_System_Threading` | Open process handle |
| `GetModuleFileNameExW` | `Win32_System_ProcessStatus` | Get process image path |
| `GetApplicationUserModelId` | `Win32_Storage_Packaging_Appx` | Get AUMID for UWP |

### Data Formats

- `CF_UNICODETEXT` — Text drag-and-drop (same format as clipboard)
- `CF_HDROP` — File drag-and-drop (HDROP handle)
- `IDataObject` — OLE data object containing dragged data

## Approach Comparison

| Approach | Complexity | Coverage | Thread Safety |
|----------|-----------|----------|---------------|
| Global WH_GETMESSAGE hook for WM_DROPFILES | Low | File drops only | Safe (message hook) |
| IDropTarget hook per window | High | All formats | Risky (COM on caller thread) |
| Hook DoDragDrop at source | Medium-High | All formats | Moderate |
| Shell drag-and-drop handler | Medium | Explorer only | Safe |

**Recommended:** Start with WH_GETMESSAGE hook for WM_DROPFILES (file drops). Add IDropTarget for text drops as a second wave.

## Thread Safety Critical Finding

Returning `DROPEFFECT_NONE` from `IDropTarget::Drop` on a background thread hangs Explorer. The COM call originates on the UI thread of the destination application. Any blocking or cross-thread manipulation of the drop result must be done before returning.

**Mitigation:** Evaluate ABAC synchronously on the calling thread. The ABAC evaluate path (cache lookup + condition matching) is sub-millisecond. If evaluation exceeds a threshold, allow the drop and emit an async alert.

## App Identity Resolution

Same pipeline as clipboard monitor:
1. `GetWindowThreadProcessId(hwnd) -> pid`
2. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) -> handle`
3. `QueryFullProcessImageNameW(handle) -> path` (or `GetModuleFileNameExW`)
4. For UWP: `GetApplicationUserModelId(handle) -> aumid`
5. `WinVerifyTrust(path) -> signature state`
6. Build `AppIdentity` with all fields

## Code Locations

- **New:** `dlp-agent/src/interception/drag_drop.rs`
- **Extend:** `dlp-agent/src/interception/mod.rs` (event loop)
- **Extend:** `dlp-common/src/abac.rs` (Action::DragDrop)
- **Extend:** `dlp-agent/src/ipc/messages.rs` (Pipe3AgentMsg::DragDropAlert)
- **Port:** `dlp-agent/src/detection/app_identity.rs` (from dlp-user-ui)

## Dependencies

- Phase 39 must complete first (AppIdentity schema with UWP fields)
- `Win32_System_Ole` feature needed in `windows` crate

## Validation Architecture

### Test Strategy
1. Unit tests for WM_DROPFILES message detection
2. Unit tests for drag_drop data format parsing (CF_HDROP)
3. Integration test for ABAC evaluate with DragDrop action
4. Manual test: drag file from notepad to explorer with T3 policy

### Guardrails
- Explorer thread must never hang
- Hook must be uninstallable on service stop
- Failed app identity resolution must not block drop (fail open for usability, audit the failure)

## Research Flags

- `IDropTarget` vtable construction in `windows-rs` `implement` macro needs verification
- Drag-and-drop deduplication: 5-second cooldown on same source/dest pair
