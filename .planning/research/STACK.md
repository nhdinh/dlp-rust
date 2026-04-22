# Technology Stack — v0.6.0 Endpoint Hardening

**Project:** dlp-rust
**Milestone:** v0.6.0 — Application-Aware DLP, Browser Boundary, USB Device Identity
**Researched:** 2026-04-21
**Scope:** New Win32 capabilities only — Win32 process identity, Authenticode signature verification,
USB SetupDi enumeration, Chrome Enterprise Connector protocol, Windows toast notifications.
Existing capabilities (axum 0.8, rusqlite, ratatui, windows 0.58, iced, JWT, r2d2) are NOT
re-researched.

---

## Verdict

Five new capability areas. Four are covered by adding new `windows` crate feature flags to existing
Cargo.toml entries (zero new crates for Win32 work). One new crate for protobuf (Chrome connector).
One new crate for toast notifications is already in the project. The windows crate should be upgraded
from 0.58 to 0.62.

---

## windows Crate Upgrade: 0.58 → 0.62

**Current version:** `windows = "0.58"` (both `dlp-agent` and `dlp-user-ui`)
**Target version:** `windows = "0.62"` (latest stable as of 2025-10-06, version 0.62.2)

**Why upgrade:** The new feature flags needed for v0.6.0 (`Win32_Devices_DeviceAndDriverInstallation`,
`Win32_Security_WinTrust`, `UI_Notifications`) are available in 0.62. The 0.58 codebase has reports
of a regression with `Win32_Devices_DeviceAndDriverInstallation` not resolving correctly; 0.62 is the
stable target all current documentation points to. The upgrade involves metadata-driven code generation
changes, not public API redesigns — existing feature flags and function signatures are preserved.

**Risk:** MEDIUM. The windows-rs project does break binary metadata between minor versions. Run
`cargo check --workspace` after bumping to catch any signature changes in the existing `windows` API
surface used by the current agent (predominantly `Win32_UI_WindowsAndMessaging`,
`Win32_System_Threading`, `Win32_Storage_FileSystem`). These modules have been stable across 0.58
through 0.62.

---

## Capability 1: Win32 Process Identity Detection

**Crate:** `windows` (existing, feature additions only)
**Feature additions to `dlp-agent/Cargo.toml` and `dlp-user-ui/Cargo.toml`:**

```toml
windows = { version = "0.62", features = [
    # --- existing features omitted for brevity ---
    # NEW for APP-01 / APP-02 (destination + source app detection):
    "Win32_System_Threading",   # Already present — OpenProcess, QueryFullProcessImageNameW,
                                # GetWindowThreadProcessId, PROCESS_QUERY_LIMITED_INFORMATION
    "Win32_UI_WindowsAndMessaging",  # Already present — GetForegroundWindow, GetClipboardOwner,
                                    # GetWindowThreadProcessId
] }
```

**No new feature flags required for core process identity.** The APIs needed —
`GetForegroundWindow`, `GetWindowThreadProcessId`, `OpenProcess`, `QueryFullProcessImageNameW`,
`GetClipboardOwner` — are all in `Win32_System_Threading` and `Win32_UI_WindowsAndMessaging`,
which are already enabled in both crates.

**API surface in `windows::Win32::System::Threading`:**
- `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)` — opens handle with minimum rights
- `QueryFullProcessImageNameW(handle, 0, buf, &mut size)` — returns full image path (e.g.
  `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`)
- `PROCESS_QUERY_LIMITED_INFORMATION` — constant (prefer over `PROCESS_QUERY_INFORMATION`; works
  without admin rights on Win 8+)

**API surface in `Win32_UI_WindowsAndMessaging`:**
- `GetForegroundWindow()` — returns HWND of foreground window at paste time
- `GetClipboardOwner()` — returns HWND of last `SetClipboardData` caller (capture at
  WM_CLIPBOARDUPDATE, not at paste time — the window may be gone by paste time)
- `GetWindowThreadProcessId(hwnd, &mut pid)` — maps HWND → PID

**UWP / AUMID detection:**

UWP apps (Store apps, Edge's renderer processes) do not have a meaningful Win32 image path — they
report `C:\Windows\System32\RuntimeBroker.exe` or similar host processes. Identity comes from the
Application User Model ID (AUMID).

Add `Win32_UI_Shell` to `dlp-user-ui/Cargo.toml` (already present) and use:
- `GetCurrentProcessExplicitAppUserModelID()` — gets the AUMID of the current process (usable from
  within a UWP-hosted process context)
- For enumerating the AUMID of *another* process: use `SHGetPropertyStoreForWindow` +
  `PKEY_AppUserModel_ID` from the property store. This requires `Win32_UI_Shell_PropertiesSystem`.

```toml
# dlp-user-ui/Cargo.toml — add if not present
"Win32_UI_Shell",                    # Already present
"Win32_UI_Shell_PropertiesSystem",   # NEW — for SHGetPropertyStoreForWindow + PKEY_AppUserModel_ID
```

**Where this code lives:** New file `dlp-user-ui/src/detection/application.rs`. Process identity
detection MUST run in dlp-user-ui (user session), not dlp-agent (session 0). `GetForegroundWindow`
is per-session; calling it from session 0 returns 0 (no foreground window in session 0).

**Confidence:** HIGH — function names and module paths verified against
microsoft.github.io/windows-docs-rs.

---

## Capability 2: Authenticode Signature Verification (Anti-Spoofing)

**Crate:** `windows` (existing, one new feature flag)
**Feature addition to `dlp-agent/Cargo.toml`:**

```toml
"Win32_Security_WinTrust",  # NEW — WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO
```

This depends on `Win32_Security` which is already present.

**API surface in `windows::Win32::Security::WinTrust`:**
- `WinVerifyTrust(HWND_DESKTOP, &WINTRUST_ACTION_GENERIC_VERIFY_V2, &mut data)` — verifies
  Authenticode signature on a file
- `WINTRUST_DATA` — top-level struct passed to `WinVerifyTrust`
- `WINTRUST_FILE_INFO` — specifies the file path to verify
- Return `S_OK` (0) → valid signature; `TRUST_E_NOSIGNATURE` (0x800B0100) → no sig;
  `TRUST_E_BAD_LENGTH` / `TRUST_E_SUBJECT_FORM_UNKNOWN` → corrupted or unsigned

**What it detects:** A renamed `notepad.exe → excel.exe` will have no Authenticode signature (or a
Microsoft-signed signature that doesn't match the expected publisher for Excel). Check: (1) is file
signed? (2) does the signer's Subject CN match the expected publisher? Publisher extraction requires
walking the `WINTRUST_DATA` result after verification — the `pwszPublisher` field is available in
the chain.

**Important limitation — CVE-2013-3900:** On unpatched Windows, `WinVerifyTrust` can be tricked
with an appended file. The patch (KB2893294, opt-in) enforces strict signature checking. For DLP
purposes this is acceptable: we use signature verification as a heuristic anti-spoofing layer, not
as a cryptographic proof. The audit trail documents the verification result. Do not rely on this as
a sole enforcement control for T4 assets.

**Where this code lives:** `dlp-user-ui/src/detection/application.rs` alongside process identity.
Must run in user session (see above). Alternatively, the agent can verify the image path received
via Pipe 3 — but this requires the image path to be fully-qualified and verifiable from session 0.
Prefer user-session verification for freshness.

**Confidence:** HIGH — `WinVerifyTrust` confirmed present in `windows::Win32::Security::WinTrust`
module with the expected signature via microsoft.github.io/windows-docs-rs.

---

## Capability 3: USB Device Identity Enumeration (SetupDi)

**Crate:** `windows` (existing, one new feature flag)
**Feature addition to `dlp-agent/Cargo.toml`:**

```toml
"Win32_Devices_DeviceAndDriverInstallation",  # NEW — SetupDi* family
```

This depends on `Win32_Devices` (added transitively). No additional parent feature needs to be
explicitly listed.

**API surface in `windows::Win32::Devices::DeviceAndDriverInstallation`:**
- `SetupDiGetClassDevsW(None, "USB", None, DIGCF_PRESENT | DIGCF_ALLCLASSES)` — get handle to
  device info set for all present USB devices
- `SetupDiEnumDeviceInfo(devinfo, index, &mut devinfo_data)` — iterate device entries
- `SetupDiGetDeviceRegistryPropertyW(devinfo, &devinfo_data, SPDRP_HARDWAREID, ...)` — returns
  `USB\VID_xxxx&PID_yyyy&REV_zzzz` formatted Hardware ID
- `SetupDiGetDeviceRegistryPropertyW(..., SPDRP_DEVICEDESC, ...)` — returns user-visible
  description (e.g., "Kingston DataTraveler 3.0 USB Device")
- `SetupDiGetDeviceRegistryPropertyW(..., SPDRP_MFG, ...)` — manufacturer string
- `SetupDiDestroyDeviceInfoList(devinfo)` — frees the device info set

**Serial number extraction:** The serial number is NOT in a standard SPDRP property. It is embedded
in the Device Instance ID string (e.g.,
`USB\VID_0951&PID_1666\0D8698F44A69A9B1234`). The last component after the final backslash is the
serial number when it is a real serial (alphanumeric, 5+ chars). When Windows generates a synthetic
ID (numeric only, e.g., `0000000000000001`), the device has no USB serial descriptor.

Extract via `SetupDiGetDeviceInstanceIdW(devinfo, &devinfo_data, buf, size, &mut required)`.

**Where this code lives:** Extend `dlp-agent/src/detection/usb.rs`. Hook into the existing
`WM_DEVICECHANGE` / `DBT_DEVICEARRIVAL` handler after the existing `GetDriveTypeW` call. The
SetupDi enumeration runs synchronously within the device-arrival callback — it is fast (milliseconds)
for a single newly-arrived device.

**Pattern:** Mirror `dlp-agent/src/detection/network_share.rs` — `Arc<RwLock<HashMap<String,
DeviceIdentity>>>` keyed by drive letter, populated on arrival, cleared on
`DBT_DEVICEREMOVECOMPLETE`.

**Confidence:** HIGH — `SetupDiGetClassDevsW`, `SetupDiEnumDeviceInfo`,
`SetupDiGetDeviceRegistryPropertyW`, `SetupDiDestroyDeviceInfoList` all confirmed present in
`windows::Win32::Devices::DeviceAndDriverInstallation` module via microsoft.github.io/windows-docs-rs.

---

## Capability 4: Chrome Enterprise Content Analysis Connector

**Protocol:** Named pipe (Windows), NOT HTTPS. Chrome communicates with the local DLP agent via a
Windows named pipe using Protocol Buffers (protobuf) serialization. The pipe is created by the agent;
Chrome connects to it. This is a local IPC mechanism, not an HTTP endpoint.

**Transport details:**
- Pipe name format (non-user-specific): `\\.\pipe\ProtectedPrefix\Administrators\<agent_name>`
- Pipe name format (user-specific): `\\.\pipe\<agent_name>.<user_sid>`
- Chrome discovers the agent pipe name from the `BulkDataEntryAnalysisConnector` /
  `OnPasteEnterpriseConnector` policy value, which specifies the `service_provider` name that
  Chrome maps to the registered pipe name.
- Chrome POSTs serialized `ChromeToAgent` protobuf messages; agent responds with `AgentToChrome`
  protobuf messages.
- Messages are framed with a 4-byte little-endian length prefix followed by serialized proto bytes.

**Proto schema (from `chromium/content_analysis_sdk`):**
- `ContentAnalysisRequest` — `request_token`, `analysis_connector` (BULK_DATA_ENTRY for paste),
  `reason` (CLIPBOARD_PASTE), `content_data` (text_content for paste), `request_data` (tab URL,
  etc.), `expires_at`
- `ContentAnalysisResponse` — `request_token`, `results[]` with `TriggeredRule.action` =
  BLOCK / WARN / REPORT_ONLY
- `ContentAnalysisAcknowledgement` — Chrome sends back after acting on the response (ALLOW / BLOCK)
- `ContentAnalysisCancelRequests` — Chrome cancels in-flight requests

**Crate: `prost` + `prost-build`**

```toml
# dlp-agent/Cargo.toml [dependencies]
prost = "0.14"

# dlp-agent/Cargo.toml [build-dependencies]
prost-build = "0.14"
```

Add a `build.rs` that calls `prost_build::compile_protos(&["proto/analysis.proto"], &["proto/"])`.
Copy `content_analysis_sdk/proto/content_analysis/sdk/analysis.proto` into
`dlp-agent/proto/content_analysis/sdk/analysis.proto`.

**Why prost over manual JSON:** Chrome sends raw protobuf over the pipe, not JSON. There is no HTTPS
endpoint. Using `prost` with `prost-build` is the idiomatic Rust path and matches exactly how
Symantec/Broadcom implement this connector in their SDK.

**Why prost 0.14 (not 0.13 or gRPC tonic):** prost 0.14 is the current stable release (2025).
gRPC/tonic is not needed — this is raw protobuf over named pipe, not HTTP/2. `prost-build` compiles
the `.proto` files in `build.rs`; no external `protoc` binary is required when using the bundled
protoc approach (`prost-build` handles this).

**Named pipe server in Rust:** The existing agent already creates named pipes for IPC (Pipe 1/2/3 in
`dlp-agent/src/ipc/`). Reuse the same `tokio::net::windows::named_pipe::ServerOptions` pattern. The
Chrome connector pipe is a separate server from Pipes 1/2/3 — it lives in a new module
`dlp-agent/src/chrome_connector.rs` that handles the Chrome protobuf protocol.

**No new windows features needed for named pipe server:** `Win32_System_Pipes` is already enabled.
The tokio async named pipe API does not use windows-rs directly — it wraps the OS via the tokio
runtime.

**Policy registration:** The Chrome enterprise policy
`BulkDataEntryAnalysisConnector` (for paste) or `OnPasteEnterpriseConnector` must be set via Group
Policy or Intune with `"service_provider": "local_content_analysis"` and an agent name matching the
pipe. Document this in deployment runbook; no code change needed in dlp-server for the policy push
itself.

**Confidence:** HIGH for protocol (verified by reading chromium/content_analysis_sdk source).
MEDIUM for Chrome policy name exactly (`OnPasteEnterpriseConnector` vs
`BulkDataEntryAnalysisConnector`) — Google's documentation uses both terms in different contexts.
The proto schema itself is HIGH confidence (directly read from analysis.proto).

---

## Capability 5: Windows Toast Notifications

**Existing crate:** `winrt-notification = "0.5"` is already in `dlp-user-ui/Cargo.toml`.

**Verdict: Keep `winrt-notification` for v0.6.0. Do NOT add a new toast crate.**

The `winrt-notification 0.5.1` crate wraps `windows::UI::Notifications::ToastNotificationManager`
and provides a builder API (`Toast::new(app_id).title(...).text1(...).show()`). It requires an
app ID string but does NOT require a registered COM activator for display-only toasts (no action
callbacks). This is exactly the use case for USB block notifications: show and forget.

**Why winrt-notification 0.5.1 (not win-toast-notify 0.1.6 or winrt-toast 0.1.1):**
- `winrt-notification` is already in the dependency graph — no new crate needed
- `winrt-toast` has a stale windows-rs dependency (`^0.39.0`) — incompatible with windows 0.62
- `win-toast-notify 0.1.6` has only `xml` as a dependency (uses COM/WinRT via raw FFI) — more
  complex to validate
- `Shell_NotifyIconW` + `NIF_INFO` balloon approach is deprecated on Win 10+ and unreliable on
  Win 11; avoid

**Session constraint:** Toast notifications MUST be shown from `dlp-user-ui` (user session process),
not from `dlp-agent` (SYSTEM session 0). This is already the established pattern in this project —
the clipboard monitor and tray icon both run in dlp-user-ui. USB block notifications follow the same
model: the agent sends a Pipe 1/2 IPC message to dlp-user-ui, which calls `Toast::show()`.

**App ID for toasts:** Use a stable string like `"DLP.SecurityAgent"`. This does not need to match
an installed AUMID as long as the process is not a packaged app. The `winrt-notification` examples
use `Toast::POWERSHELL_APP_ID` as a default; use a DLP-specific string so the notification source
is identifiable to end users.

**windows crate feature for UI_Notifications:** The `winrt-notification` crate uses windows-rs
internally but declares its own `windows` dependency at `^0.24.0`. This is a transitive dependency
and does NOT conflict with the workspace-level `windows = "0.62"` dependency, because
`winrt-notification` uses `windows` as a private dependency for COM activation only. Cargo resolves
this correctly.

**Confidence:** HIGH for session constraint and approach. MEDIUM for `winrt-notification` internal
windows-rs version compatibility — the crate pins `^0.24.0`, but `winrt-notification`'s source
confirms it uses the WinRT `windows::UI::Notifications` namespace which has been stable since
windows 0.24. No known breakage.

---

## Summary: Dependency Delta for v0.6.0

### `Cargo.toml` workspace — no changes needed

### `dlp-agent/Cargo.toml`

```toml
[dependencies]
# Bump existing:
windows = { version = "0.62", features = [
    # ... all existing features ...
    # NEW additions:
    "Win32_Devices_DeviceAndDriverInstallation",   # SetupDi* for USB VID/PID/Serial
    "Win32_Security_WinTrust",                     # WinVerifyTrust for Authenticode
] }

# NEW:
prost = "0.14"   # Chrome Content Analysis Connector protobuf deserialization

[build-dependencies]
# NEW:
prost-build = "0.14"   # Compiles analysis.proto in build.rs
```

### `dlp-user-ui/Cargo.toml`

```toml
[dependencies]
# Bump existing:
windows = { version = "0.62", features = [
    # ... all existing features ...
    # NEW addition:
    "Win32_UI_Shell_PropertiesSystem",  # SHGetPropertyStoreForWindow for UWP AUMID
] }

# winrt-notification = "0.5" already present — no change
```

### Build script addition

New file `dlp-agent/build.rs`:

```rust
fn main() {
    prost_build::compile_protos(
        &["proto/content_analysis/sdk/analysis.proto"],
        &["proto/"],
    )
    .expect("prost_build must compile Chrome Content Analysis proto");
}
```

---

## What NOT to Add

| Rejected option | Reason |
|----------------|--------|
| `winapi` crate | Legacy, unmaintained. All needed APIs are in `windows` crate. |
| `setupapi` crate | Unmaintained thin wrapper. Use `windows` feature flag directly. |
| `authenticode` crate | No active Rust crate for this exists with current windows-rs support. Use raw `WinVerifyTrust` via windows-rs. |
| `tonic` / gRPC | Chrome connector is raw protobuf over named pipe, not gRPC. Tonic adds HTTP/2 overhead with no benefit. |
| `notify-rust` | Linux-first. Does not work on Windows. |
| `win-toast-notify` | Redundant — `winrt-notification` already in project. |
| HTTP endpoint for Chrome connector | Chrome uses named pipe IPC, not HTTP. Adding an HTTPS endpoint would not receive Chrome connector events. |
| `windows-service` version bump | Not required — no changes to service lifecycle for v0.6.0 features. |
| Separate `dlp-chrome-connector` crate | Overkill — the Chrome named pipe server is a single async task in `dlp-agent/src/chrome_connector.rs`. |

---

## Key Integration Points

| New capability | Lives in | Communicates with |
|---------------|----------|-------------------|
| Process identity (`GetForegroundWindow`, `QueryFullProcessImageNameW`) | `dlp-user-ui/src/detection/application.rs` | Pipe 3 `ClipboardAlert` — new fields `source_app`, `dest_app` |
| Authenticode verification (`WinVerifyTrust`) | `dlp-user-ui/src/detection/application.rs` | Same — called after process identity resolution |
| UWP AUMID detection (`SHGetPropertyStoreForWindow`) | `dlp-user-ui/src/detection/application.rs` | Same — fallback path when image path is a host process |
| SetupDi USB enumeration | `dlp-agent/src/detection/usb.rs` | Populates `DeviceIdentity` in `UsbDetector`; audit event via existing `audit_emitter.rs` |
| Chrome Content Analysis named pipe | `dlp-agent/src/chrome_connector.rs` (new) | dlp-server admin API for managed origins; `ContentAnalysisResponse` with BLOCK decision |
| USB block toast notification | `dlp-user-ui/src/notifications.rs` (new or extend) | Triggered by Pipe 1/2 message from agent on USB block event |

---

## Confidence Assessment

| Area | Confidence | Reason |
|------|------------|--------|
| Windows feature flags for SetupDi | HIGH | Confirmed in microsoft.github.io/windows-docs-rs docs |
| Windows feature flags for WinVerifyTrust | HIGH | Confirmed in microsoft.github.io/windows-docs-rs + win32 docs |
| Process identity API surface | HIGH | All functions confirmed in `Win32_System_Threading` / `Win32_UI_WindowsAndMessaging` |
| UWP AUMID via shell property store | MEDIUM | `GetCurrentProcessExplicitAppUserModelID` confirmed; cross-process property store path less documented in Rust |
| Chrome connector is named pipe (not HTTPS) | HIGH | Confirmed by reading chromium/content_analysis_sdk agent_win.cc |
| Chrome proto schema | HIGH | Read directly from analysis.proto in chromium repo |
| Chrome policy name exact string | MEDIUM | Google docs use multiple policy names; functional behavior confirmed, exact policy name needs validation against Chrome admin policy list |
| winrt-notification 0.5 compat with windows 0.62 | MEDIUM | Crate pins windows ^0.24; transitive dep resolution works but not explicitly tested against 0.62 |
| windows 0.58 → 0.62 migration risk | MEDIUM | No documented API surface breaks for used modules; metadata changes exist |

---

## Sources

- [windows-rs 0.62.2 Cargo.toml feature flags (docs.rs)](https://docs.rs/crate/windows/latest/source/Cargo.toml.orig)
- [windows-rs releases page — 0.58 through 0.62.2 dates](https://github.com/microsoft/windows-rs/releases)
- [SetupDiGetClassDevsW in windows::Win32::Devices::DeviceAndDriverInstallation (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Devices/DeviceAndDriverInstallation/fn.SetupDiGetClassDevsW.html)
- [WinVerifyTrust in windows::Win32::Security::WinTrust (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/WinTrust/fn.WinVerifyTrust.html)
- [QueryFullProcessImageNameW in windows::Win32::System::Threading (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Threading/fn.QueryFullProcessImageNameW.html)
- [ToastNotificationManager in windows::UI::Notifications (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/UI/Notifications/struct.ToastNotificationManager.html)
- [chromium/content_analysis_sdk — official Chrome DLP connector SDK](https://github.com/chromium/content_analysis_sdk)
- [analysis.proto — ContentAnalysisRequest / ContentAnalysisResponse schema](https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/proto/content_analysis/sdk/analysis.proto)
- [common/utils_win.cc — GetPipeNameForAgent, named pipe name format](https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/common/utils_win.cc)
- [agent_win.cc — Chrome named pipe server implementation](https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/agent/src/agent_win.cc)
- [prost crate (tokio-rs/prost)](https://github.com/tokio-rs/prost)
- [winrt-notification 0.5.1 (allenbenz)](https://github.com/allenbenz/winrt-notification)
- [WinVerifyTrust function — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [SetupDiGetClassDevsW function — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw)
- [GetCurrentProcessExplicitAppUserModelID (docs-rs)](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/UI/Shell/fn.GetCurrentProcessExplicitAppUserModelID.html)
