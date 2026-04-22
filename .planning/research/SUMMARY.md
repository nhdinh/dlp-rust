# Research Summary — v0.6.0 Endpoint Hardening

**Project:** dlp-rust
**Milestone:** v0.6.0 — Endpoint Hardening (SEED-001 + SEED-002 + SEED-003)
**Researched:** 2026-04-22
**Confidence:** HIGH (codebase-derived); MEDIUM (Chrome connector protocol exact schema)

---

## Stack Additions

| Crate / Feature Flag | Version | Purpose | Notes |
|---|---|---|---|
| `windows` feature: `Win32_Devices_DeviceAndDriverInstallation` | 0.62 (bump from 0.58) | SetupDi USB enumeration — VID/PID/Serial | Bump first phase; validate no API breaks |
| `windows` feature: `Win32_Security_WinTrust` | 0.62 | Authenticode signature verification | `WinVerifyTrust` — must run in `spawn_blocking` |
| `windows` feature: `Win32_UI_Shell_PropertiesSystem` | 0.62 | UWP AUMID via `PKEY_AppUserModel_ID` | Sparse Rust docs; may need a small spike |
| `prost = "0.14"` + `prost-build = "0.14"` | 0.14 | Chrome Enterprise Connector protobuf serialization | Add `build.rs` in `dlp-agent`; copy `analysis.proto` from `chromium/content_analysis_sdk` |
| `winrt-notification = "0.5"` | 0.5 | USB toast notifications | Already in `dlp-user-ui/Cargo.toml` — reuse, do not add |

**What NOT to add:** custom form library, kernel filter driver crate, browser extension build toolchain (no Path A in v0.6.0), `notify` crate upgrade for USB-03 enforcement.

---

## Feature Table Stakes

### SEED-001: Application-Aware DLP
- Capture **destination process** image path + publisher at paste time (`GetForegroundWindow` → `GetWindowThreadProcessId` → `QueryFullProcessImageNameW`) — in `dlp-user-ui`
- Capture **source process** via `GetClipboardOwner` at `WM_CLIPBOARDUPDATE` time — synchronously, before the source window closes
- Authenticode publisher extraction (not full blocking validation) via `WinVerifyTrust` — cached, non-blocking
- `AppIdentity` struct added to `dlp-common::abac::AbacContext` as `source_application` + `destination_application`
- Evaluator enforces new conditions; audit events populated with app fields

### SEED-002: Browser Boundary (Chrome Enterprise Connector)
- `dlp-agent` registers as a Chrome Content Analysis agent via named pipe (`\\.\pipe\brcm_chrm_cas`) + protobuf
- `dlp-server` exposes managed-origins DB table + admin API for allow/block list
- Paste from a protected origin to an unmanaged origin is blocked and audited
- **Depends on SEED-001 AppIdentity being in dlp-common first**

### SEED-003: USB Device-Identity Whitelist
- Agent enumerates VID/PID/Serial/description on `DBT_DEVICEARRIVAL` via `SetupDiGetDeviceInstanceIdW`
- `device_registry` DB table + JWT-protected admin API (GET/POST/DELETE)
- Trust tiers: `blocked` / `read_only` / `full_access`; read-only enforced at I/O level in `file_monitor.rs`
- User toast notification on block (`winrt-notification`, from `dlp-user-ui`)
- Audit events include device identity fields

---

## Build Order

```
Phase 22 — dlp-common foundation
  New types: AppIdentity, SignatureState, DeviceIdentity, UsbTrustTier
  Modified: AbacContext, AuditEvent, Pipe3 ClipboardAlert, Pipe2 messages
  ← BLOCKS everything below

Phase 23 (parallel) — USB enumeration in dlp-agent
  SetupDi calls on DBT_DEVICEARRIVAL; log VID/PID/Serial; no behavior change yet

Phase 24 (parallel) — Device registry DB + admin API in dlp-server
  device_registry table; GET/POST/DELETE /admin/device-registry routes

Phase 25 (parallel) — App identity capture in dlp-user-ui
  GetClipboardOwner at WM_CLIPBOARDUPDATE; GetForegroundWindow at paste;
  Authenticode; UWP AUMID; AppIdentity → Pipe 3 ClipboardAlert

Phase 26 — ABAC enforcement convergence
  Evaluator handles AppIdentity + DeviceIdentity conditions;
  USB trust tier enforcement in file_monitor.rs hot path

Phase 27 — USB toast notification in dlp-user-ui
  Pipe 2 UsbBlockNotify variant → winrt-notification toast

Phase 28 — Admin TUI screens in dlp-admin-cli
  App identity condition picker; Device Registry screen; managed-origins screen

Phase 29 — Chrome Enterprise Connector in dlp-agent
  Named pipe server; protobuf decode; BrowserClipboardAlert audit path
```

Phases 23, 24, 25 can run in parallel after Phase 22 lands (different crates, no shared changes).

---

## Watch Out For

1. **Clipboard ownership race** (CRITICAL) — `GetClipboardOwner` returns a dead HWND if the source window closes before capture. Must be called synchronously inside the `WM_CLIPBOARDUPDATE` handler, not in the 100ms polling loop. Structural change to `clipboard_monitor.rs` required.

2. **`WinVerifyTrust` blocks on CRL network** (HIGH) — Will freeze the UI message thread on machines with slow CRL endpoints. Must be routed through `tokio::task::spawn_blocking` with a per-process result cache from day one. Never call inline in the message pump.

3. **Chrome connector is named pipe + protobuf, NOT HTTP** (HIGH) — The SEED-002 "Path B HTTP endpoint" description refers to a different protocol. The actual Chrome Content Analysis SDK transport is a Win32 named pipe with protobuf frames. Building the wrong transport wastes the entire phase. Verify against `chromium/content_analysis_sdk` before Phase 29 starts.

4. **Pipe 3 `ClipboardAlert` cross-crate deserialization** (HIGH) — This struct is duplicated in both `dlp-user-ui` and `dlp-agent`. New fields without `#[serde(default)]` cause silent runtime deserialization failures — no compile error. Every new field MUST carry `#[serde(default)]`.

5. **USB-03 enforcement feasibility** (MEDIUM) — Current `file_monitor.rs` uses `notify` which may be observation-only (no write-blocking capability). If so, USB read-only enforcement requires a different hook point. Resolve this as a design gate before writing Phase 26 USB enforcement code.

---

## Open Questions

| Question | Phase | Priority |
|---|---|---|
| Does `notify` backend on Windows actually block writes, or is it observation-only? | Before Phase 26 | HIGH |
| Exact Chrome named pipe path and HKLM registration key format | Before Phase 29 | HIGH |
| Does `winrt-notification 0.5` compile against `windows 0.62`? | Phase 22 | MEDIUM |
| UWP AUMID via `SHGetPropertyStoreForWindow` + `PKEY_AppUserModel_ID` — Rust docs sparse; needs a spike | Phase 25 | MEDIUM |
| Toast channel: reuse existing Pipe 2 `Toast` variant or add `UsbBlockNotify`? | Phase 27 | LOW |

---

*Research completed: 2026-04-22 | Ready for requirements: yes*
