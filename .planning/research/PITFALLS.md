# Domain Pitfalls — v0.6.0 Endpoint Hardening

**Domain:** Windows DLP — App-aware clipboard, Browser connector, USB device identity
**Researched:** 2026-04-21
**Scope:** Pitfalls specific to adding these features to this Rust/Windows codebase

---

## Section 1: Application-Aware DLP (APP-01 to APP-06)

### PITFALL-A1: Clipboard Ownership Race — Dead HWND from GetClipboardOwner

**Problem:** `GetClipboardOwner()` returns the HWND of the window that last called
`SetClipboardData`. If the source window is destroyed before the DLP code resolves
PID from that HWND, `GetWindowThreadProcessId` returns 0 for the PID and the identity
is lost. This happens routinely — apps that copy to clipboard then immediately close
(short-lived paste dialogs, context-menu handlers, scripted automation) leave dead
HWNDs within milliseconds.

**Why it happens:** `handle_clipboard_change` in `dlp-user-ui/src/clipboard_monitor.rs`
fires on `WM_CLIPBOARDUPDATE`, which is delivered asynchronously via the message pump.
The 100ms sleep in the current polling loop (`PeekMessageW` + `thread::sleep`) means
source identity capture can lag by up to 100ms after the clipboard change. During that
window, any short-lived source process has already exited.

**Prevention:**
- Capture `GetClipboardOwner()` SYNCHRONOUSLY inside the `WM_CLIPBOARDUPDATE` handler
  itself — not after the sleep cycle. Remove the 100ms sleep on the clipboard-update
  code path (sleep only on the idle/no-message branch).
- Cache `(hwnd, pid, image_path)` in a `Mutex<Option<AppIdentity>>` at WM_CLIPBOARDUPDATE
  time. Use this cached value when building the `ClipboardAlert` — never re-query
  at alert-send time.
- If `GetWindowThreadProcessId` returns 0, log a warn-level event with identity
  `AppIdentity::Unknown` and proceed. Never panic or block the clipboard monitor thread.

**Phase to address:** Phase for APP-02 (source app detection). The caching structure
must be in place before APP-05 (audit enrichment) can populate source fields.

---

### PITFALL-A2: UWP / AppX Apps Return Wrong Path from QueryFullProcessImageNameW

**Problem:** For UWP apps (Windows Store apps, Win11 system apps), `OpenProcess` +
`QueryFullProcessImageNameW` returns the host process path (`C:\Windows\System32\
RuntimeBroker.exe` or `C:\Program Files\WindowsApps\...\AppName.exe`). The image
path alone is not a reliable identity token — multiple UWP apps share the same host.
The correct identity is the Application User Model ID (AUMID), retrieved via
`GetApplicationUserModelId` (winbase.h) on the process handle. If the code path
only checks image path, all UWP apps will either all match or all miss a publisher rule.

**Why it happens:** Electron/Win32 app detection using `QueryFullProcessImageNameW` is
straightforward. UWP has a fundamentally different identity model (package + app ID,
not filesystem path). SEED-001 explicitly flags this but it is easy to defer until
an actual UWP app triggers the wrong behavior in QA.

**Prevention:**
- Add an `AppIdentityKind` enum (`Win32 { image_path }`, `Uwp { aumid, image_path }`,
  `Unknown`) to the `AppIdentity` struct from the start.
- After `QueryFullProcessImageNameW`, attempt `GetApplicationUserModelId`. If it
  succeeds, the process is UWP; populate `aumid`. If it returns
  `APPMODEL_ERROR_NO_APPLICATION`, the process is Win32.
- Policy conditions for app identity MUST match on `publisher` (from Authenticode
  signer CN, or AUMID package family), not raw `image_path`. Raw path rules are a
  bypass vector (rename the binary) and also break UWP.
- Add unit tests with synthetic `AppIdentity` structs covering both kinds before
  implementing the Win32 API layer.

**Phase to address:** Phase for APP-01 (destination app detection) and APP-06
(anti-spoofing). The `AppIdentity` type must be defined with `AppIdentityKind` before
any detection code is written, or retrofitting breaks existing tests.

---

### PITFALL-A3: Electron App Identity Collapses Multiple Apps to One Publisher

**Problem:** Slack, VSCode, Teams (classic), Discord, Notion, and 20+ other apps all
ship signed Electron bundles. `WinVerifyTrust` on these binaries returns:
- Slack: publisher = "Slack Technologies, Inc."
- VSCode: publisher = "Microsoft Corporation"
- Teams (classic): publisher = "Microsoft Corporation"
- Discord: publisher = "Discord Inc."

If a policy says "allow T3 paste into Microsoft-signed apps", it will match BOTH
VSCode AND Teams — and also any future Microsoft-signed Electron app. Policy authors
expect "allow VSCode" and will author a publisher rule. The rule will silently allow
far more apps than intended.

**Why it happens:** Publisher-based allowlists are coarse. The granularity DLP
operators expect (per-app) requires image-path-based rules, but image paths change
on every app update (version number in path). This is a product design gap that
surfaces as a misconfiguration pitfall.

**Prevention:**
- `AppIdentity` must carry BOTH `publisher: Option<String>` AND `image_path: String`.
- Policy conditions for `SourceApplication` and `DestinationApplication` must support
  matching on either field independently. The TUI condition builder (APP-04) must
  present this clearly: "publisher" for coarse group rules, "image_path glob" for
  specific-app rules.
- Docs and TUI help text must state that publisher rules match ALL apps from that signer.
- For Electron apps, the executable name (e.g., `slack.exe`, `code.exe`) in the
  image path is a more stable identifier than the full path. Consider a normalized
  `executable_name: String` field stripped from the full path.

**Phase to address:** Phase for APP-03 (policy evaluation) and APP-04 (TUI authoring).
The policy condition schema in `dlp-common::abac::PolicyCondition` must have the
`SourceApplication` and `DestinationApplication` variants defined before Phase for
APP-03 begins, or the evaluator will be written to an incomplete contract.

---

### PITFALL-A4: WinVerifyTrust Blocks on Network Calls — Freezes the UI Thread

**Problem:** `WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2` performs
certificate revocation checks (CRL/OCSP) by default. On a machine with no internet
access, or a machine where the CRL endpoint is slow, this call can block for 5-30
seconds. The clipboard monitor runs in `dlp-user-ui` on the UI message thread. A
30-second block on every clipboard change event will freeze the entire user interface
and miss subsequent clipboard events.

**Why it happens:** The default `WINTRUST_DATA` flags do not disable revocation
checking. Most DLP teams discover this only under production load when a flaky proxy
causes random UI hangs.

**Prevention:**
- Set `dwProvFlags` to include `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT` and consider
  `WTD_CACHE_ONLY_URL_RETRIEVAL` for the clipboard hot path.
- Run `WinVerifyTrust` in a `tokio::task::spawn_blocking` or a dedicated thread pool,
  never on the message pump thread.
- Cache verification results: once a binary at path X with size Y and mtime Z is
  verified, cache the `(publisher, signature_state)` result. Re-verify only when the
  file changes (check mtime/size, not hash, for performance). Cache in an
  `Arc<RwLock<HashMap<String, CachedIdentity>>>` shared between source and destination
  detection paths.
- Fallback: if verification takes > 2 seconds, mark the app as
  `SignatureState::VerificationTimeout` and apply the policy's default-for-unknown
  behavior rather than blocking.

**Phase to address:** Phase for APP-06 (anti-spoofing). Must be addressed before
APP-06 is considered complete. The caching structure should be introduced at the same
time as `WinVerifyTrust` integration — retrofitting cache after the fact requires
re-threading call sites.

---

### PITFALL-A5: Pipe 3 ClipboardAlert Protocol Change Breaks Existing Integration Tests

**Problem:** `ClipboardAlert` in `dlp-user-ui/src/ipc/messages.rs` and
`dlp-agent/src/ipc/messages.rs` is a flat struct with 4 fields: `session_id`,
`classification`, `preview`, `text_length`. Adding `source_application` and
`destination_application` as new fields changes the Pipe 3 wire format. The agent-side
handler at `dlp-agent/src/ipc/pipe3.rs:197-228` will fail to deserialize the old
format and emit a `serde_json` error.

**Why it happens:** `Pipe3UiMsg` uses `#[serde(tag = "type", content = "payload")]`.
Adding required fields to `ClipboardAlert` without defaults will break deserialization
of any `ClipboardAlert` sent by a UI that has not yet been updated. During a rolling
deploy (or during the integration test harness when old test fixtures are used), this
causes silent drops.

**Prevention:**
- All new fields in `ClipboardAlert` MUST be `Option<AppIdentity>` with `#[serde(default)]`.
  This is the established pattern for forward/backward compat in this codebase (see
  `EvaluateRequest::agent: Option<AgentInfo>` and `#[serde(default)]` on `AbacContext`).
- Update BOTH `dlp-user-ui/src/ipc/messages.rs` AND `dlp-agent/src/ipc/messages.rs`
  in the same commit. These files are intentionally duplicated (separate crates cannot
  share IPC types without a dependency cycle). Any divergence causes runtime failures
  that do not manifest at compile time.
- Add a round-trip serde test: serialize a `ClipboardAlert` WITHOUT the new fields
  (simulate old sender) and verify the agent-side deserializer succeeds with
  `source_application: None`. This test must pass before the phase is closed.

**Phase to address:** Phase for APP-01 or APP-02, whichever first touches `ClipboardAlert`.
The field additions and the serde compat test are a single atomic change — never split
the struct change from the test.

---

### PITFALL-A6: AbacContext / PolicyCondition Extension Breaks TOML Export

**Problem:** `PolicyCondition` uses `#[serde(tag = "attribute", rename_all = "snake_case")]`.
This is a known TOML incompatibility documented in STATE.md (2026-04-16). Adding
`SourceApplication` and `DestinationApplication` variants to `PolicyCondition` extends
this enum. If any phase tries to export policies containing the new condition types to
TOML (POLICY-F4), it will fail for the same reason as before — and may surface as a
panic at export time if POLICY-F4 is attempted in a future milestone.

**Why it happens:** The `toml` crate does not support internally-tagged enums with
`#[serde(tag)]`. This is a pre-existing deficiency. New enum variants do not fix the
underlying problem and will exhibit the same failure mode.

**Prevention:**
- New `PolicyCondition` variants (`SourceApplication`, `DestinationApplication`) are
  JSON-only — same as all current variants. Do not attempt TOML serialization.
- The TOML deferred status (POLICY-F4) applies to ALL `PolicyCondition` variants,
  not just the old ones. Document this in the DEFERRED section of REQUIREMENTS.md for
  v0.6.0.
- When `EvaluateRequest` gains `source_application` / `destination_application` on
  `AbacContext`, mark them `#[serde(default, skip_serializing_if = "Option::is_none")]`
  for backward-compat with existing v0.4.0/v0.5.0 policy evaluations that do not
  include these fields.

**Phase to address:** Phase for APP-03 (policy evaluation engine extension).

---

## Section 2: Browser Boundary (BRW-01 to BRW-03)

### PITFALL-B1: Chrome Content Analysis SDK Uses Named Pipes, Not HTTP

**Problem:** The Chrome Content Analysis Connector (content_analysis_sdk) communicates
via a Windows named pipe, not HTTP. Chrome connects to a pipe registered under a
well-known name derived from a policy-controlled configuration value. The protocol is
protobuf-over-pipe, not JSON-over-HTTP. If the BRW-01 implementation builds an axum
HTTP endpoint expecting Chrome to POST to it, Chrome will never connect — the browser
only talks to the named pipe agent.

**Why it happens:** The seed (SEED-002) describes "Path B" as building a
`POST /browser/chrome-connector/scan` HTTP endpoint. This description is a
simplification that does not match the actual Content Analysis SDK protocol. The real
SDK uses protobuf messages over a named pipe and requires the agent to be registered
under a policy-controlled registry entry. The dlp-server HTTP stack is not the right
integration point for the SDK path.

There are TWO distinct Chrome integration mechanisms. They are not interchangeable:
- **Content Analysis SDK (named pipe + protobuf):** Chrome Enterprise DLP connector
  that blocks clipboard/upload events synchronously. Requires a native pipe agent,
  protobuf dependency (`prost` crate), and a Chrome enterprise policy to configure
  the pipe name. The SDK C++ sources confirm this transport.
- **Enterprise Connector HTTP endpoint (`OnTextEnteredEnterpriseConnector` policy):**
  Chrome POSTs to an HTTPS URL. This path IS a dlp-server axum route but requires
  TLS and a deployed Chrome policy. This is what SEED-002 "Path B minimum slice" refers to.

**Prevention:**
- Before Phase for BRW-01 begins, a design spike must confirm which of the two Chrome
  integration paths is being implemented. The spike must produce a working prototype
  that Chrome connects to — not just a design document.
- If choosing the SDK path: add `prost` and `prost-build` to the workspace, generate
  Rust types from the Content Analysis SDK `.proto` files, and implement the named
  pipe agent using the same win32 pipe pattern as `dlp-agent/src/ipc/`.
- If choosing the HTTP Enterprise Connector path: the axum handler for the scan
  endpoint must match the request/response schema that Chrome sends. This schema is
  JSON and requires the server to respond within Chrome's internal scan timeout.
  TLS is mandatory — Chrome will not POST to plain HTTP.
- Do not mix the two — they have different client configurations and different
  request/response contracts.

**Phase to address:** Phase for BRW-01 (design decision must precede implementation).
This is the single highest-risk unknown in the browser boundary feature area.

---

### PITFALL-B2: Chrome Blocks Until the Connector Responds — Timeout Causes Tab Hang

**Problem:** When Chrome submits a content scan request (whether via SDK pipe or HTTP
Enterprise Connector), it blocks the paste/upload operation until the connector
responds. If the dlp-server or the named pipe agent is slow or unreachable, the user's
Chrome tab hangs until Chrome's internal timeout fires. At timeout, Chrome typically
allows the operation (fail-open) or fails with an error dialog, depending on the
policy configuration. Either behavior is unacceptable in production: fail-open defeats
DLP; an error dialog every paste is intolerable.

**Why it happens:** The scan request is synchronous from Chrome's perspective.
The DLP connector is on the critical path of every paste and every file upload.

**Prevention:**
- The connector must respond within 2-3 seconds for UX parity with non-DLP users.
  The text classification pipeline (`dlp_common::classify_text`) is already fast, but
  the round-trip through the ABAC policy engine and managed-origins lookup adds
  latency. Benchmark the full path before shipping.
- For the HTTP Enterprise Connector path: the axum handler for the scan endpoint
  must use `tokio::time::timeout` around the policy evaluation call. If evaluation
  exceeds a budget (e.g., 2000ms), respond with ALLOW + audit flag (never hang
  the browser).
- For the SDK named pipe path: the pipe message handler on the agent side must run
  the evaluation in `tokio::task::spawn_blocking` if the ABAC evaluator is sync
  (which it is per STATE.md). Never block the pipe read loop.
- Add a health check that the browser connector endpoint measures latency on startup
  and logs a warning if policy evaluation + managed-origins lookup exceeds 500ms.

**Phase to address:** Phase for BRW-01. Performance budget must be defined in the
phase plan and validated before the phase is closed.

---

### PITFALL-B3: Managed-Origins List Must Follow the Operator-Config-in-DB Pattern

**Problem:** If the managed-origins list is stored in the agent config TOML file
(`C:\ProgramData\DLP\agent-config.toml`) or in env vars, it cannot be hot-reloaded
without a service restart, cannot be managed from the TUI, and violates the established
pattern for operator config (STATE.md 2026-04-13: "DB-backed config as the standard
pattern"). Agents would need to restart to pick up origin list changes, creating a
compliance gap window.

**Why it happens:** The managed-origins list is a new data type that could plausibly
live in agent config (it's used by the agent/connector for enforcement). The correct
location per the codebase's established pattern is the server DB.

**Prevention:**
- New `managed_origins` table in `dlp-server/src/db.rs`. Schema: `id INTEGER PRIMARY KEY`,
  `hostname TEXT NOT NULL UNIQUE`, `description TEXT`, `created_at TEXT`, `updated_at TEXT`.
- JWT-protected `GET/POST/DELETE /admin/managed-origins` routes in `admin_api.rs`,
  following the same pattern as device registry (SEED-003 phase B).
- The connector (whether SDK agent or HTTP handler) fetches the origins list from the
  server on startup and on a configurable refresh interval, storing it in an
  `Arc<RwLock<HashSet<String>>>` — identical to `network_share.rs` pattern in the agent.
- Admin TUI screen for managed-origins management mirrors the AlertConfig / SIEM config
  pattern from previous milestones.

**Phase to address:** Phase for BRW-02 (managed-origins API + TUI). Must be completed
before BRW-01 connector can enforce origin-based block decisions.

---

### PITFALL-B4: Chrome Origin vs. Hostname Matching — Scheme and Port Sensitivity

**Problem:** A managed-origins list entry of `"sharepoint.com"` is expected to match
`https://company.sharepoint.com/sites/Finance`. But Chrome's connector sends the full
origin (`scheme://hostname:port`), not just the hostname. A naive `hostname.contains(entry)`
match will produce false positives (matching `evil-sharepoint.com.attacker.com`) and
false negatives (missing `https://sharepoint.com:443` if the entry stores without port).
The SEED-002 "copy once, paste many" problem is also related: if the source tab origin
is stored at copy time, it must be stored with the same normalization applied to it
as to the managed-origins entries, or the block decision will be inconsistent.

**Why it happens:** Web origin comparison is canonically `scheme + hostname + port`.
Substring matching on arbitrary strings is both insecure and unreliable.

**Prevention:**
- Define an `Origin` newtype that parses and canonicalizes `scheme://hostname:port`
  using a URL parser (the `url` crate, already likely transitive dep via reqwest).
  Store canonicalized origins in the DB, match on exact equality or suffix-match
  on eTLD+1 (registered domain) level using the `publicsuffix` crate.
- The managed-origins list admin UI must validate entries at input time: accept
  `sharepoint.com` (auto-expands to match all subdomains and schemes) OR full origins.
- Define the matching semantics explicitly in REQUIREMENTS.md before writing the
  matching code. "Matches sharepoint.com" should mean: hostname ends with `.sharepoint.com`
  OR equals `sharepoint.com`, any scheme, any port. This must be a unit-tested function.

**Phase to address:** Phase for BRW-02 (origin storage and matching) — design the
matching function before the BRW-01 connector logic references it.

---

## Section 3: USB Device Identity (USB-01 to USB-05)

### PITFALL-U1: SetupDi Enumeration Must Happen in the WM_DEVICECHANGE Callback — Not After

**Problem:** `DBT_DEVICEARRIVAL` is delivered as a `WM_DEVICECHANGE` message. The
`DEV_BROADCAST_DEVICEINTERFACE_W.dbcc_name` field in the `lParam` struct contains the
device instance path (e.g., `\\?\USB#VID_1234&PID_5678#SERIALNUMBER#{GUID}`). This
device instance path is the correct input to `SetupDiOpenDeviceInterfaceW` and
subsequent `SetupDiGetDeviceRegistryPropertyW` calls. If the SetupDi enumeration
is deferred (e.g., spawned as a background task), the device may have been removed
before enumeration completes, and the calls will fail with `ERROR_NO_SUCH_DEVINST`.

**Why it happens:** The USB detection code in `dlp-agent/src/detection/usb.rs` currently
processes `DBT_DEVICEARRIVAL` synchronously in the window procedure. Extending it to
call multiple `SetupDi*` functions is tempting to do asynchronously to keep the message
pump responsive, but the device instance data is most reliably available during the
arrival callback itself.

**Prevention:**
- Call `SetupDiGetDeviceRegistryPropertyW` (for VID, PID, serial, description) inside
  the `DBT_DEVICEARRIVAL` handler, synchronously. The enumeration is fast (microseconds
  per property) and does not block I/O.
- Cache the result: `Arc<RwLock<HashMap<char, DeviceIdentity>>>` keyed by drive letter,
  populated on arrival, cleared on `DBT_DEVICEREMOVECOMPLETE`.
- Extract VID/PID from the Hardware ID string (format: `USB\VID_xxxx&PID_yyyy`) using
  a regex or manual parse. Do NOT call `SetupDiGetDeviceRegistryPropertyW` for VID/PID
  separately — parse them from `SPDRP_HARDWAREID` which contains the full `VID&PID` string.
- The serial number is in the third segment of the device instance path
  (`USB#VID_1234&PID_5678#SERIAL#{GUID}`). Extract it directly from
  `dbcc_name` as a fallback if `SPDRP_FRIENDLYNAME` is empty.

**Phase to address:** Phase for USB-01 (device identity enumeration).

---

### PITFALL-U2: USB Serial Numbers Are Not Guaranteed Unique and Can Be Absent

**Problem:** USB serial numbers are manufacturer-assigned and entirely optional.
Cheap drives (commodity flash drives, no-name USB sticks) frequently report no serial
number. When no serial is available, Windows uses a generated ID based on the USB
controller port and hub position — meaning the same device in a different port will
have a different "serial number". Conversely, some manufacturers ship all drives of
a product line with the same hardcoded serial (e.g., `0001234567890`), making serial
alone useless as a unique identifier. A whitelist keyed on `(VID, PID, serial)` will
have registration failures for no-serial drives and false positives for clone-serial drives.

**Why it happens:** The SEED-003 schema assumes `(vid, pid, serial)` as the primary
key. This is the correct schema for devices that have real serials, but the
application must handle the degenerate cases.

**Prevention:**
- The `device_registry` table MUST allow `serial TEXT` to be empty string or NULL.
  Devices without a serial are identified by `(vid, pid)` alone and treated as a
  weaker identity class (log a warning at registration time: "No serial — this entry
  matches ALL devices with VID/PID xxxx:yyyy").
- Policy enforcement must distinguish: `(vid, pid, serial)` match = high-confidence
  registered device; `(vid, pid)` match with null/empty serial = low-confidence match,
  apply the `trust_tier` but log an audit event with `identity_confidence: "low"`.
- The admin TUI screen for device registration must display the confidence level and
  warn when adding an entry with no serial.
- A device with a duplicated/generic serial (heuristic: serial is all zeros, all `F`s,
  or fewer than 4 characters) should be treated as "no serial" for matching purposes.

**Phase to address:** Phase for USB-01 (identity enumeration) — detect and log the
absent-serial case; Phase for USB-02 (device registry DB) — schema must support it.

---

### PITFALL-U3: USB Thread Shutdown — GetMessageW Blocks Forever

**Problem:** `STATE.md (2026-04-10)` documents: "Skip USB thread join on shutdown —
`GetMessageW` blocks forever; OS reclaims on process exit." The existing implementation
deliberately skips the `thread.join()` in `unregister_usb_notifications`. Any new
code added to the USB thread (SetupDi enumeration, device registry lookup, cache
invalidation) must not introduce new resources that require cleanup on the hot path
before process exit. Specifically: Rust `Drop` impls for any struct held only in the
USB thread may not run if the thread is abandoned.

**Why it happens:** `GetMessageW` in the message loop has no timeout. `PostQuitMessage`
or `PostThreadMessage` to unblock it from another thread is unreliable for
message-only windows, as documented in the existing code comments. The existing
decision to not join is correct and should not be revisited.

**Prevention:**
- The `DeviceIdentity` cache (`Arc<RwLock<HashMap<char, DeviceIdentity>>>`) MUST be
  an `Arc` shared with the rest of the agent (not owned solely by the USB thread).
  When the USB thread is abandoned on shutdown, the `Arc` still has strong references
  from the enforcement layer — no data is lost.
- Do NOT hold `MutexGuard`, `RwLockWriteGuard`, or `RwLockReadGuard` across any code
  that could be blocked waiting for the message pump. The guards will never be released
  if the thread is abandoned.
- Any new `HANDLE` resources opened inside the USB thread (SetupDi device info sets,
  etc.) must be closed before `GetMessageW` is called again, not deferred to a `Drop`
  impl that may never run. Pattern: open handle, use handle, close handle, then re-enter
  the message loop.
- The device arrival handler should complete enumeration, update the cache, and return
  to the message loop within milliseconds. Long-running operations inside the wndproc
  callback will starve the message pump.

**Phase to address:** Phase for USB-01. This constraint must be written into the phase
plan as a design invariant, not left to be discovered during code review.

---

### PITFALL-U4: Read-Only Tier Enforcement at I/O Level Cannot Use file_monitor.rs Alone

**Problem:** The current `file_monitor.rs` uses the `notify` crate to watch filesystem
change events. The `notify` watcher fires AFTER the write succeeds (it is an
observation layer, not an interception layer). For read-only USB enforcement, the write
must be denied BEFORE it succeeds. The existing `should_block_write` check in
`UsbDetector` only blocks based on classification, and the file_monitor detour is the
only write-blocking mechanism. If read-only enforcement is added using the same
post-event pattern, writes to read-only devices will succeed and then be logged —
which is not enforcement, it is auditing.

**Why it happens:** The SEED-003 description says "reuse the existing file_monitor
detour." The existing detour for classification-based blocking works because the
notify watcher is hooked into a write-interception path, not a post-event observer.
But the details of HOW the detour works (kernel-level filter vs. user-mode hook) must
be confirmed before trusting that the same mechanism blocks writes at I/O time.

**Prevention:**
- Before the phase for USB-03 begins, verify with a test: can the current file_monitor
  detour deny a write to a USB drive at the filesystem level, or does it only observe
  after the fact? Check `dlp-agent/src/interception/file_monitor.rs` and the underlying
  `notify` crate's backend on Windows (likely `ReadDirectoryChangesW`, which is
  observation-only).
- If the current detour is observation-only, USB read-only enforcement requires either:
  (a) A Windows filesystem filter driver (`IRP_MJ_WRITE` intercept) — significant new
      engineering, beyond the scope of a single phase.
  (b) Volume shadow / NTFS permissions manipulation at mount time — fragile.
  (c) A user-mode I/O completion port hook on the specific file handle — complex.
- The SEED-003 "trade-off" question (mount-time vs. I/O-time) must be resolved in
  the phase design discussion BEFORE implementation begins. This is the highest
  technical risk item in the USB feature area.
- If a filter driver is out of scope for v0.6.0, consider scoping read-only to
  "deny mount" (prevent Explorer from seeing the drive at all) via a different
  mechanism, or clearly document that the v0.6.0 read-only tier is "audit-only with
  user notification" and enforcement is deferred to a future kernel-mode phase.

**Phase to address:** Phase for USB-03 (read-only enforcement). The enforcement
mechanism decision is a phase-0 design gate; all subsequent USB work depends on it.

---

### PITFALL-U5: User Notification Toast Must Run in User Session, Not Session 0

**Problem:** `dlp-agent` runs as SYSTEM in Windows session 0. Session 0 is isolated
from the interactive desktop. Any Win32 toast, balloon notification, or dialog
created from session 0 will either fail silently or appear on an invisible desktop.
This is the same constraint that drove the decision to run clipboard monitoring in
`dlp-user-ui` (STATE.md 2026-04-10: "Clipboard monitoring in UI process — SYSTEM
session 0 cannot access user clipboard").

**Why it happens:** The SEED-003 Phase E describes adding a `Shell_NotifyIconW` or
`ToastNotificationManager` call. Neither API works in session 0. The agent will
receive the USB block event (it runs the enforcement), but the notification must be
dispatched to the UI process in the user session via the existing IPC infrastructure.

**Prevention:**
- USB block events that need user notification must be sent from `dlp-agent` to
  `dlp-user-ui` via Pipe 2 (`DLPEventAgent2UI`) using the existing `Pipe2AgentMsg::Toast`
  variant, which already has `{ title: String, body: String }` fields — no new IPC
  message type needed for basic notifications.
- If richer USB-specific dialog (showing device identity, policy explanation, "request
  registration" button) is needed, a new `Pipe2AgentMsg` variant can be added, but
  the transport is still Pipe 2.
- The `ToastNotificationManager` vs `Shell_NotifyIconW` decision (SEED-003 design
  question) applies to the `dlp-user-ui` side. The user-ui process is already in the
  user session. The installer question (COM activator registration for modern toast)
  is a Phase E implementation detail, not a blocker for Phase D.
- Unit test: verify that the USB block audit path calls the Pipe 2 notification
  dispatch, not any direct Win32 notification API from within `dlp-agent`.

**Phase to address:** Phase for USB-04 (user notification). Must use existing Pipe 2
infrastructure — do not create a new IPC channel.

---

## Section 4: Cross-Cutting Integration Pitfalls

### PITFALL-X1: AuditEvent New Fields Must Update alert_router.rs Simultaneously

**Problem:** `dlp-common/src/audit.rs` `AuditEvent` will gain new fields for
`source_application`, `destination_application`, and `device` (SEED-001 and SEED-003
respectively). The `alert_router.rs::send_email` function in dlp-server formats audit
events into email alert bodies. If a new field is added to `AuditEvent` without
simultaneously updating `send_email`, the email template will either silently omit
the new field (acceptable but incomplete) or panic if the field is accessed
non-optionally.

**Why it happens:** `AuditEvent` is shared across all crates via `dlp-common`.
`alert_router.rs` accesses specific fields by name. This is an existing pattern
documented in SEED-003 Breadcrumbs: "Per Phase 4 TM-03 forward-compat rule, the PR
adding the field MUST simultaneously update `dlp-server/src/alert_router.rs::send_email`
to redact or include the new field explicitly."

**Prevention:**
- Each PR that adds a field to `AuditEvent` MUST include a corresponding change to
  `alert_router.rs::send_email` in the same commit (not a follow-up PR).
- New optional fields must be `Option<T>` with `#[serde(default)]`. The email template
  should render them with a "N/A" fallback, not `unwrap()`.
- Add a compile-time test (or at minimum a clippy lint) that exhaustively matches
  on all `AuditEvent` fields to catch silent omissions in the alert template.

**Phase to address:** Every phase that modifies `AuditEvent` (APP-05, USB-05).

---

### PITFALL-X2: Policy Engine Sync Evaluator on the Hot Path Cannot Block on Win32 Calls

**Problem:** `PolicyStore::evaluate()` is sync (STATE.md 2026-04-16: "PolicyStore
evaluate() stays sync on hot path"). The new `SourceApplication` and `DestinationApplication`
condition evaluation will need to compare the `AppIdentity` against policy rules.
If condition evaluation calls Win32 APIs (e.g., `WinVerifyTrust`, `GetApplicationUserModelId`)
at evaluation time, it violates the sync/no-block contract of the evaluator and will
introduce unpredictable latency spikes.

**Why it happens:** It is tempting to do "late" identity resolution — resolve app
identity at evaluation time when the policy needs it. But the evaluator is on the
critical path of every file and clipboard operation.

**Prevention:**
- App identity (publisher, signature state, AUMID) must be FULLY resolved and cached
  BEFORE `PolicyStore::evaluate()` is called. The `ClipboardAlert` handler in
  `dlp-agent/src/ipc/pipe3.rs` builds an `AuditEvent` — this is where the
  `AbacContext` (once extended with app identity) must be populated from the already-
  cached `AppIdentity` values.
- The `AbacContext` struct (new for v0.6.0, wrapping the existing `EvaluateRequest`
  or extending it) carries pre-resolved identity. The evaluator only reads struct
  fields — it never calls Win32 APIs.
- Follow the established pattern: classify text in `dlp-user-ui`, send
  `ClipboardAlert` with pre-classified data. The agent evaluator receives pre-resolved
  data. Same principle applies to app identity.

**Phase to address:** Phase for APP-03 (policy evaluation). The `AbacContext` extension
design must be documented in the phase plan before implementation.

---

### PITFALL-X3: DB Schema Changes Without Migration Framework Can Corrupt Existing Data

**Problem:** This codebase uses `ALTER TABLE` in `dlp-server::db::open` for schema
migrations (STATE.md: "DB schema migrations: column adds via ALTER TABLE in
dlp-server::db::open with NOT NULL DEFAULT for backward compat"). New tables for
`device_registry` and `managed_origins` must be created with `CREATE TABLE IF NOT EXISTS`.
However, if a column is added to an existing table (e.g., adding `trust_tier` to a
table that previously lacked it) WITHOUT a `NOT NULL DEFAULT`, existing rows will fail
the constraint check and the server will fail to start after upgrade.

**Why it happens:** The pattern works for simple column additions because all existing
rows get the default. It breaks if: (a) the default is omitted, (b) a NOT NULL
constraint is added to an existing column via ALTER TABLE (SQLite does not support
`ALTER TABLE ... ALTER COLUMN`), (c) a new table has a foreign key to an old table
with incompatible types.

**Prevention:**
- All new tables (`device_registry`, `managed_origins`) use `CREATE TABLE IF NOT EXISTS`
  — safe on both fresh installs and upgrades.
- Any `ALTER TABLE` for existing tables MUST specify `DEFAULT` for NOT NULL columns.
- Do not add NOT NULL constraints to existing nullable columns — this is not supported
  by SQLite's `ALTER TABLE`. If needed, create a new column with the constraint,
  backfill, drop old column (requires table recreation in SQLite — avoid).
- Run the integration test suite (which opens a real SQLite DB) against a pre-existing
  database fixture that contains v0.5.0 schema data, verifying the v0.6.0 `db::open`
  migrates it correctly without errors.

**Phase to address:** Phase for USB-02 (device registry DB) and Phase for BRW-02
(managed origins DB). Each phase's migration SQL must be reviewed before merge.

---

### PITFALL-X4: Two-Crate IPC Message Duplication — Silent Divergence on New Variants

**Problem:** `Pipe3UiMsg` and `Pipe2AgentMsg` are defined in BOTH
`dlp-user-ui/src/ipc/messages.rs` AND in the corresponding agent messages file.
Per the codebase comment: "Since dlp-agent and dlp-user-ui are separate crates, the
message types are duplicated here." When v0.6.0 adds new message variants
(`UsbBlockNotification`, app identity fields on `ClipboardAlert`), both copies must
be updated. Forgetting one copy compiles successfully — the deserialization failure
only occurs at runtime when the new variant is sent.

**Why it happens:** The two-crate architecture prevents a shared IPC types crate
without a dependency cycle. This is an acknowledged structural decision. The risk is
that both copies must be kept in sync manually.

**Prevention:**
- Every PR that adds or modifies a `Pipe2AgentMsg` or `Pipe3UiMsg` variant MUST
  include a search for the other copy (Grep for the struct/enum name in both crates)
  and update both in the same commit.
- Add an integration test that serializes every variant in both copies and asserts
  the JSON output matches. This test will fail at compile time if one copy gains a
  new variant that the other lacks.
- Consider adding a `#[test] mod ipc_sync_check` in `dlp-common` that imports
  the canonical message shape and asserts that the field names and types match
  a hardcoded schema string — a cheap structural synchrony test.

**Phase to address:** Any phase that adds new IPC message variants (APP-01/02, USB-04).

---

## Phase-Specific Warning Matrix

| Phase Topic | Highest-Risk Pitfall | Mitigation Required Before Coding |
|-------------|---------------------|-----------------------------------|
| APP-01: Destination app detection | PITFALL-A2 (UWP), PITFALL-A4 (WinVerifyTrust hang) | Define `AppIdentityKind` enum; run Authenticode in spawn_blocking |
| APP-02: Source app detection | PITFALL-A1 (dead HWND), PITFALL-A5 (Pipe 3 compat) | Synchronous capture at WM_CLIPBOARDUPDATE; all new fields `Option` + `#[serde(default)]` |
| APP-03: Policy evaluation | PITFALL-A3 (Electron collapse), PITFALL-A6 (TOML), PITFALL-X2 (evaluator blocking) | Publisher + path both in condition; evaluator receives pre-resolved identity only |
| APP-04: TUI authoring | PITFALL-A3 | Condition builder must expose publisher vs. path distinction clearly |
| APP-05/06: Audit + anti-spoofing | PITFALL-X1, PITFALL-A4 | alert_router update in same PR; verification cache in place |
| BRW-01: Chrome connector | PITFALL-B1 (wrong protocol), PITFALL-B2 (timeout) | Design spike to confirm HTTP vs. SDK path; timeout budget defined |
| BRW-02: Managed origins | PITFALL-B3 (config location), PITFALL-B4 (origin matching) | DB-backed; URL-parsed origin matching with unit tests |
| USB-01: Device enumeration | PITFALL-U1 (timing), PITFALL-U2 (serial absent), PITFALL-U3 (thread shutdown) | Enumerate in callback; Arc-based cache; no Drop deps in abandoned thread |
| USB-02: Device registry DB | PITFALL-U2, PITFALL-X3 (migration) | Schema allows null serial; `CREATE TABLE IF NOT EXISTS` |
| USB-03: Read-only enforcement | PITFALL-U4 (observation vs. interception) | Confirm file_monitor blocks vs. observes; resolve mount-time vs. I/O-time before coding |
| USB-04: User notification | PITFALL-U5 (session 0) | Dispatch via Pipe 2 Toast; no direct Win32 notification from dlp-agent |
| USB-05/APP-05: Audit enrichment | PITFALL-X1, PITFALL-X4 | alert_router + both IPC copies updated in same commit |

---

## Sources

- Codebase analysis: `dlp-agent/src/detection/usb.rs`, `dlp-user-ui/src/clipboard_monitor.rs`,
  `dlp-user-ui/src/ipc/messages.rs`, `dlp-agent/src/ipc/pipe3.rs`, `dlp-common/src/abac.rs`,
  `dlp-common/src/audit.rs`, `.planning/seeds/SEED-001`, `.planning/seeds/SEED-002`,
  `.planning/seeds/SEED-003`, `.planning/STATE.md`
- [WinVerifyTrust API — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [GetClipboardOwner API — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboardowner)
- [chromium/content_analysis_sdk — confirms protobuf-based named pipe protocol](https://github.com/chromium/content_analysis_sdk)
- [Chrome Enterprise Content Analysis Connector (Broadcom/Symantec)](https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/16-0-1/about-discovering-and-preventing-data-loss-on-endp-v98548126-d294e27/about-monitoring-google-chrome-using-the-chrome-content-analysis-connector-agent-sdk-on-windows-endpoints.html)
- WinVerifyTrust CVE-2013-3900 — confirms `EnableCertPaddingCheck` registry key behavior
- [USB device instance ID serial number handling — Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/1418133/usb-device-identification-serial-string-of-device-instance-id-changes)
