# Phase 25: App Identity Capture in dlp-user-ui - Context

**Gathered:** 2026-04-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Populate `source_application` and `destination_application` in `ClipboardAlert` (currently both `None` in `dlp-user-ui/src/ipc/pipe3.rs:92-93`). Wire in Win32 identity resolution for both source (GetClipboardOwner at copy time) and destination (SetWinEventHook foreground tracking). Run Authenticode verification via WinVerifyTrust in spawn_blocking with a session-lifetime cache. All types are already defined in dlp-common — this phase wires them in.

Requirements in scope: APP-01, APP-02, APP-05, APP-06
</domain>

<decisions>
## Implementation Decisions

### Destination Identity Capture (APP-01)
- **D-01:** Destination identity via `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` — maintains a single previous-foreground HWND slot, updated on every focus change, cleared after each `WM_CLIPBOARDUPDATE` is processed.
- **D-02:** At `WM_CLIPBOARDUPDATE` time: destination = the slot value (the window that had focus before the source app). If source and destination resolve to the same process (intra-app copy — user never switched windows), destination is populated with the same `AppIdentity` as source, not `None`. Intra-app copy is explicitly modeled.

### Source Identity Capture (APP-02)
- **D-03:** Source identity via `GetClipboardOwner` called synchronously inside the `WM_CLIPBOARDUPDATE` handler (before returning to the message loop), per requirements. HWND → `GetWindowThreadProcessId` → `QueryFullProcessImageNameW`.

### Authenticode Cache (APP-06)
- **D-04:** Cache stored as a `OnceLock<Mutex<HashMap<String, (String, SignatureState)>>>` process-wide static — same pattern as `REGISTRY_CACHE` in Phase 24. Keyed by image path (absolute). No Arc threading needed; accessible from any `spawn_blocking` call.
- **D-05:** Unbounded `HashMap` — no eviction policy. In practice ≤200 unique executable paths touch the clipboard per session; unbounded is safe.
- **D-06:** No TTL — `WinVerifyTrust` runs once per unique path per process start. Certificate revocation propagation takes hours minimum; mid-session re-verification deferred to a future hardening phase.

### AppTrustTier Assignment (APP-06)
- **D-07:** Trust tier derived purely from `SignatureState`:
  - `SignatureState::Valid` → `AppTrustTier::Trusted`
  - `SignatureState::Invalid` / `NotSigned` → `AppTrustTier::Untrusted`
  - `SignatureState::Unknown` → `AppTrustTier::Unknown`
  Publisher allowlist (admin-managed trusted publishers) is deferred to Phase 28 (Admin TUI Screens).

### Identity Resolution Failures
- **D-08:** Two distinct failure cases, handled differently:
  - `GetClipboardOwner` returns NULL → `source_application = None` (clipboard written without an owner — legitimate; some apps don't set owner)
  - Owner HWND found but `QueryFullProcessImageNameW` fails (elevated process, process exited before query) → `Some(AppIdentity { image_path: String::new(), publisher: String::new(), trust_tier: AppTrustTier::Unknown, signature_state: SignatureState::Unknown })`
  - Destination slot empty (no previous foreground window) → `destination_application = None`
  - Destination HWND found but path resolution fails → `Some(AppIdentity)` with all-Unknown fields
  This distinguishes "no owner" from "resolution attempted but failed" so the policy evaluator can act on each case.

### Claude's Discretion
- Exact `SetWinEventHook` registration and teardown lifecycle (thread vs process scope)
- `spawn_blocking` task structure for the WinVerifyTrust → cache-lookup → AppIdentity construction pipeline
- Whether the foreground slot is an `AtomicUsize` (HWND as usize) or `Mutex<Option<HWND>>`

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements
- `.planning/REQUIREMENTS.md` — APP-01, APP-02, APP-05, APP-06 definitions
- `.planning/ROADMAP.md` §Phase 25 — success criteria (5 items), dependency on Phase 22

### Existing Types (already implemented — do not redefine)
- `dlp-common/src/endpoint.rs` — `AppIdentity`, `AppTrustTier`, `SignatureState` structs
- `dlp-common/src/abac.rs` — `AbacContext` with `source_application` / `destination_application` fields
- `dlp-common/src/audit.rs` — `AuditEvent` with `source_application` / `destination_application` fields

### Integration Points (files that need modification)
- `dlp-user-ui/src/clipboard_monitor.rs` — `handle_clipboard_change` and `WM_CLIPBOARDUPDATE` message loop
- `dlp-user-ui/src/ipc/pipe3.rs` — `ClipboardAlert` construction (source/dest currently `None`)
- `dlp-user-ui/src/ipc/messages.rs` — `Pipe3UiMsg::ClipboardAlert` shape (fields already exist)

### Patterns to Follow
- `dlp-agent/src/device_registry.rs` — `REGISTRY_CACHE` OnceLock static pattern (D-04)
- `dlp-server/src/admin_api.rs` — `spawn_blocking` usage pattern for blocking Win32 work

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AppIdentity`, `AppTrustTier`, `SignatureState` in `dlp-common::endpoint` — fully defined, serde-ready, no changes needed
- `Pipe3UiMsg::ClipboardAlert` in `dlp-user-ui/src/ipc/messages.rs` — already has `source_application: Option<AppIdentity>` and `destination_application: Option<AppIdentity>` fields at lines 102–104
- `REGISTRY_CACHE` OnceLock pattern in `dlp-agent/src/device_registry.rs` — direct analog for the Authenticode cache

### Established Patterns
- `spawn_blocking` for CPU/IO-bound work off the Tokio reactor — used throughout `dlp-server/src/admin_api.rs`
- `OnceLock<Mutex<T>>` for process-wide shared state — Phase 24 pattern
- Default-deny on unknown state (`AppTrustTier::Unknown` treated as untrusted by evaluator)

### Integration Points
- `dlp-user-ui/src/clipboard_monitor.rs:124` — `WM_CLIPBOARDUPDATE` branch; `GetClipboardOwner` call goes here (synchronous, before `handle_clipboard_change`)
- `dlp-user-ui/src/ipc/pipe3.rs:92-93` — `source_application: None, destination_application: None` → replace with resolved identities
- `SetWinEventHook` registration goes in the clipboard monitor setup (same thread that owns the hidden HWND)

</code_context>

<specifics>
## Specific Ideas

- Intra-app copy modeled explicitly (destination = source identity, not None) — allows policies like "block copy-paste within Word if content is T3+"
- `WinVerifyTrust` cache keyed by absolute image path — renaming a signed binary produces a new cache entry (different path), so the renamed binary is verified fresh (satisfies APP-06 success criterion 5)

</specifics>

<deferred>
## Deferred Ideas

- Publisher allowlist (admin-managed trusted publishers list) — deferred to Phase 28
- Right-click paste detection — WH_KEYBOARD_LL hook for Ctrl+V; out of scope for v0.6.0
- TTL-based Authenticode cache invalidation for revoked certificates — deferred to future hardening phase
- APP-07: UWP app identity via AUMID — already deferred in REQUIREMENTS.md

</deferred>

---

*Phase: 25-app-identity-capture-in-dlp-user-ui*
*Context gathered: 2026-04-22*
