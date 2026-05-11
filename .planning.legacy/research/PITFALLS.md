# Pitfalls Research: UWP AUMID, OLE Drag-and-Drop, and Browser Origin Clipboard Policies

**Domain:** Windows Endpoint DLP — Adding UWP App Identity (AUMID), OLE Drag-and-Drop Enforcement, and Browser Origin-Aware Clipboard Policies to an existing Enterprise DLP system
**Researched:** 2026-05-06
**Confidence:** HIGH (existing codebase knowledge HIGH; Win32 OLE/UWP API specifics MEDIUM-HIGH; Chrome Enterprise Connector protocol HIGH)

---

## Critical Pitfalls

Mistakes that cause silent security bypasses, audit gaps, or integration failures when adding these features to the existing v0.7.1 system.

---

### Pitfall 1: UWP Apps Resolve as "Unknown" Because AUMID Path Is Not Checked

**What goes wrong:**
UWP apps (Calculator, Mail, Edge UWP, Store apps) run as `WWAHost.exe`, `ApplicationFrameHost.exe`, or `WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe`. The existing `hwnd_to_image_path` + `QueryFullProcessImageNameW` path resolves these to the host executable path, not the actual app identity. Policies targeting "Microsoft.Windows.Photos" or "Microsoft.MicrosoftEdge.Stable" never match. UWP apps become invisible to ABAC enforcement — a complete bypass for app-aware policies.

**Why it happens:**
- The existing `app_identity.rs` only calls `QueryFullProcessImageNameW` on the process handle.
- UWP apps run inside `ApplicationFrameHost.exe` (the window frame) or `WWAHost.exe` (web apps).
- The real app identity is the AUMID (Application User Model ID), e.g. `Microsoft.Windows.Photos_8wekyb3d8bbwe!App`.
- AUMID resolution requires `IShellItem::GetApplicationUserModelId` or `GetApplicationUserModelIdFromWindow`, not process image path queries.
- The `AppIdentity` struct has no `aumid` field — even if we resolve it, there is nowhere to store it.

**Consequences:**
- All UWP apps are classified as "Unknown" publisher / "Untrusted" tier.
- Policies allowing "Microsoft Office" apps miss Edge (UWP), Mail, Calendar, and Store-installed enterprise apps.
- Policies blocking "untrusted" apps inadvertently block legitimate UWP workflows.
- Audit events show `image_path = C:\Windows\System32\ApplicationFrameHost.exe` instead of the actual app.

**Prevention:**
- **Add `aumid: Option<String>` to `AppIdentity`** (dlp-common `endpoint.rs`). This is a schema change that ripples through serde, ABAC evaluation, admin CLI conditions builder, and audit events.
- **Implement AUMID resolution as a fallback:** In `resolve_app_identity`, after `hwnd_to_image_path` returns a path containing `ApplicationFrameHost.exe` or `WWAHost.exe`, call `GetApplicationUserModelIdFromWindow(hwnd)` (Win32 API, requires Windows 8+).
- **Add `AppField::Aumid` to the ABAC `AppField` enum** so policies can target AUMID directly.
- **Update the admin CLI conditions builder** to include AUMID as a selectable field for SourceApplication/DestinationApplication conditions.
- **Cache AUMID lookups** the same way Authenticode results are cached — AUMID resolution involves COM (`IShellItem`) and is slower than a simple path query.

**Detection:**
- UAT: Open Windows Calculator, copy text, paste into Notepad. Verify `source_application.aumid` = `Microsoft.WindowsCalculator_8wekyb3d8bbwe!App` (or similar) in the audit event.
- UAT: Policy `source_application.aumid eq "Microsoft.Windows.Photos_8wekyb3d8bbwe!App"` → DENY. Copy from Photos, paste into Word → verify block.
- UAT: Policy `destination_application.publisher eq "Microsoft Corporation"` → ALLOW. Paste into Calculator (UWP) → verify allow (because AUMID resolves to Microsoft-published app).

**Phase to address:** Phase 39 (UWP App Identity via AUMID).

---

### Pitfall 2: Adding AUMID to AppIdentity Breaks Backward Compatibility

**What goes wrong:**
`AppIdentity` is serialized in `ClipboardAlert` Pipe 3 messages, `EvaluateRequest` JSON, `AuditEvent` JSON, and SQLite policy conditions. Adding an `aumid` field without careful serde handling causes:
1. Old agents (pre-v0.8.0) deserializing new `ClipboardAlert` messages fail because the JSON contains an unknown `aumid` key.
2. Old dlp-server instances receiving `EvaluateRequest` with `aumid` fail to deserialize.
3. Policy conditions stored in SQLite with `aumid` fields cannot be read by old admin CLI versions.

**Why it happens:**
- `AppIdentity` does not use `#[serde(default)]` at the struct level — adding a field breaks deserialization of JSON missing that field.
- The `AppField` enum is serialized as a string tag (`"publisher"`, `"image_path"`, `"trust_tier"`). Adding `"aumid"` is safe for forward compat but old evaluators do not know how to match it.
- The admin CLI `build_condition` function has a fixed match on `AppField` variants. Adding `Aumid` without updating all match arms causes compile errors or runtime panics.

**Consequences:**
- Mixed-version deployments (rolling upgrade) break during the v0.8.0 rollout.
- Audit events from new agents cannot be ingested by old servers.
- Policies authored on new admin CLI cannot be evaluated by old policy engines.

**Prevention:**
- **Add `#[serde(default)]` to `AppIdentity`** before adding the `aumid` field. This ensures old JSON without `aumid` deserializes safely.
- **Add `aumid: Option<String>` (not `String`)** so missing = `None`, which serializes as `null` or is skipped with `skip_serializing_if`.
- **Update `AppField` enum** with `Aumid` variant. In the policy evaluator (`app_identity_matches`), add the new arm. Old evaluators without the arm will fail to compile — this is a compile-time safety check, not a runtime bug.
- **Update ALL match sites on `AppField`:**
  - `dlp-server/src/policy_store.rs` — `app_identity_matches` function
  - `dlp-admin-cli/src/screens/dispatch.rs` — `operators_for`, `value_count_for`, `build_condition`, `condition_to_edit_state`, `condition_display`
  - `dlp-common/src/abac.rs` — `AppField` serde tests
- **Bump the wire protocol version** or add a capability flag: new agents advertise "supports_aumid" in their heartbeat; old servers ignore it.

**Detection:**
- Integration test: serialize `AppIdentity` with `aumid`, deserialize with old struct definition (simulate via `serde_json::from_str` on a string missing `aumid`).
- Integration test: old `EvaluateRequest` JSON (no `aumid` in `source_application`) deserializes into new struct.
- CI build gate: ensure all `match` expressions on `AppField` are exhaustive (Rust compiler enforces this).

**Phase to address:** Phase 39 (UWP App Identity) — must be designed in, not retrofitted.

---

### Pitfall 3: OLE Drag-and-Drop Interception Misses the Actual Source App

**What goes wrong:**
OLE drag-and-drop uses `IDataObject` to transfer data between applications. The source app is the window that initiated the drag (`DoDragDrop` caller). The existing clipboard monitor only watches `WM_CLIPBOARDUPDATE` — it never sees drag-and-drop operations. Even if we add a drag-drop hook, the source identity captured via `GetClipboardOwner` is wrong: drag-and-drop source is NOT the clipboard owner. The destination is the window under the cursor at drop time, which may not be the foreground window.

**Why it happens:**
- Drag-and-drop is a completely different Win32 subsystem from clipboard.
- `WM_CLIPBOARDUPDATE` does not fire for drag-and-drop.
- `GetClipboardOwner` returns the last app that called `SetClipboardData` — unrelated to the drag source.
- The drop target window is determined by `IDropTarget::Drop` — the window under the cursor, not the foreground window.
- Existing `FOREGROUND_SLOT` (WinEvent hook) captures foreground changes, but during a drag operation the foreground window does NOT change — the user drags over multiple windows without clicking.

**Consequences:**
- Drag-and-drop exfiltration is completely invisible to the DLP.
- A user can drag a T4 file from Explorer to a browser upload zone, or from Word to Slack, with zero audit event.
- Policies blocking paste into "untrusted" apps are bypassed via drag-and-drop.

**Prevention:**
- **Implement a global `IDropTarget` hook** (COM interface) registered via `RegisterDragDrop` on a message-only window. This is the standard Windows shell extension pattern for intercepting drag-and-drop.
- **Capture source app at drag-start time:** Use `GetAsyncKeyState(VK_LBUTTON)` + `GetCursorPos` + `WindowFromPoint` to identify the source window when the drag begins. Cache this HWND for the duration of the drag operation.
- **Capture destination app at drop time:** In `IDropTarget::Drop`, use `WindowFromPoint` on the current cursor position to find the drop-target window. Resolve to `AppIdentity` via the existing `resolve_app_identity` path.
- **Send a new `DragDropAlert` Pipe 3 message** (do not reuse `ClipboardAlert` — the semantics and wire format are different). Add `DragDropAlert` to `Pipe3UiMsg` in `dlp-user-ui/src/ipc/messages.rs`.
- **Do NOT rely on `GetClipboardOwner` or `FOREGROUND_SLOT` for drag-and-drop** — they are fundamentally wrong for this use case.

**Detection:**
- UAT: Drag text from Word to Notepad. Verify `DragDropAlert` is sent with correct source (Word) and destination (Notepad) identities.
- UAT: Drag a file from Explorer to Chrome. Verify block event if policy denies Explorer->Chrome.
- UAT: Drag within the same app (Word -> Word). Verify intra-app copy logic (same PID = allow) works for drag-drop.

**Phase to address:** Phase 40 (Drag-and-drop enforcement).

---

### Pitfall 4: Drag-and-Drop `IDropTarget` Hook Interferes with System DnD

**What goes wrong:**
Registering a global `IDropTarget` hook on the desktop or a message-only window can interfere with normal drag-and-drop operations. If the hook's `IDropTarget::Drop` implementation blocks (e.g., waits for ABAC evaluation over a network round-trip), the user's drag operation hangs for seconds. If the hook crashes, the entire desktop drag-and-drop subsystem becomes unresponsive.

**Why it happens:**
- `RegisterDragDrop` installs a COM interface that the OLE runtime calls synchronously during the drop.
- The `IDropTarget::Drop` method runs on the thread that called `DoDragDrop` in the source app — blocking here blocks the source app.
- If our hook returns `E_FAIL` or panics, the OLE runtime may revoke the drop target and refuse future drag operations.
- The existing DLP UI process (`dlp-user-ui`) is not designed to host COM drop targets — it runs an `iced` GUI event loop that may conflict with OLE message pumping.

**Consequences:**
- User experience degradation: drag-and-drop feels "sticky" or hangs.
- System instability: Explorer drag operations fail after DLP UI crash.
- False positives: blocking legitimate drag operations because the evaluation timed out.

**Prevention:**
- **Use `RevokeDragDrop` + `RegisterDragDrop` per-session**, not globally. Register on a message-only window in the `dlp-user-ui` process, scoped to the user session.
- **Make `IDropTarget::Drop` non-blocking:** Immediately accept the drop (`DROPEFFECT_COPY`), spawn a background thread to evaluate the policy, and show a toast notification if the policy denies. Do NOT block the OLE thread waiting for evaluation.
- **Implement `IDropTarget` with `Sync` + `Send` safety:** The COM interface must be thread-safe. Use `Arc<Mutex<...>>` for shared state. Document all `unsafe` COM vtable construction.
- **Graceful degradation:** If `RegisterDragDrop` fails (e.g., another hook is already registered), log a warning and continue without drag-and-drop enforcement. Do not crash.
- **Test with high-frequency DnD:** Drag 50 files rapidly from Explorer to Desktop. Verify no hangs, no memory leaks, no COM reference count leaks.

**Detection:**
- UAT: Drag a 100MB file from Explorer to Desktop. Verify the drop completes within 200ms (no perceptible delay from DLP hook).
- UAT: Kill `dlp-user-ui` during an active drag. Verify Explorer drag-and-drop continues to work.
- UAT: Run for 1 hour with frequent drag operations. Verify no GDI handle leaks (check in Process Explorer).

**Phase to address:** Phase 40 (Drag-and-drop enforcement).

---

### Pitfall 5: Chrome Enterprise Connector Only Sees Source Origin, Not Destination

**What goes wrong:**
The current Chrome handler (`dlp-agent/src/chrome/handler.rs`) only inspects `request_data.url` — this is the **source** URL (where the content came from). For clipboard paste events, Chrome sends the source origin but NOT the destination origin (the tab where the paste occurred). The handler blocks based on "managed source origin" alone, which is wrong: pasting from a managed origin into another managed origin should be ALLOWED. The current logic blocks ALL pastes from managed origins, regardless of destination.

**Why it happens:**
- The Chrome Content Analysis SDK's `ContentMetaData` only includes `url` (source page URL), not a separate destination URL.
- The `reason` field distinguishes `CLIPBOARD_PASTE` from `DRAG_AND_DROP`, but neither reason carries destination origin information in the current protobuf schema.
- The existing `dispatch_request` logic: `if source_origin.is_managed() -> BLOCK`. This is correct for "paste from managed to unmanaged" but incorrect for "paste from managed to managed."
- There is no destination origin in the `ContentAnalysisRequest` — the handler cannot make a source/destination boundary decision.

**Consequences:**
- Users cannot paste from SharePoint into Outlook Web (both managed) — false positive.
- The policy is too blunt: it blocks all managed-origin clipboard operations, not just cross-boundary ones.
- Admin confusion: "why is SharePoint -> Outlook Web blocked?"

**Prevention:**
- **Upgrade the Chrome Content Analysis protocol** to include destination origin. This requires:
  1. Extending the protobuf schema (`content_analysis.proto`) with a `destination_url` field in `ContentMetaData`.
  2. Updating the Chrome Enterprise policy to send destination URL (may require Chrome 125+ or a custom connector configuration).
  3. Updating the handler to compare `source_origin` AND `destination_origin` against the managed-origins cache.
- **Implement the correct decision logic:**
  ```
  if source_is_managed AND NOT destination_is_managed -> BLOCK
  if source_is_managed AND destination_is_managed -> ALLOW
  if NOT source_is_managed -> ALLOW (no boundary crossing)
  ```
- **If destination origin is unavailable** (older Chrome versions), fall back to the current behavior but log a warning: "destination origin unavailable — blocking all managed-origin pastes."
- **Document the Chrome version requirement** in deployment guides.

**Detection:**
- UAT: Copy from SharePoint (managed), paste into Outlook Web (managed). Verify ALLOW.
- UAT: Copy from SharePoint (managed), paste into ChatGPT (unmanaged). Verify BLOCK.
- UAT: Copy from example.com (unmanaged), paste into ChatGPT. Verify ALLOW.
- Check Chrome version in UAT environment — document minimum version for destination-origin support.

**Phase to address:** Phase 41 (Browser origin-aware clipboard policies).

---

### Pitfall 6: Browser Origin Policy Bypass via Subdomain Spoofing

**What goes wrong:**
The current `to_origin` function normalizes URLs to `scheme://host` but does not handle subdomain wildcards. An admin adds `https://company.sharepoint.com` as a managed origin. An attacker registers `https://company-sharepoint.com` (hyphen instead of dot) or `https://company.sharepoint.com.evil.com` (subdomain takeover). The `to_origin` function strips path but does not validate domain boundaries, so `company-sharepoint.com` is treated as a different origin (correctly), but `sharepoint.com.evil.com` also strips to `sharepoint.com.evil.com` which does not match. However, if the admin adds `https://sharepoint.com` (without `company.`), then `evil-sharepoint.com` does not match but `sharepoint.com.evil.com` still doesn't match either. The real risk is: admin adds `https://sharepoint.com` and `https://sub.sharepoint.com` is also managed (correct), but `https://sharepoint.com.evil.com` is NOT managed (correct). The bypass is more subtle: `to_origin` does not canonicalize punycode (`xn--` domains) or IDN homographs.

**Why it happens:**
- `to_origin` is a simple string split on `://` and `/`. It does not use a proper URL parser.
- No wildcard or suffix matching: `https://*.sharepoint.com` is not supported.
- No IDN/punycode normalization: `https://sharepoint.com` and `https://xn--sharepoint-xyz.com` (homograph) are treated as different origins.
- The `ManagedOriginsCache` uses exact string matching (`HashSet<String>::contains`).

**Consequences:**
- Admin must enumerate every subdomain individually (`a.sharepoint.com`, `b.sharepoint.com`, ...).
- IDN homograph attacks can spoof managed origins (low probability in enterprise, but possible).
- Subdomain-based SaaS (e.g., `company.slack.com`, `team.atlassian.net`) requires per-tenant entries.

**Prevention:**
- **Support wildcard suffix matching in `ManagedOriginsCache`:**
  - Exact match: `https://sharepoint.com`
  - Wildcard suffix: `*.sharepoint.com` (matches `a.sharepoint.com`, `b.sharepoint.com`)
  - Store two `HashSet`s: one for exact origins, one for wildcard suffixes.
  - At lookup time: check exact first, then check if any wildcard suffix matches the host.
- **Use `url::Url` crate for parsing** instead of manual string splitting. This handles punycode, ports, and edge cases correctly.
- **Normalize to punycode** before matching: `Url::host_str()` returns the ASCII punycode form.
- **Validate admin input** in the admin API: reject origins without scheme, reject origins with path components, warn on wildcard usage.

**Detection:**
- UAT: Add `*.sharepoint.com` to managed origins. Verify `https://company.sharepoint.com` matches.
- UAT: Verify `https://evil-sharepoint.com` does NOT match `*.sharepoint.com`.
- UAT: Verify `https://sharepoint.com.evil.com` does NOT match `*.sharepoint.com`.
- Unit test: `to_origin("https://xn--sharepoint-xyz.com")` returns normalized punycode form.

**Phase to address:** Phase 41 (Browser origin-aware clipboard policies).

---

### Pitfall 7: Audit Event Schema Gaps for New Features

**What goes wrong:**
The v0.7.1 audit schema (AUDIT-05) guarantees non-null `source_application` and `destination_application` fields by replacing `None` with `AGENT-UNKNOWN` at emission time. When drag-and-drop and browser origin policies are added, new fields (`drag_drop_source`, `drag_drop_destination`, `browser_source_origin`, `browser_destination_origin`) may be introduced. If these fields are optional (`Option<T>`) and not backfilled with sentinels, the AUDIT-05 guarantee is broken for the new event types.

**Why it happens:**
- `AuditEvent` uses `#[serde(skip_serializing_if = "Option::is_none")]` for most optional fields.
- AUDIT-05 specifically requires `source_application` and `destination_application` to ALWAYS be serialized (even as `null`) so downstream SIEM parsers can rely on their presence.
- New fields for drag-drop and browser origins may follow the same pattern (optional + skip) without considering the AUDIT-05 contract.
- The `emit_chrome_block_audit` function in `handler.rs` already sets `source_origin` and `destination_origin` — but `destination_origin` is always `None` today (Pitfall 5).

**Consequences:**
- SIEM parsers that expect `source_application` to always be present break on drag-drop events where the field is missing.
- Compliance auditors see inconsistent schema across event types.
- Downstream analytics (Splunk/ELK dashboards) fail to correlate events because fields are sometimes absent.

**Prevention:**
- **Follow the AUDIT-05 pattern for ALL new identity fields:**
  - Always serialize `source_application` and `destination_application` (even as `null` or `AGENT-UNKNOWN`).
  - For drag-drop: add `drag_drop_source_app` and `drag_drop_dest_app` as `Option<AppIdentity>` with the same sentinel guarantee.
  - For browser: `source_origin` and `destination_origin` already exist — ensure they are always serialized (remove `skip_serializing_if` or add a sentinel).
- **Update the `AuditEvent` builder pattern** to enforce sentinel population at compile time. Consider a `finalize()` method that replaces all `None` app identity fields with `agent_unknown_app()`.
- **Update SIEM schema documentation** to include new fields.

**Detection:**
- Unit test: serialize an `AuditEvent` for drag-drop with no app identities. Verify `source_application: null` and `destination_application: null` are present in JSON.
- Unit test: serialize a Chrome block event. Verify `source_origin` and `destination_origin` keys are present (even if `null`).
- Integration test: ingest all event types into a test Splunk HEC endpoint. Verify no parsing errors.

**Phase to address:** Phase 42 (Audit enrichment — close gaps in app identity fields across all interception paths).

---

### Pitfall 8: Policy Evaluator Does Not Know How to Match AUMID

**What goes wrong:**
After adding `AppField::Aumid` to the `AppField` enum, the policy evaluator (`dlp-server/src/policy_store.rs`, `app_identity_matches` function) must be updated to handle the new field. If the match arm for `AppField::Aumid` is missing, the Rust compiler will catch this at compile time (exhaustive match check). However, if the evaluator is updated but the admin CLI is not, admins can author AUMID-based policies that the server evaluates correctly but the CLI cannot display or edit.

**Why it happens:**
- `app_identity_matches` in `policy_store.rs` has a `match field` block with arms for `Publisher`, `ImagePath`, and `TrustTier`.
- Adding `Aumid` without updating all arms causes a compile error — good.
- But the admin CLI `condition_display` function has a separate `match field` block that may not be exhaustive if written with a catch-all `_ =>` arm.
- The `build_condition` function in the admin CLI constructs `PolicyCondition` values — adding `Aumid` requires a new value input path (text input, like Publisher/ImagePath).

**Consequences:**
- Admin CLI crashes or displays malformed conditions when viewing AUMID-based policies.
- Policies authored via API (bypassing CLI) work correctly, creating a CLI/API capability gap.
- Users cannot edit AUMID conditions in the TUI.

**Prevention:**
- **Update ALL `AppField` match sites simultaneously:**
  1. `dlp-server/src/policy_store.rs` — `app_identity_matches` (add `AppField::Aumid` arm with `eq`/`ne`/`contains` support)
  2. `dlp-admin-cli/src/screens/dispatch.rs` — `operators_for` (AUMID supports `eq`/`ne`/`contains` like ImagePath)
  3. `dlp-admin-cli/src/screens/dispatch.rs` — `value_count_for` (AUMID = 0, free-text input)
  4. `dlp-admin-cli/src/screens/dispatch.rs` — `build_condition` (AUMID uses buffer text input)
  5. `dlp-admin-cli/src/screens/dispatch.rs` — `condition_to_edit_state` (AUMID round-trip)
  6. `dlp-admin-cli/src/screens/dispatch.rs` — `condition_display` (AUMID display string)
  7. `dlp-common/src/abac.rs` — `AppField` serde tests
- **Use a compile-time checklist** (comment block in `abac.rs` next to `AppField`) listing every file that must be updated when a new field is added.
- **Add integration tests** that create, serialize, display, and evaluate a policy with each `AppField` variant.

**Detection:**
- CI build: all crates compile with the new `AppField` variant.
- Unit test: `app_identity_matches` with `AppField::Aumid` returns correct result.
- Unit test: `condition_display` for AUMID condition produces expected string.
- UAT: Create AUMID condition in admin CLI, save policy, verify it evaluates correctly.

**Phase to address:** Phase 39 (UWP App Identity) — the schema change must be coordinated across all crates.

---

### Pitfall 9: Drag-and-Drop and Clipboard Events Double-Count or Collide

**What goes wrong:**
Some applications implement "copy on drag start" — when the user starts dragging, the app copies the data to the clipboard as a side effect. This triggers both a `WM_CLIPBOARDUPDATE` (clipboard monitor) and later an `IDropTarget::Drop` (drag-drop monitor). The DLP emits two alerts for the same user action: one clipboard alert and one drag-drop alert. The audit log shows duplicate events, and the user sees two toast notifications.

**Why it happens:**
- Explorer copies file paths to the clipboard when dragging files.
- Word and Excel may copy selected text to the clipboard on drag-start for internal use.
- The clipboard monitor and drag-drop monitor run independently with no coordination.
- There is no deduplication key or session ID shared between the two paths.

**Consequences:**
- Duplicate audit events inflate SIEM ingestion costs.
- Users see double notifications and perceive the DLP as buggy.
- Policy decisions may differ between the two paths (e.g., clipboard allows but drag-drop blocks), causing inconsistent UX.

**Prevention:**
- **Implement a short-lived deduplication cache in `dlp-user-ui`:**
  - Key: hash of `(content_hash, source_pid, dest_pid, timestamp_bucket_5s)`.
  - Value: `EventType` (Clipboard or DragDrop) and timestamp.
  - If a second event arrives within 5 seconds with the same key, suppress it.
- **Prefer drag-drop over clipboard for drag operations:** If the drag-drop monitor detects an operation, suppress the clipboard alert for the next 2 seconds (the clipboard copy is an implementation detail, not the user's intent).
- **Do NOT deduplicate across different source/dest pairs:** Copy from Word to Excel (clipboard) and drag from Word to Notepad (drag-drop) are different actions — both should be logged.
- **Add an `event_channel` field to `AuditEvent`** (`"clipboard"` | `"dragdrop"` | `"chrome"` | `"file"`) so downstream analytics can filter duplicates if deduplication fails.

**Detection:**
- UAT: Drag a file from Explorer to Desktop. Verify exactly ONE audit event (drag-drop, not clipboard).
- UAT: Copy text in Word (Ctrl+C), then paste into Excel. Verify exactly ONE clipboard event.
- UAT: Drag text from Word to Excel. Verify exactly ONE drag-drop event and NO clipboard event.

**Phase to address:** Phase 40 (Drag-and-drop enforcement) and Phase 42 (Audit enrichment).

---

### Pitfall 10: Chrome Handler Blocks Non-Clipboard Requests

**What goes wrong:**
The Chrome Content Analysis SDK sends requests for many reasons: `CLIPBOARD_PASTE`, `DRAG_AND_DROP`, `FILE_PICKER_DIALOG`, `PRINT_PREVIEW_PRINT`, `NORMAL_DOWNLOAD`, `SAVE_AS_DOWNLOAD`. The current handler only checks `reason == Some(1)` (CLIPBOARD_PASTE) and allows everything else. If a future Chrome policy sends `DRAG_AND_DROP` (reason = 2) or `FILE_PICKER_DIALOG` (reason = 3), the handler allows them unconditionally — a bypass for browser-based file exfiltration.

**Why it happens:**
- `dispatch_request` has an early return: `if !is_clipboard { response.results.push(make_result_allow()); return response; }`.
- The intention was to scope v0.6.0 to clipboard only, but this creates a known bypass.
- Chrome's `DRAG_AND_DROP` reason fires when a user drags a file from the browser to the desktop — exactly the exfiltration path the DLP should block.
- The `FILE_PICKER_DIALOG` reason fires on "Save As" — another exfiltration path.

**Consequences:**
- Browser drag-and-drop file exfiltration bypasses the DLP entirely.
- "Save As" from a managed origin to an unregistered disk is not blocked.
- The bypass is silent — no audit event, no user notification.

**Prevention:**
- **Extend the Chrome handler to process ALL reasons**, not just clipboard:
  - `CLIPBOARD_PASTE` (1): existing logic (source/destination origin check).
  - `DRAG_AND_DROP` (2): treat as drag-drop event — resolve source/destination origins, apply managed-origins boundary policy.
  - `FILE_PICKER_DIALOG` (3): treat as file save — check destination path against disk allowlist (reuse Phase 36 logic).
  - `PRINT_PREVIEW_PRINT` (4) / `SYSTEM_DIALOG_PRINT` (5): treat as print operation — apply print policy (future phase, but at least log/audit).
  - `NORMAL_DOWNLOAD` (6) / `SAVE_AS_DOWNLOAD` (7): treat as file write — check destination against disk allowlist.
- **Add a `reason` field to the Chrome audit event** so admins can see which Chrome operation was blocked.
- **Default-deny for unknown reasons:** If Chrome adds a new reason in a future update, the handler should block it and log: "Unknown Chrome reason N — default deny."

**Detection:**
- UAT: Drag an image from SharePoint to Desktop. Verify block event (if policy applies).
- UAT: "Save As" a file from SharePoint to an unregistered USB disk. Verify block event.
- UAT: Print a document from a managed origin. Verify audit event (even if allowed).

**Phase to address:** Phase 41 (Browser origin-aware clipboard policies) — extend the existing Chrome handler, not just add destination origin.

---

## Moderate Pitfalls

### Pitfall 11: UWP AUMID Resolution Fails for Non-Packaged Apps

**What goes wrong:**
Not all apps that look like UWP apps are actually packaged. Some are "Desktop Bridge" apps (Win32 apps packaged as MSIX) or "unpackaged" Win32 apps. Calling `GetApplicationUserModelIdFromWindow` on a non-packaged app returns `APPMODEL_ERROR_NO_APPLICATION`. If the code does not handle this error gracefully, it may panic or return an incorrect identity.

**Why it happens:**
- `GetApplicationUserModelIdFromWindow` returns an error for traditional Win32 apps.
- The existing `resolve_app_identity` function returns `Some(AppIdentity::default())` on failure — but `AppIdentity::default()` has empty strings and `Unknown` tier, which is treated as untrusted.
- A Desktop Bridge app (e.g., packaged Notepad++) has both a Win32 image path AND an AUMID. If AUMID resolution fails, we fall back to the Win32 path — but the policy may target the AUMID, causing a mismatch.

**Consequences:**
- Desktop Bridge apps are misidentified as "Unknown" instead of their actual AUMID.
- Policies targeting AUMID do not match Desktop Bridge apps.
- Error handling gaps may cause the clipboard monitor thread to panic on AUMID resolution failure.

**Prevention:**
- **Handle `APPMODEL_ERROR_NO_APPLICATION` explicitly:** If AUMID resolution fails with this error, fall back to the Win32 image path (existing behavior). Do NOT treat this as a fatal error.
- **Try AUMID first, then Win32 path:** For all HWNDs, attempt AUMID resolution. If it succeeds, use the AUMID as the primary identity and skip WinVerifyTrust on the host executable. If it fails, fall back to the existing `QueryFullProcessImageNameW` + `WinVerifyTrust` path.
- **Log AUMID resolution failures** at `debug` level, not `warn` — non-packaged apps are normal and expected.

**Detection:**
- UAT: Test with a traditional Win32 app (Notepad). Verify AUMID resolution fails gracefully and image path is used.
- UAT: Test with a Desktop Bridge app (if available). Verify AUMID resolves correctly.
- UAT: Test with a pure UWP app (Calculator). Verify AUMID resolves correctly.

**Phase to address:** Phase 39 (UWP App Identity).

---

### Pitfall 12: Drag-and-Drop `IDataObject` Format Enumeration Is Slow

**What goes wrong:**
To classify dragged content, the `IDropTarget::Drop` implementation must inspect the `IDataObject` for supported formats (`CF_TEXT`, `CF_UNICODETEXT`, `CF_HDROP`, etc.). Enumerating formats via `IDataObject::EnumFormatEtc` can be slow for large data objects (e.g., dragging 1000 files from Explorer). If the enumeration blocks the OLE thread, the drop operation hangs.

**Why it happens:**
- `IDataObject` format enumeration may trigger lazy loading of data from the source app.
- `CF_HDROP` (file drop) requires the source app to construct a `DROPFILES` structure — this can be expensive for large file lists.
- The existing `classify_text` function is fast, but reading the `IDataObject` may not be.

**Consequences:**
- Dragging large file sets from Explorer hangs for seconds.
- Users perceive the DLP as causing system slowdown.
- Explorer may show "Not Responding" during the drag.

**Prevention:**
- **Do not enumerate formats on the OLE thread.** In `IDropTarget::Drop`, immediately accept the drop, clone the `IDataObject` reference (AddRef), and pass it to a background thread for format enumeration and classification.
- **Check lightweight formats first:** `CF_UNICODETEXT` is cheap — check it before `CF_HDROP`. If text is present, classify it and skip file enumeration.
- **Timeout format enumeration:** If enumeration takes > 500ms, log a warning and allow the drop (fail-open for UX, fail-closed for security is configurable).

**Detection:**
- UAT: Drag 1000 files from Explorer to Desktop. Verify drop completes within 1 second.
- UAT: Drag a single text selection from Word to Notepad. Verify classification completes within 100ms.
- Profile: measure `EnumFormatEtc` time for various data object sizes.

**Phase to address:** Phase 40 (Drag-and-drop enforcement).

---

### Pitfall 13: Managed Origins Cache Poll Race on Agent Startup

**What goes wrong:**
The `ManagedOriginsCache` is populated by a background Tokio task that polls `dlp-server` every 30 seconds. The Chrome pipe server (`handler.rs::serve`) starts immediately and may receive Chrome requests before the first cache refresh completes. If Chrome sends a paste event during this window, the cache is empty → all origins are treated as unmanaged → paste is allowed even from managed origins.

**Why it happens:**
- `chrome::cache::start_poll` spawns an async task.
- `chrome::handler::serve` blocks a dedicated `std::thread`.
- There is no synchronization between "cache has been populated at least once" and "handler starts accepting requests."
- The race window is typically < 1 second (first HTTP request to localhost), but on slow networks or if the server is unreachable, the cache may stay empty for minutes.

**Consequences:**
- Paste from managed origins is allowed during agent startup.
- The bypass is transient but reproducible on every agent restart.
- If the server is permanently unreachable, the Chrome connector becomes a no-op.

**Prevention:**
- **Block handler startup until first cache refresh completes:** In `service.rs` startup sequence, call `cache.refresh().await` before spawning the handler thread. Use a `tokio::sync::Notify` or `std::sync::Barrier` to signal readiness.
- **Fail-closed on empty cache:** If the cache has never been populated, treat ALL origins as managed (block everything) rather than unmanaged. This is conservative but safe.
- **Add a `cache_ready` flag** to `ManagedOriginsCache`. The handler checks this flag before evaluating. If not ready, return BLOCK with reason "cache not ready."

**Detection:**
- UAT: Start agent, immediately paste from SharePoint. Verify block (not allow) if cache is not yet ready.
- UAT: Start agent with server unreachable. Verify Chrome paste is blocked (fail-closed) or allowed with warning audit.
- Log inspection: verify "managed origins cache: initial refresh complete" appears before first Chrome request handling.

**Phase to address:** Phase 41 (Browser origin-aware clipboard policies).

---

## Minor Pitfalls

### Pitfall 14: Admin CLI AUMID Input Is Free-Text (No Validation)

**What goes wrong:**
The admin CLI conditions builder uses free-text input for `Publisher` and `ImagePath` fields. If `Aumid` is added as a free-text field too, admins may type malformed AUMIDs (e.g., missing `!App` suffix, wrong package family name format). Policies with malformed AUMIDs never match, but the admin has no feedback.

**Why it happens:**
- AUMID format is `PackageFamilyName!ApplicationID`, e.g. `Microsoft.Windows.Photos_8wekyb3d8bbwe!App`.
- There is no autocomplete or validation in the TUI.
- The evaluator does a simple string comparison (`eq`/`ne`/`contains`) — no format validation.

**Consequences:**
- Admin frustration: "why isn't my AUMID policy working?"
- Policies with typos are silently ineffective.

**Prevention:**
- **Add AUMID format validation in the admin API:** Reject AUMIDs that do not contain `!` or have invalid characters.
- **Add a helper in the admin CLI:** After the admin types an AUMID, show a preview: "Policy will match: Microsoft.Windows.Photos_8wekyb3d8bbwe!App".
- **Document common AUMIDs** in the admin guide (Calculator, Mail, Edge, etc.).

**Detection:**
- UAT: Try to create a policy with AUMID `"Microsoft.Windows.Photos"` (missing `!App`). Verify validation error.
- UAT: Create policy with valid AUMID. Verify it matches in evaluation test.

**Phase to address:** Phase 39 (UWP App Identity) — admin UX polish.

---

### Pitfall 15: Browser Origin List Does Not Sync to Agent Immediately

**What goes wrong:**
The admin adds a new managed origin via the TUI. The change is saved to `dlp-server`'s database. The agent polls every 30 seconds for cache refresh. During the 30-second window, Chrome paste events from the newly-managed origin are still allowed.

**Why it happens:**
- `ManagedOriginsCache` uses a 30-second polling interval.
- There is no push mechanism (WebSocket, server-sent event, or pipe notification) from server to agent.
- This is the same pattern used for policy sync (5-minute refresh) and agent config (30-second poll).

**Consequences:**
- Transient bypass window of up to 30 seconds after admin adds an origin.
- Admin tests the policy immediately after saving and sees it "not working."

**Prevention:**
- **Acceptable for v0.8.0:** Document the 30-second propagation delay in admin docs.
- **Future improvement:** Add a cache invalidation push via Pipe 1 (agent command pipe) when admin changes managed origins. The server can send a `RefreshOrigins` command to all connected agents.
- **Add a "last refreshed" timestamp** to the admin TUI managed origins screen so admins know when the cache was last updated.

**Detection:**
- UAT: Add origin, wait 35 seconds, test paste. Verify block.
- UAT: Add origin, test paste immediately. Verify allow (documented behavior).

**Phase to address:** Phase 41 (Browser origin-aware clipboard policies) — document; push invalidation is future work.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Reuse `ClipboardAlert` for drag-drop events | Less code, faster implementation | Audit schema confusion, double-counting, wrong event type | Never — create `DragDropAlert` |
| Skip AUMID fallback for non-packaged apps | Simpler code | Desktop Bridge apps misidentified | Never — always fallback to Win32 path |
| Use string splitting for URL origin extraction | No extra dependency | Subdomain spoofing, IDN issues, port handling bugs | Never — use `url::Url` crate |
| Allow all non-clipboard Chrome reasons | Smaller handler code | Silent bypass for drag-drop, save-as, print | Never — default-deny unknown reasons |
| 30-second cache poll with no push | Simpler architecture | 30-second policy propagation delay | Acceptable in v0.8.0; document clearly |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Chrome Enterprise Connector | Only handling `CLIPBOARD_PASTE` (reason=1) | Handle ALL reasons; default-deny unknown ones |
| Chrome Content Analysis SDK | Trusting `request_data.url` as the only origin | Extract both source and destination origins; validate with `url::Url` |
| Win32 OLE Drag-and-Drop | Using `GetClipboardOwner` for drag source | Use `WindowFromPoint` at drag-start; implement `IDropTarget` for drop |
| UWP AUMID Resolution | Calling `QueryFullProcessImageNameW` only | Try `GetApplicationUserModelIdFromWindow` first; fallback to image path |
| Admin CLI Conditions Builder | Adding `AppField::Aumid` without updating all match arms | Update `operators_for`, `value_count_for`, `build_condition`, `condition_display`, and evaluator simultaneously |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| AUMID COM call on every clipboard event | Clipboard monitor thread lag (>50ms per event) | Cache AUMID lookups in `AUTHENTICODE_CACHE`-style HashMap | >10 clipboard events/second |
| `IDataObject` format enumeration on OLE thread | Explorer hangs during large drag operations | Offload enumeration to background thread; timeout at 500ms | Dragging >100 files |
| Chrome handler synchronous evaluation | Chrome UI freeze on paste ("page not responding") | Keep handler response < 100ms; cache lookups only | Slow network to server |
| Admin CLI loading all policies with AUMID conditions | TUI lag when listing policies | Lazy-load condition details; cache parsed policies | >100 policies with AUMID conditions |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Treating non-packaged AUMID failure as "Unknown" tier | Desktop Bridge apps bypass AUMID policies | Fallback to Win32 path + Authenticode; do not downgrade tier |
| Allowing Chrome requests with unknown reasons | New Chrome exfiltration vectors bypass DLP | Default-deny all unknown reasons; audit and alert |
| Exact-string origin matching without wildcard | Admin adds `sharepoint.com`, misses `sub.sharepoint.com` | Support `*.origin.com` wildcard suffix matching |
| Not validating URL origin format | Malformed origins cause parser panics or unexpected matches | Use `url::Url` for parsing; reject invalid origins at admin API |
| Drag-drop `IDropTarget` running without DACL | Other processes can interact with our drop target | Apply pipe-security DACL pattern to COM object |

---

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Double toast for clipboard + drag-drop on same action | User sees two notifications for one drag | Implement deduplication cache; suppress duplicate within 5s |
| Chrome paste blocked with no explanation | User thinks Chrome is broken | Return `WARN` action from Chrome handler with custom message; Chrome shows native warning |
| AUMID policy typo silently fails | Admin thinks policy works but it does not | Validate AUMID format in admin API; show preview in TUI |
| Drag-drop blocked after drop already completed | User sees file appear then disappear | Use non-blocking drop acceptance; show toast AFTER evaluation completes |
| UWP apps always show as "Untrusted" | Legitimate UWP workflows blocked | Resolve AUMID correctly; add Microsoft UWP apps to default trusted list |

---

## "Looks Done But Isn't" Checklist

- [ ] **AUMID Resolution:** Often missing fallback for non-packaged apps — verify Desktop Bridge apps resolve correctly.
- [ ] **AppIdentity Schema:** Often missing `#[serde(default)]` on new `aumid` field — verify old JSON deserializes.
- [ ] **ABAC Evaluator:** Often missing `AppField::Aumid` arm in `app_identity_matches` — verify exhaustive match.
- [ ] **Admin CLI:** Often missing AUMID in `condition_display` or `build_condition` — verify all match arms updated.
- [ ] **Drag-Drop Source:** Often uses `GetClipboardOwner` instead of `WindowFromPoint` at drag-start — verify correct source capture.
- [ ] **Drag-Drop Threading:** Often blocks OLE thread with classification — verify background thread offload.
- [ ] **Chrome Handler:** Often allows non-clipboard reasons — verify default-deny for unknown reasons.
- [ ] **Chrome Destination Origin:** Often missing — verify `destination_url` is extracted and evaluated.
- [ ] **Audit Schema:** Often missing sentinel for new fields — verify `source_application`/`destination_application` always present.
- [ ] **Cache Sync:** Often starts handler before cache ready — verify initial refresh completes before accepting Chrome requests.

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| AUMID schema breaks backward compat | HIGH | Roll back agent; emergency patch to add `serde(default)`; re-deploy |
| Drag-drop hook crashes Explorer | MEDIUM | Unregister `IDropTarget` in UI process restart; log crash; fallback to clipboard-only monitoring |
| Chrome handler allows unknown reasons | LOW | Hot-patch `dispatch_request` to default-deny; no agent restart needed (handler is in dlp-agent) |
| Managed origins cache empty on startup | LOW | Restart agent; verify server connectivity; cache will populate on next poll |
| Admin CLI cannot display AUMID conditions | LOW | Use API directly to edit policies; patch CLI in next release |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Pitfall 1: UWP apps resolve as "Unknown" | Phase 39 | UAT with Calculator, Mail, Edge UWP — verify AUMID in audit event |
| Pitfall 2: AUMID breaks backward compat | Phase 39 | Integration test: old JSON deserializes; new JSON round-trips |
| Pitfall 3: DnD misses actual source app | Phase 40 | UAT: drag Word->Notepad — verify correct source/dest identities |
| Pitfall 4: DnD hook interferes with system | Phase 40 | UAT: drag 50 files rapidly — no hangs; kill UI mid-drag — Explorer works |
| Pitfall 5: Chrome only sees source origin | Phase 41 | UAT: SharePoint->Outlook Web = ALLOW; SharePoint->ChatGPT = BLOCK |
| Pitfall 6: Subdomain spoofing bypass | Phase 41 | UAT: `*.sharepoint.com` matches subdomains; `evil-sharepoint.com` does not |
| Pitfall 7: Audit schema gaps | Phase 42 | Unit test: all event types serialize `source_application`/`destination_application` |
| Pitfall 8: Evaluator missing AUMID arm | Phase 39 | CI build: exhaustive match on `AppField`; unit test for AUMID condition |
| Pitfall 9: Clipboard + DnD double-count | Phase 40 + 42 | UAT: drag file from Explorer — verify single event, no duplicate |
| Pitfall 10: Chrome allows non-clipboard | Phase 41 | UAT: drag file from browser to desktop — verify block event |
| Pitfall 11: AUMID fails for non-packaged | Phase 39 | UAT: Notepad (Win32) — graceful fallback; Calculator (UWP) — AUMID resolved |
| Pitfall 12: `IDataObject` enumeration slow | Phase 40 | UAT: drag 1000 files — completes < 1s |
| Pitfall 13: Origins cache race on startup | Phase 41 | Log inspection: cache refresh before first Chrome request |
| Pitfall 14: Admin CLI AUMID no validation | Phase 39 | UAT: malformed AUMID rejected; valid AUMID accepted |
| Pitfall 15: Origin sync delay | Phase 41 | Document 30s delay; verify push invalidation is future work |

---

## Sources

### Primary (HIGH confidence — existing codebase)
- `dlp-user-ui/src/detection/app_identity.rs` — existing HWND-to-identity resolution, Authenticode cache, `AppIdentity` construction
- `dlp-user-ui/src/clipboard_monitor.rs` — `WM_CLIPBOARDUPDATE` handler, `FOREGROUND_SLOT`, WinEvent hook, `GetClipboardOwner`
- `dlp-common/src/endpoint.rs` — `AppIdentity` struct, `AppTrustTier`, `SignatureState`
- `dlp-common/src/abac.rs` — `AppField` enum, `PolicyCondition::SourceApplication`/`DestinationApplication`
- `dlp-server/src/policy_store.rs` — `app_identity_matches` evaluator, `condition_matches`
- `dlp-admin-cli/src/screens/dispatch.rs` — conditions builder: `operators_for`, `value_count_for`, `build_condition`, `condition_display`
- `dlp-agent/src/chrome/handler.rs` — Chrome Content Analysis request dispatch, `to_origin`, `dispatch_request`
- `dlp-agent/src/chrome/cache.rs` — `ManagedOriginsCache`, polling mechanism
- `dlp-agent/proto/content_analysis.proto` — Chrome SDK protobuf schema
- `dlp-common/src/audit.rs` — `AuditEvent` schema, `source_application`/`destination_application` fields, AUDIT-05 sentinel pattern

### Secondary (MEDIUM confidence — Win32 API documentation)
- Microsoft Docs: `GetApplicationUserModelIdFromWindow` — AUMID resolution from HWND
- Microsoft Docs: `RegisterDragDrop` / `RevokeDragDrop` / `IDropTarget` — OLE drag-and-drop COM interfaces
- Microsoft Docs: `IDataObject::EnumFormatEtc` — format enumeration for drag-and-drop data
- Microsoft Docs: `DoDragDrop` — source-side drag initiation
- Microsoft Docs: `WindowFromPoint` — window under cursor (for drop target detection)
- Microsoft Docs: `GetAsyncKeyState` — detecting drag initiation

### Tertiary (LOW confidence — WebSearch, single source)
- Chrome Enterprise Connector SDK documentation — reason codes, `ContentMetaData` fields, destination URL availability
- Microsoft Purview Endpoint DLP — browser origin policy patterns (competitive reference)
- Symantec DLP / Forcepoint DLP — drag-and-drop interception architecture patterns

---

*Pitfalls research for: v0.8.0 Application-Aware DLP (UWP AUMID, OLE Drag-and-Drop, Browser Origin Policies)*
*Researched: 2026-05-06*
