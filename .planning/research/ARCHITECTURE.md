# Architecture Patterns: Application-Aware DLP v0.8.0

**Domain:** Enterprise Windows Endpoint DLP — UWP App Identity, Drag-and-Drop Enforcement, Browser Origin-Aware Policies
**Researched:** 2026-05-06
**Confidence:** HIGH (existing codebase fully understood; Windows APIs well-documented; Chrome SDK proto verified)

---

## Executive Summary

The v0.8.0 milestone extends the existing DLP architecture with three application-aware enforcement capabilities: **UWP app identity via AUMID**, **drag-and-drop interception**, and **browser origin-aware policies**. All three features share a common constraint: they require operations that can only execute in the **interactive user session**, not in the agent's SYSTEM session 0. This makes the `dlp-user-ui` process — already responsible for clipboard monitoring — the natural execution context for UWP AUMID resolution and drag-and-drop hooks.

The architecture follows the established pattern of "agent owns policy decisions; UI owns session-dependent data collection." New IPC message types extend the existing 3-pipe architecture to carry UWP identity and drag-drop context from UI to agent. The Chrome Enterprise Connector extension is purely agent-side: it adds origin fields to the existing protobuf protocol and integrates origin checks into the `dispatch_request` handler.

**Key architectural decision:** All three features are evaluated as **ABAC subject/resource attributes**, not as separate pre-ABAC enforcement layers (unlike USB/disk enforcement in v0.6.0/v0.7.0). This preserves the unified policy model: a single policy can combine file classification, user identity, app identity, origin, and drag-drop context in one rule set.

---

## Recommended Architecture

### High-Level Component Diagram

```
+-----------------------------------------------------------------------------+
|                           dlp-user-ui (per user session)                     |
|                                                                              |
|  +-------------------+    +-------------------+    +---------------------+  |
|  | Clipboard Monitor |    | UwpIdentityResolver|    | DragDropInterceptor |  |
|  | (existing)        |    | (NEW APP-07)      |    | (NEW APP-08)        |  |
|  |                   |    |                   |    |                     |  |
|  | - WinEvent hook   |    | - IShellItem::    |    | - RegisterDragDrop  |  |
|  | - GetClipboardOwner|   |   GetApplication- |    |   hook (per HWND)   |  |
|  | - Foreground slot |    |   UserModelId     |    | - IDataObject peek  |  |
|  +---------+---------+    +---------+---------+    +----------+----------+  |
|            |                        |                         |              |
|            |                        |                         |              |
|            v                        v                         v              |
|  +---------------------------------------------------------------+        |
|  |                    Pipe 3 (UI -> Agent)                        |        |
|  |  ClipboardAlert { source_app, dest_app }                       |        |
|  |  UwpIdentityAlert { aumid, package_family_name }               |        |
|  |  DragDropAlert { source_app, dest_app, data_formats }          |        |
|  +---------------------------------------------------------------+        |
+-----------------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------+
|                           dlp-agent (Windows Service)                        |
|                                                                              |
|  +-------------------+    +-------------------+    +---------------------+  |
|  | Chrome Connector  |    | AbacContext       |    | PolicyStore         |  |
|  | (existing + NEW)  |    | (extended)        |    | (existing)          |  |
|  |                   |    |                   |    |                     |  |
|  | - Named pipe srv  |    | - source_app      |    | - Evaluates all     |  |
|  | - Protobuf decode |    | - dest_app        |    |   conditions        |  |
|  | - Origin check    |    | - source_origin   |    | - Origin-aware      |  |
|  |   (NEW BRW-04)    |    | - dest_origin     |    |   rules (NEW)       |  |
|  |                   |    | - uwp_app (NEW)   |    |                     |  |
|  |                   |    | - drag_drop_ctx   |    |                     |  |
|  +---------+---------+    +---------+---------+    +----------+----------+  |
|            |                        |                         |              |
|            v                        v                         v              |
|  +---------------------------------------------------------------+        |
|  |                    run_event_loop (existing)                   |        |
|  |  1. Receive FileAction from file_monitor                      |        |
|  |  2. DiskEnforcer::check() -> DENY? -> audit + skip ABAC       |        |
|  |  3. UsbEnforcer::check()  -> DENY? -> audit + skip ABAC       |        |
|  |  4. ABAC evaluation with enriched context (NEW fields)        |        |
|  |  5. Emit audit event, notify UI                               |        |
|  +---------------------------------------------------------------+        |
+-----------------------------------------------------------------------------+
                                    |
                                    v
+-----------------------------------------------------------------------------+
|                           dlp-server (central)                               |
|                                                                              |
|  +-------------------+    +-------------------+    +---------------------+  |
|  | Policy CRUD API   |    | Managed Origins   |    | Audit Store         |  |
|  | (existing)        |    | (existing)        |    | (existing)          |  |
|  +-------------------+    +-------------------+    +---------------------+  |
+-----------------------------------------------------------------------------+
```

### Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| `UwpIdentityResolver` | Resolves AUMID from HWND/IShellItem in user session | Sends `UwpIdentityAlert` via Pipe 3 to agent; consumes `AppIdentity` from clipboard monitor |
| `DragDropInterceptor` | Hooks `RegisterDragDrop` for target windows, intercepts `IDropTarget::Drop` | Sends `DragDropAlert` via Pipe 3 to agent; reads `IDataObject` formats |
| `ChromeConnector` (extended) | Handles `ContentAnalysisRequest` with origin-aware decisions | Reads `ManagedOriginsCache`; emits audit events with origin fields |
| `AbacContext` (extended) | Carries UWP identity and origin fields into policy evaluation | Populated by agent from Pipe 3 alerts and Chrome requests |
| `PolicyStore` (extended) | Evaluates conditions including `source_origin`, `destination_origin`, `uwp_app` | Reads policies from SQLite; no schema change needed (conditions are dynamic) |

---

## Data Flow

### UWP App Identity Flow (APP-07)

```
User copies/pastes content involving a UWP app
    |
    +---> Clipboard monitor (existing) captures source/dest HWND
    |         |
    |         +---> For Win32 apps: existing path (QueryFullProcessImageNameW)
    |         +---> For UWP apps: HWND -> IShellItem -> GetApplicationUserModelId
    |                 |
    |                 +---> AUMID: "Microsoft.Windows.Photos_8wekyb3d8bbwe!App"
    |                 +---> PackageFamilyName: "Microsoft.Windows.Photos_8wekyb3d8bbwe"
    |                 +---> Build AppIdentity with image_path = AUMID
    |                 +---> Build UwpIdentity { aumid, package_family_name }
    |
    +---> Pipe 3: ClipboardAlert { source_app, dest_app, uwp_identity }
    |
    +---> Agent receives alert, stores UWP identity in session-scoped cache
    |
    +---> ABAC evaluation: policy conditions can match on uwp_app.aumid
```

### Drag-and-Drop Flow (APP-08)

```
User drags file/content from App A to App B
    |
    +---> DragDropInterceptor (in UI process) has hooked RegisterDragDrop
    |         for target windows in this session
    |         |
    |         +---> IDropTarget::Drop fires on target window
    |         +---> Interceptor wraps the call:
    |                 |
    |                 +---> Peek IDataObject for data formats (CF_HDROP, etc.)
    |                 +---> Resolve source app from drag source HWND
    |                 +---> Resolve dest app from target window HWND
    |                 +---> Query agent for policy decision (Pipe 1 request/response)
    |                 +---> IF DENY: return DROPEFFECT_NONE (drop appears to fail)
    |                 +---> IF ALLOW: forward to original IDropTarget::Drop
    |
    +---> Agent evaluates ABAC with drag_drop_context
    |         (source_app, dest_app, data_formats)
    |
    +---> Audit event emitted with drag_drop_context
```

### Browser Origin-Aware Flow (BRW-04)

```
Chrome Content Analysis request arrives
    |
    +---> Chrome handler reads ContentAnalysisRequest protobuf
    |         |
    |         +---> request_data.url = "https://sharepoint.com/doc.xlsx"
    |         +---> reason = CLIPBOARD_PASTE (1)
    |         +---> NEW (v0.8.0): Extract source_origin from URL
    |         +---> NEW (v0.8.0): Extract destination_origin from context
    |                 (derived from analysis_connector + URL)
    |
    +---> dispatch_request extended:
    |         |
    |         +---> ManagedOriginsCache.is_managed(source_origin) -> bool
    |         +---> NEW: Check ABAC policy for origin-specific rules
    |                 (e.g., "IF source_origin = 'https://sharepoint.com' THEN DENY")
    |         +---> Return allow/block verdict
    |
    +---> Audit event with source_origin, destination_origin fields
```

---

## New Components (Detailed)

### 1. UwpIdentityResolver

**Location:** `dlp-user-ui/src/uwp_resolver.rs` (new module)

**Purpose:** Resolve AUMID (Application User Model ID) for UWP applications given an HWND. Called from the clipboard monitor when the process image path resolution indicates a UWP app (typically via `ApplicationFrameHost.exe` or `WindowsInternal.ComposableShell.exe`).

**Key APIs:**
- `GetApplicationUserModelId(hProcess, &length, buffer)` — `appmodel.h`, requires `PROCESS_QUERY_LIMITED_INFORMATION`
- `IShellItem::GetProperty(PKEY_AppUserModel_ID)` — Shell API for window-to-AUMID resolution
- `IApplicationResolver::GetAppIDForWindow(HWND)` — undocumented but stable COM interface

**Algorithm:**
```rust
pub fn resolve_uwp_identity(hwnd: HWND) -> Option<UwpIdentity> {
    // Strategy 1: GetApplicationUserModelId on the window's owning process
    let pid = get_window_thread_process_id(hwnd);
    let h_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
    
    let mut len: u32 = 0;
    let rc = unsafe { GetApplicationUserModelId(h_process, &mut len, null_mut()) };
    if rc == ERROR_INSUFFICIENT_BUFFER {
        let mut buf = vec![0u16; len as usize];
        let rc = unsafe { GetApplicationUserModelId(h_process, &mut len, buf.as_mut_ptr()) };
        if rc == ERROR_SUCCESS {
            let aumid = String::from_utf16_lossy(&buf[..len as usize]);
            return Some(UwpIdentity::from_aumid(&aumid));
        }
    }
    
    // Strategy 2: IShellItem property lookup (fallback for packaged apps)
    // ...
    
    None
}
```

**Data structure (in `dlp-common`):**
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UwpIdentity {
    /// Full AUMID: "PackageFamilyName!AppId"
    pub aumid: String,
    /// Just the package family name portion
    pub package_family_name: String,
    /// Just the app ID portion
    pub app_id: String,
    /// Publisher display name from package manifest
    pub publisher: String,
    /// Package display name
    pub display_name: String,
}
```

**Integration with clipboard monitor:**
The existing `clipboard_monitor.rs` already resolves `source_hwnd` and `dest_hwnd`. After the existing `get_process_image_path` call, add a UWP detection branch:

```rust
// In clipboard_monitor.rs::handle_clipboard_change
let source_app = if is_uwp_process(source_pid) {
    uwp_resolver::resolve_uwp_identity(source_hwnd)
        .map(|uwp| AppIdentity::from_uwp(&uwp))
        .or_else(|| resolve_win32_app(source_pid))
} else {
    resolve_win32_app(source_pid)
};
```

**Confidence:** HIGH — `GetApplicationUserModelId` is a documented Win32 API since Windows 8. The `PROCESS_QUERY_LIMITED_INFORMATION` requirement is satisfied when querying processes in the same session (the UI runs as the interactive user).

---

### 2. DragDropInterceptor

**Location:** `dlp-user-ui/src/drag_drop.rs` (new module)

**Purpose:** Intercept OLE drag-and-drop operations within the user session to enforce DLP policies on drop actions. Unlike clipboard monitoring (which is passive observation), drag-and-drop interception is **active enforcement** — the interceptor can block a drop by returning `DROPEFFECT_NONE` from `IDropTarget::Drop`.

**Architecture approach:**

There is **no system-wide OLE drag-and-drop hook** in Windows. The feasible approaches are:

| Approach | Complexity | Scope | Recommendation |
|----------|-----------|-------|----------------|
| Hook `RegisterDragDrop` in all processes via DLL injection | Very High | System-wide | **Rejected** — requires DLL injection into every process; fragile; antivirus issues |
| Implement `IDropTarget` for our own windows only | Low | Our windows only | **Rejected** — only protects DLP UI windows, not user apps |
| Use `SetWinEventHook(EVENT_OBJECT_DRAGSTART)` | Medium | Notification only | **Rejected** — only detects drag start, cannot intercept or access data |
| **Hook `RegisterDragDrop` in the UI process, register for top-level windows** | Medium | Session-wide | **Recommended** — enumerate top-level windows in session, call `RevokeDragDrop` + `RegisterDragDrop` with wrapped `IDropTarget` |

**Recommended approach: Per-session window hooking**

The UI process (running in the user session) can enumerate all top-level windows and replace their `IDropTarget` registration with a wrapper that intercepts `Drop` calls:

```rust
impl DragDropInterceptor {
    /// Enumerate all top-level windows in this session and hook their
    /// drop targets. Called once at UI startup.
    pub fn hook_session_windows(&self) {
        enum_windows(|hwnd| {
            if Self::is_interesting_window(hwnd) {
                self.hook_window(hwnd);
            }
            true
        });
    }
    
    /// For a single window: revoke existing drop target, register our wrapper.
    fn hook_window(&self, hwnd: HWND) {
        unsafe { RevokeDragDrop(hwnd) }; // Safe to call even if not registered
        let wrapper = DropTargetWrapper::new(hwnd, self.policy_client.clone());
        unsafe { RegisterDragDrop(hwnd, wrapper) }.ok();
    }
}

/// COM wrapper that delegates to the original IDropTarget after policy check.
struct DropTargetWrapper {
    original: Option<Box<dyn IDropTarget>>,
    hwnd: HWND,
    policy_client: Arc<DragDropPolicyClient>,
}

impl IDropTarget for DropTargetWrapper {
    fn DragEnter(&self, pDataObj: &IDataObject, grfKeyState: u32, pt: POINT, pdwEffect: &mut u32) -> HRESULT {
        // Forward to original; we only care about Drop
        if let Some(ref orig) = self.original {
            orig.DragEnter(pDataObj, grfKeyState, pt, pdwEffect)
        } else {
            S_OK
        }
    }
    
    fn Drop(&self, pDataObj: &IDataObject, grfKeyState: u32, pt: POINT, pdwEffect: &mut u32) -> HRESULT {
        // 1. Peek data formats from IDataObject
        let formats = self.peek_data_formats(pDataObj);
        
        // 2. Resolve source application from drag source
        let source_app = self.resolve_source_app();
        
        // 3. Resolve destination application from target window
        let dest_app = self.resolve_dest_app(self.hwnd);
        
        // 4. Query agent for policy decision (synchronous over Pipe 1)
        match self.policy_client.query_decision(source_app, dest_app, &formats) {
            Decision::ALLOW => {
                // Forward to original drop target
                if let Some(ref orig) = self.original {
                    orig.Drop(pDataObj, grfKeyState, pt, pdwEffect)
                } else {
                    *pdwEffect = DROPEFFECT_NONE;
                    S_OK
                }
            }
            Decision::DENY => {
                // Block the drop
                *pdwEffect = DROPEFFECT_NONE;
                // Emit audit via Pipe 3
                self.emit_drag_drop_blocked(source_app, dest_app, &formats);
                S_OK
            }
        }
    }
}
```

**Critical design points:**

1. **Window enumeration on startup + new window detection:** Use `SetWinEventHook(EVENT_OBJECT_CREATE)` to detect new top-level windows and hook them automatically.

2. **UAC/integrity level:** If the target window runs at a higher integrity level than the UI process, `RegisterDragDrop` will fail. The interceptor must gracefully skip such windows (log a warning). This is acceptable because:
   - Most user apps run at medium integrity
   - Elevated apps dragging from non-elevated sources is already blocked by Windows UIPI
   - The file monitor I/O path (existing) still catches the actual file write

3. **IDataObject format inspection:** Peek `CF_HDROP` (file paths), `CF_TEXT`/`CF_UNICODETEXT` (text content), `CF_BITMAP` (images). Do NOT read the full data — only inspect formats for policy matching.

4. **Synchronous policy query:** `Drop` is called on the UI thread (message pump). The policy query to the agent must be synchronous (blocking) to return a decision before `Drop` returns. Use Pipe 1 request/response pattern with a timeout (e.g., 500ms). If timeout, default to ALLOW (fail-open) to avoid breaking UX, but emit an audit event.

**Confidence:** MEDIUM-HIGH — The `RegisterDragDrop`/`RevokeDragDrop` approach is documented and works for windows the UI process can access. The main risk is missing windows that are created before the UI starts or that resist re-registration. The file monitor I/O path serves as a backstop.

---

### 3. Chrome Connector Extension (BRW-04)

**Location:** `dlp-agent/src/chrome/handler.rs` (modified)

**Purpose:** Extend the existing Chrome Content Analysis handler to support origin-aware policy decisions. The current implementation (BRW-03) only checks if the source URL is in the `ManagedOriginsCache` (binary allow/block). BRW-04 adds fine-grained origin-based rules via the ABAC policy engine.

**Current protobuf (verified from chromium/content_analysis_sdk):**

```protobuf
message ContentMetaData {
  optional string url = 1;           // The URL containing the file/content
  optional string filename = 2;
  optional string digest = 3;
  optional string email = 5;
  optional string tab_title = 9;
}

message ContentAnalysisRequest {
  optional string request_token = 5;
  optional AnalysisConnector analysis_connector = 9;
  optional ContentMetaData request_data = 10;
  repeated string tags = 11;
  optional ClientMetadata client_metadata = 12;
  
  oneof content_data {
    string text_content = 13;
    string file_path = 14;
    PrintData print_data = 18;
  }
  
  optional int64 expires_at = 15;
  optional string user_action_id = 16;
  optional int64 user_action_requests_count = 17;
  
  enum Reason {
    UNKNOWN = 0;
    CLIPBOARD_PASTE = 1;
    DRAG_AND_DROP = 2;
    FILE_PICKER_DIALOG = 3;
    PRINT_PREVIEW_PRINT = 4;
    SYSTEM_DIALOG_PRINT = 5;
    NORMAL_DOWNLOAD = 6;
    SAVE_AS_DOWNLOAD = 7;
  }
  optional Reason reason = 19;
}
```

**Key insight:** The `ContentMetaData.url` field already carries the origin URL. The existing code extracts this via `to_origin()` and checks against `ManagedOriginsCache`. BRW-04 extends this to:

1. **Extract both source and destination origins:**
   - `source_origin`: From `request_data.url` (where content came from)
   - `destination_origin`: Derived from `analysis_connector` context (where content is going)
     - `FILE_DOWNLOADED` -> destination is the browser (local disk)
     - `FILE_ATTACHED` -> destination is the upload target (web app)
     - `BULK_DATA_ENTRY` -> destination depends on `reason` (CLIPBOARD_PASTE or DRAG_AND_DROP)

2. **Integrate with ABAC evaluator:**
   Instead of the binary `ManagedOriginsCache.is_managed()` check, construct an `EvaluateRequest` and call the policy engine:

```rust
fn dispatch_request(request: &ContentAnalysisRequest) -> ContentAnalysisResponse {
    let source_origin = extract_source_origin(request);
    let destination_origin = extract_destination_origin(request);
    
    // Build ABAC context
    let eval_request = EvaluateRequest {
        subject: Subject { /* ... */ },
        resource: Resource {
            path: request.content_data.file_path.clone().unwrap_or_default(),
            classification: classify_from_request(request),
        },
        environment: Environment { /* ... */ },
        action: action_from_connector(request.analysis_connector),
        source_application: None, // Browser is the source app
        destination_application: None,
        // NEW fields for v0.8.0:
        source_origin: source_origin.clone(),
        destination_origin: destination_origin.clone(),
    };
    
    // Query policy engine
    let response = POLICY_STORE.evaluate(&eval_request);
    
    match response.decision {
        Decision::ALLOW | Decision::AllowWithLog => make_result_allow(),
        Decision::DENY | Decision::DenyWithAlert => {
            emit_chrome_block_audit(&source_origin, &destination_origin);
            make_result_block()
        }
    }
}
```

**Protobuf changes:**

No protobuf changes are needed. The existing `ContentMetaData.url` field carries the origin. The `analysis_connector` and `reason` fields provide sufficient context to derive source/destination semantics.

**Confidence:** HIGH — The protobuf structure is verified from the official Chromium SDK. The `url` field is documented as "The URL containing the file download/upload or to which web content is being uploaded." The integration with `EvaluateRequest` follows the existing pattern from `run_event_loop`.

---

## Modified Components

### 1. `dlp-common` — Extended Types

**`abac.rs` — `EvaluateRequest` and `AbacContext`:**

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvaluateRequest {
    pub subject: Subject,
    pub resource: Resource,
    pub environment: Environment,
    pub action: Action,
    pub agent: Option<AgentInfo>,
    pub source_application: Option<AppIdentity>,
    pub destination_application: Option<AppIdentity>,
    // NEW v0.8.0 fields:
    /// Source web origin for browser-originated requests (BRW-04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_origin: Option<String>,
    /// Destination web origin for browser-originated requests (BRW-04).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_origin: Option<String>,
    /// UWP app identity when the source/dest is a packaged app (APP-07).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uwp_identity: Option<UwpIdentity>,
    /// Drag-and-drop context when the action is a drop operation (APP-08).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drag_drop_context: Option<DragDropContext>,
}
```

**`endpoint.rs` — `UwpIdentity`:**

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UwpIdentity {
    pub aumid: String,
    pub package_family_name: String,
    pub app_id: String,
    pub publisher: String,
    pub display_name: String,
}
```

**`audit.rs` — `AuditEvent`:**

Add fields:
```rust
/// UWP app identity for packaged applications (APP-07).
#[serde(skip_serializing_if = "Option::is_none")]
pub uwp_identity: Option<UwpIdentity>,
/// Drag-and-drop context for drop operations (APP-08).
#[serde(skip_serializing_if = "Option::is_none")]
pub drag_drop_context: Option<DragDropContext>,
```

### 2. `dlp-agent/src/ipc/messages.rs` — New Pipe 3 Messages

```rust
/// Messages sent FROM the UI TO the agent over Pipe 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum Pipe3UiMsg {
    // ... existing variants ...
    
    /// UWP app identity resolved for a clipboard operation (APP-07).
    UwpIdentityAlert {
        session_id: u32,
        /// The HWND that was resolved.
        hwnd: usize,
        /// Resolved UWP identity.
        uwp_identity: UwpIdentity,
        /// Whether this is the source or destination app.
        role: AppRole,
    },
    
    /// Drag-and-drop operation detected and policy-checked (APP-08).
    DragDropAlert {
        session_id: u32,
        /// Source application identity.
        source_application: Option<AppIdentity>,
        /// Destination application identity.
        destination_application: Option<AppIdentity>,
        /// Data formats present in the drop.
        data_formats: Vec<String>,
        /// Policy decision from the agent.
        decision: Decision,
        /// Human-readable reason for the decision.
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AppRole {
    Source,
    Destination,
}
```

### 3. `dlp-agent/src/ipc/pipe3.rs` — Route New Messages

Extend the `route` function to handle `UwpIdentityAlert` and `DragDropAlert`:

```rust
fn route(msg: Pipe3UiMsg) {
    match msg {
        // ... existing variants ...
        
        Pipe3UiMsg::UwpIdentityAlert { session_id, hwnd, uwp_identity, role } => {
            // Store in session-scoped UWP identity cache
            if let Some(map) = crate::session_identity::global_map() {
                map.set_uwp_identity(session_id, hwnd, uwp_identity, role);
            }
        }
        
        Pipe3UiMsg::DragDropAlert { session_id, source_application, destination_application, data_formats, decision, reason } => {
            // Emit audit event for the drag-and-drop operation
            let mut event = AuditEvent::new(
                EventType::Block,
                // ... identity fields ...
            )
            .with_source_application(source_application)
            .with_destination_application(destination_application);
            // ... emit ...
        }
    }
}
```

### 4. `dlp-agent/src/chrome/handler.rs` — Origin-Aware Dispatch

Modify `dispatch_request` to integrate with the ABAC policy engine instead of only checking `ManagedOriginsCache`:

```rust
fn dispatch_request(request: &ContentAnalysisRequest) -> ContentAnalysisResponse {
    // Extract origins from request
    let source_origin = request.request_data.as_ref()
        .and_then(|d| d.url.as_ref())
        .and_then(|u| to_origin(u));
    
    let destination_origin = derive_destination_origin(request);
    
    // Build ABAC evaluation request
    let eval_request = build_evaluate_request(request, &source_origin, &destination_origin);
    
    // Query policy engine (via OfflineManager / PolicyStore)
    let response = evaluate_policy(eval_request);
    
    // Build response based on decision
    match response.decision {
        Decision::ALLOW | Decision::AllowWithLog => make_result_allow(),
        Decision::DENY | Decision::DenyWithAlert => {
            emit_chrome_block_audit(&source_origin, &destination_origin);
            make_result_block()
        }
    }
}
```

### 5. `dlp-common/src/abac.rs` — New Policy Conditions

Add new condition variants for origin and UWP:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "attribute", rename_all = "snake_case")]
pub enum PolicyCondition {
    // ... existing variants ...
    
    /// Match by source web origin (BRW-04).
    SourceOrigin {
        op: String,
        origin: String,
    },
    /// Match by destination web origin (BRW-04).
    DestinationOrigin {
        op: String,
        origin: String,
    },
    /// Match by UWP package family name (APP-07).
    UwpPackageFamily {
        op: String,
        package_family_name: String,
    },
    /// Match by UWP AUMID (APP-07).
    UwpAumid {
        op: String,
        aumid: String,
    },
    /// Match by drag-and-drop data format (APP-08).
    DragDropFormat {
        op: String,
        format: String,
    },
}
```

### 6. `dlp-admin-cli` — TUI Condition Builder Extensions

Extend the conditions builder (Phase 13, 28) to support the new attribute types:

- `source_origin` -> operator: `eq`, `ne`, `contains` -> value: origin string
- `destination_origin` -> operator: `eq`, `ne`, `contains` -> value: origin string
- `uwp_package_family` -> operator: `eq`, `ne` -> value: package family name
- `uwp_aumid` -> operator: `eq`, `ne` -> value: full AUMID
- `drag_drop_format` -> operator: `eq`, `contains` -> value: format name (CF_HDROP, CF_TEXT, etc.)

---

## Patterns to Follow

### Pattern 1: Session-0 / User-Session Split
**What:** Operations requiring interactive desktop access (clipboard, UWP AUMID, drag-and-drop) run in `dlp-user-ui`. Policy decisions and audit emission run in `dlp-agent`.
**When:** Any feature that touches user-session-only APIs.
**Example:** Clipboard monitoring already follows this pattern. UWP AUMID and drag-and-drop follow the same split.

### Pattern 2: Enrich-Then-Evaluate
**What:** The UI process enriches raw events with identity/context, sends to agent via IPC, and the agent evaluates against policies.
**When:** When the evaluation context cannot be fully resolved in a single process.
**Example:** Clipboard alert carries `source_application` and `destination_application`. Drag-drop alert will carry the same plus `data_formats`.

### Pattern 3: COM Interface Wrapping for Interception
**What:** To intercept a Windows COM interface method (like `IDropTarget::Drop`), implement a wrapper that delegates to the original after performing the intercept logic.
**When:** When Windows provides no hook or notification mechanism.
**Example:** The `DropTargetWrapper` implements `IDropTarget`, stores a reference to the original, and intercepts `Drop` while delegating `DragEnter`/`DragOver`/`DragLeave`.

### Pattern 4: Fail-Open with Audit for UX-Critical Paths
**What:** When a policy query times out or fails (e.g., drag-drop decision), default to ALLOW to avoid breaking user experience, but emit an audit event.
**When:** The interception point is on the user's critical path (clipboard paste, drag-drop).
**Example:** Drag-drop `Drop` must return within ~500ms or the UI appears frozen. If the agent doesn't respond in time, allow the drop and log a timeout audit event.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: DLL Injection for System-Wide Drag-and-Drop
**What:** Injecting a DLL into every process to hook `RegisterDragDrop` globally.
**Why bad:** Fragile, triggers antivirus, requires 32/64-bit dual injection, breaks on Windows updates, difficult to debug.
**Instead:** Hook only windows in the user session that the UI process can access. Accept that some elevated-process drops will be missed — the file monitor I/O path catches them.

### Anti-Pattern 2: Blocking Drops Synchronously Without Timeout
**What:** Making `IDropTarget::Drop` wait indefinitely for a policy decision.
**Why bad:** Windows drag-and-drop has no progress indicator. A hung `Drop` makes the application appear frozen. Users will force-kill the app.
**Instead:** Use a strict timeout (500ms max). Default to ALLOW on timeout with audit logging.

### Anti-Pattern 3: Storing UWP Identity as ABAC Subject Attribute
**What:** Adding `uwp_identity` to `Subject` instead of keeping it as a separate field in `EvaluateRequest`.
**Why bad:** UWP identity is an application attribute, not a user attribute. Conflating them makes policy authoring confusing.
**Instead:** Keep `uwp_identity` as a top-level field in `EvaluateRequest`, alongside `source_application` and `destination_application`.

### Anti-Pattern 4: Reading Full IDataObject Content in Drop Handler
**What:** Extracting the full file content or large text from `IDataObject` during `Drop` for classification.
**Why bad:** `Drop` runs on the UI thread. Reading large files blocks the application. Also, the DLP policy should not need content — it decides based on metadata (source app, dest app, format).
**Instead:** Only inspect `IDataObject::QueryGetData` to determine available formats (CF_HDROP, CF_TEXT, etc.). Leave content classification to the file monitor or clipboard classifier.

### Anti-Pattern 5: Relying on HWND Alone for UWP Detection
**What:** Assuming that if `GetWindowThreadProcessId` returns a UWP process, the window belongs to that UWP app.
**Why bad:** UWP apps host their UI in `ApplicationFrameHost.exe` or `WindowsInternal.ComposableShell.exe`. The process PID does not directly map to the UWP package.
**Instead:** Use `GetApplicationUserModelId` on the process token, or `IShellItem::GetProperty(PKEY_AppUserModel_ID)` on the window, to resolve the actual AUMID.

---

## Scalability Considerations

| Concern | At 1 endpoint | At 10K endpoints | At 100K endpoints |
|---------|--------------|------------------|-------------------|
| UWP identity resolution | Per-clipboard operation, ~1ms | Same per-endpoint | Same per-endpoint |
| Drag-drop hooked windows | ~50 windows per session | Same per-endpoint | Same per-endpoint |
| Chrome origin checks | Per-paste operation | Same per-endpoint | Same per-endpoint |
| IPC message volume | Low (only on clipboard change / drop) | Medium | Medium — ensure Pipe 3 buffer is sized appropriately |
| Policy condition count | ~10 conditions per policy | ~50 conditions per policy | ~100 conditions per policy — evaluate in O(n) |

---

## Integration Points Summary

| Integration Point | Existing Code | New Code | Change Type |
|-------------------|--------------|----------|-------------|
| `dlp-common::EvaluateRequest` | `source_application`, `destination_application` | Add `source_origin`, `destination_origin`, `uwp_identity`, `drag_drop_context` | Modified |
| `dlp-common::AuditEvent` | `source_origin`, `destination_origin` | Add `uwp_identity`, `drag_drop_context` | Modified |
| `dlp-common::PolicyCondition` | Classification, MemberOf, DeviceTrust, etc. | Add `SourceOrigin`, `DestinationOrigin`, `UwpPackageFamily`, `UwpAumid`, `DragDropFormat` | Modified |
| `dlp-agent::ipc::Pipe3UiMsg` | `ClipboardAlert`, `HealthPong`, etc. | Add `UwpIdentityAlert`, `DragDropAlert` | Modified |
| `dlp-agent::ipc::pipe3::route` | Routes clipboard alerts | Add routes for UWP and drag-drop alerts | Modified |
| `dlp-agent::chrome::handler` | `dispatch_request` with `ManagedOriginsCache` | Integrate ABAC policy engine for origin rules | Modified |
| `dlp-user-ui::clipboard_monitor` | Resolves Win32 app identity | Add UWP AUMID resolution branch | Modified |
| `dlp-user-ui` | Clipboard monitor only | Add `drag_drop` module with `DragDropInterceptor` | New module |
| `dlp-admin-cli` | Conditions builder for existing attrs | Add picker entries for origin, UWP, drag-drop | Modified |

---

## Build Order Recommendation

Based on dependency analysis:

1. **Phase 39-A: Common types extension** (`dlp-common`)
   - Add `UwpIdentity`, `DragDropContext` structs
   - Extend `EvaluateRequest`, `AbacContext`, `AuditEvent` with new fields
   - Add new `PolicyCondition` variants
   - No dependencies on other v0.8.0 work

2. **Phase 39-B: UWP AUMID resolver** (`dlp-user-ui`)
   - Create `uwp_resolver.rs` with `GetApplicationUserModelId` FFI
   - Integrate into `clipboard_monitor.rs` for UWP app detection
   - Add `UwpIdentityAlert` Pipe 3 message
   - Depends on Phase 39-A

3. **Phase 39-C: Agent-side UWP context handling** (`dlp-agent`)
   - Extend `Pipe3UiMsg` with `UwpIdentityAlert`
   - Route UWP alerts in `pipe3.rs`
   - Store UWP identity in `SessionIdentityMap`
   - Extend ABAC evaluator with `UwpPackageFamily`/`UwpAumid` conditions
   - Depends on Phase 39-A, 39-B

4. **Phase 39-D: Chrome origin-aware policies** (`dlp-agent`)
   - Extend `dispatch_request` to build `EvaluateRequest` with origin fields
   - Add `SourceOrigin`/`DestinationOrigin` policy conditions
   - Extend `ManagedOriginsCache` or replace with policy engine integration
   - Depends on Phase 39-A

5. **Phase 39-E: Drag-and-drop interceptor** (`dlp-user-ui`)
   - Create `drag_drop.rs` with `DropTargetWrapper` COM implementation
   - Implement window enumeration and `RegisterDragDrop` hooking
   - Add synchronous policy query over Pipe 1
   - Add `DragDropAlert` Pipe 3 message
   - Depends on Phase 39-A, 39-C (ABAC evaluator must support drag-drop conditions)

6. **Phase 39-F: Admin TUI condition builder extensions** (`dlp-admin-cli`)
   - Add origin, UWP, and drag-drop attributes to the conditions picker
   - Depends on Phase 39-A, 39-C, 39-D, 39-E

---

## Key Questions Answered

### Where does UWP AUMID resolution run?
**Answer:** In the **user session UI process** (`dlp-user-ui`), not in the agent. `GetApplicationUserModelId` requires a process handle with `PROCESS_QUERY_LIMITED_INFORMATION`. While the agent (SYSTEM) could technically open any process, the clipboard monitoring already runs in the UI process, and the HWND-to-process resolution is already there. Adding UWP resolution to the same code path is natural.

### How does drag-and-drop enforcement avoid DLL injection?
**Answer:** By using **per-session window hooking** instead of system-wide DLL injection. The UI process enumerates top-level windows in its session, calls `RevokeDragDrop` + `RegisterDragDrop` with a wrapper `IDropTarget`. This only affects windows the UI process can access (same integrity level). Elevated windows are skipped gracefully. The file monitor I/O path serves as the backstop for missed drops.

### What is the Chrome origin field in the protobuf?
**Answer:** The official Chromium `analysis.proto` (verified from `chromium/content_analysis_sdk`) defines `ContentMetaData.url` as "The URL containing the file download/upload or to which web content is being uploaded." There is no separate `origin` field. The origin is derived from `url` via the existing `to_origin()` function (scheme + host, lowercased). Source vs destination semantics are inferred from `analysis_connector` and `reason` fields.

### How do origin-aware policies integrate with existing managed origins?
**Answer:** The existing `ManagedOriginsCache` provides a binary "is this origin managed?" check. BRW-04 extends this to **fine-grained ABAC rules** — e.g., "IF source_origin = 'https://sharepoint.com' AND classification >= T3 THEN DENY." The managed origins list can still be used as a shorthand (all managed origins = block by default), but admins can now override with specific rules.

### What happens when a drag-drop policy query times out?
**Answer:** The `Drop` handler uses a **500ms timeout**. If the agent doesn't respond, the drop is **allowed** (fail-open) and an audit event is emitted with `decision = TIMEOUT`. This prevents application hangs. The file monitor may still block the actual file write if the dropped content triggers a file operation.

### Should drag-drop and clipboard share the same AppIdentity resolution?
**Answer:** **Yes.** Both clipboard paste and drag-and-drop need to resolve source and destination applications. The existing `AppIdentity` resolution (Win32 path + publisher) and the new `UwpIdentity` resolution (AUMID) should be shared via a common resolver module in `dlp-user-ui`. The only difference is the trigger event (clipboard change vs `IDropTarget::Drop`).

---

## Sources

### Primary (HIGH confidence)
- `dlp-agent/src/ipc/messages.rs` — existing IPC message definitions
- `dlp-agent/src/ipc/pipe3.rs` — Pipe 3 routing logic
- `dlp-agent/src/chrome/handler.rs` — Chrome Content Analysis handler
- `dlp-agent/src/chrome/proto.rs` — Protobuf integration
- `dlp-user-ui/src/clipboard_monitor.rs` — Clipboard monitoring with WinEvent hooks
- `dlp-common/src/abac.rs` — ABAC types and `EvaluateRequest`
- `dlp-common/src/audit.rs` — `AuditEvent` schema
- `dlp-common/src/endpoint.rs` — `AppIdentity` and related types
- `dlp-agent/src/interception/mod.rs` — `run_event_loop` integration point
- `dlp-agent/src/service.rs` — Service startup and subsystem initialization
- `dlp-agent/proto/content_analysis.proto` — Local vendored protobuf (BRW-01)
- `https://raw.githubusercontent.com/chromium/content_analysis_sdk/main/proto/content_analysis/sdk/analysis.proto` — Official Chromium SDK protobuf (verified 2026-05-06)

### Secondary (MEDIUM confidence)
- [Microsoft Docs: RegisterDragDrop function](https://learn.microsoft.com/en-us/windows/win32/api/ole2/nf-ole2-registerdragdrop) — official API documentation
- [Microsoft Docs: IDropTarget interface](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nn-oleidl-idroptarget) — official COM interface docs
- [Microsoft Docs: GetApplicationUserModelId](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getapplicationusermodelid) — official UWP API docs
- [Stack Overflow: Detect drag and drop in external application](https://stackoverflow.com/questions/1746380/detect-drag-and-drop-operations-in-an-external-application-using-net) — community-validated approach
- [Catch22: Drop Target Tutorial](https://www.catch22.net/tuts/ole/drop-target/) — practical COM implementation guide

### Tertiary (LOW confidence)
- Community discussions on UWP `IApplicationResolver` COM interface (undocumented but widely used)
- USB bridge chip behavior discussions (JMicron JMS583, ASMedia ASM2362)

---
*Research completed: 2026-05-06*
*Ready for roadmap: yes*
