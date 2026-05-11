# Phase 39: UWP App Identity - Context

**Gathered:** 2026-05-06
**Status:** Ready for planning
**Mode:** Auto-generated (smart discuss — codebase-informed decisions)

<domain>
## Phase Boundary

Agent can capture UWP application identity via AUMID for ABAC enforcement. UWP apps (distributed via Microsoft Store / MSIX) do not have traditional Win32 image paths under Program Files. Instead, they have an Application User Model ID (AUMID) like `Microsoft.Windows.Photos_8wekyb3d8bbwe!App` and a Package Family Name. This phase extends the existing app identity capture pipeline (Phase 25) to resolve UWP process identity to AUMID using Win32 `GetApplicationUserModelId`, capture it as a first-class `source_application` / `destination_application` attribute, and ensure it flows through the same ABAC evaluator without special-casing.

</domain>

<decisions>
## Implementation Decisions

### UWP Detection Strategy
- **Detection heuristic**: After `QueryFullProcessImageNameW` returns a path, check if it starts with `C:\Program Files\WindowsApps\`. This is the canonical UWP app installation directory. No registry queries or COM calls needed for detection.
- **Rationale**: Simple, fast, zero external dependencies. The WindowsApps directory is the standard UWP container path on all Windows 10/11 systems.

### AUMID Resolution API
- **API choice**: `GetApplicationUserModelId` from `Windows.Win32.System.Threading` (windows-rs 0.62 feature). Takes a process handle and returns the AUMID string.
- **Alternative considered**: `IShellItem::GetApplicationUserModelId` — rejected because it requires COM interface initialization and a shell item; `GetApplicationUserModelId` is a direct system call.
- **Process handle**: Use `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)` — same handle we already open for `QueryFullProcessImageNameW`. No additional handle needed.

### AppIdentity Schema Extension
- **Extend `AppIdentity`** with three new fields:
  - `aumid: Option<String>` — the full AUMID (e.g., `Microsoft.Windows.Photos_8wekyb3d8bbwe!App`)
  - `package_family_name: Option<String>` — extracted from AUMID (everything before `!`)
  - `is_uwp: bool` — convenience flag for quick branching
- **Rationale**: Option<String> preserves backward compatibility for Win32 processes. `is_uwp` avoids repeated path-prefix checks downstream.
- **PackageFamilyName extraction**: Split AUMID on `!` character. If no `!`, store full string as package_family_name (defensive).

### ABAC Integration
- **New `AppField` variant**: `Aumid` — for exact AUMID matching in policies
- **New `AppField` variant**: `PackageFamilyName` — for matching entire package families (e.g., block all Microsoft Office apps)
- **Evaluator behavior**: `app_identity_matches()` in policy_store.rs handles `Aumid` and `PackageFamilyName` with `eq`/`ne`/`contains` operators. `contains` is useful for partial AUMID matching.
- **No special-casing**: UWP identity flows through the same `SourceApplication` / `DestinationApplication` condition paths. The evaluator checks `is_uwp` only to select the right field value.

### TUI Conditions Builder
- **Add AUMID and PackageFamilyName to AppField picker** in the conditions builder (dlp-admin-cli)
- **Display**: When admin selects AUMID, show a text input. When PackageFamilyName, show a text input with placeholder example.
- **Rationale**: Follows existing pattern for Publisher, ImagePath, TrustTier fields.

### Audit Integration
- **AuditEvent already has** `source_application` and `destination_application` fields of type `AppIdentity`
- **No schema changes needed** — the extended AppIdentity with `aumid`/`package_family_name`/`is_uwp` fields will serialize naturally via serde
- **AGENT-UNKNOWN handling**: If AUMID resolution fails (e.g., process exits mid-resolution), fall back to existing Win32 identity + `is_uwp: false`. Do NOT emit AGENT-UNKNOWN for UWP detection failures — the Win32 path still provides useful identity.

### Error Handling
- **AUMID resolution failure is non-fatal**: Log at `tracing::warn!` level, continue with Win32 identity (image_path + publisher). Never panic.
- **Buffer sizing**: `GetApplicationUserModelId` requires two calls — first to get buffer size, second to fill. Handle `ERROR_INSUFFICIENT_BUFFER` correctly.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AppIdentity` struct in `dlp-common/src/endpoint.rs` — extend with three new fields
- `AppField` enum in `dlp-common/src/abac.rs` — add `Aumid` and `PackageFamilyName` variants
- `app_identity_matches()` in `dlp-server/src/policy_store.rs` — add new field branches
- `resolve_app_identity()` in `dlp-user-ui/src/detection/app_identity.rs` — add UWP detection + AUMID resolution after existing Win32 path
- `AUTHENTICODE_CACHE` pattern — can be reused for AUMID caching if needed, but AUMID resolution is fast (single system call) so skip caching for simplicity
- `GetWindowThreadProcessId` → `OpenProcess` → `QueryFullProcessImageNameW` pipeline — reuse same process handle for `GetApplicationUserModelId`

### Established Patterns
- Win32 API calls: `#[cfg(windows)]` gated, `unsafe` blocks with `SAFETY:` comments, non-Windows stubs
- Error handling: `Result<T, AppIdentityError>` with `thiserror` — add `AumidResolutionFailed` variant
- ABAC condition matching: `eq`/`ne` for all fields, `contains` for string fields
- TUI picker: `AppField` variants map to display labels in conditions builder
- Serde: All dlp-common types derive `Serialize` + `Deserialize` — new fields need derive

### Integration Points
- **dlp-common**: AppIdentity + AppField changes propagate to all crates
- **dlp-user-ui**: clipboard_monitor.rs calls resolve_app_identity() — automatically gets UWP support
- **dlp-agent**: audit_emitter.rs get_application_metadata() may need UWP path if used for clipboard blocks
- **dlp-server**: policy_store.rs evaluator needs new field branches
- **dlp-admin-cli**: conditions builder UI needs new picker options

</code_context>

<specifics>
## Specific Ideas

- The `GetApplicationUserModelId` API is in `Windows.Win32.System.Threading` namespace. Need to enable this feature in dlp-user-ui's Cargo.toml (currently uses windows 0.58).
- dlp-agent uses windows 0.62 — verify the API is in the same namespace across versions.
- For AUMID extraction from HWND: same flow as existing — `GetWindowThreadProcessId` → `OpenProcess` → `GetApplicationUserModelId`. The process handle is already opened for `QueryFullProcessImageNameW`.
- UWP apps may have a `WindowsApps` path but the executable inside is a proxy (e.g., `Photos.exe`). The AUMID is the true identity, not the proxy path.
- Admin TUI already has AppField picker in Phase 28 — adding two variants is a mechanical change.

</specifics>

<deferred>
## Deferred Ideas

- AUMID caching: Not needed — single system call per process, and clipboard monitor already caches at the identity level (intra-app copy optimization)
- Per-user UWP app variants: Some UWP apps have per-user installs under `%LOCALAPPDATA%\Microsoft\WindowsApps\`. Detection heuristic could be expanded in future but `C:\Program Files\WindowsApps\` covers the vast majority.
- UWP app capability enumeration: Not needed for DLP — we only need identity, not capabilities.
- Full MSIX package info: Could extract publisher from package manifest, but Authenticode verification already gives us publisher. Skip for simplicity.

</deferred>
