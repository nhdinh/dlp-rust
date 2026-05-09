# M017: v0.9.0 Cloud & Print Exfiltration Prevention

**Vision:** Close the two largest remaining exfiltration channels: cloud sync and print. Deliver true preventive controls using only user-mode APIs — API hooking for sync client processes, WFP for network defense-in-depth, and print spooler interception with XPS content extraction.

## Success Criteria

- Cloud sync folder writes are blocked before sync client sees them (T4) or allowed (T1)
- Print jobs containing T4 content are cancelled before reaching printer
- Cloud share links for T3/T4 content trigger Alert audit events
- WFP provides defense-in-depth when API hook is bypassed
- Admin CLI can view and configure cloud/print policy settings
- No regressions in existing USB/disk/clipboard interception

## Slices

- [x] **S01: S01** `risk:high` `depends:[]`
  > After this: Write a test file to a OneDrive folder — the hook blocks CreateFileW before the sync client sees it. Bypass the hook with a direct syscall → WFP catches the HTTPS upload attempt.

- [x] **S04: S04** `risk:high` `depends:[]`
  > After this: Print a document containing T4 content — job is cancelled via SetJob(..., JOB_CONTROL_DELETE) before the printer receives it. Admin CLI shows print policy status.

- [x] **S02: S02** `risk:high` `depends:[]`
  > After this: Copy a T4 file to Dropbox → blocked with user toast. Copy a T1 file → allowed. Works for all four providers (OneDrive, GDrive, Dropbox, Box).

- [x] **S03: S03** `risk:medium` `depends:[]`
  > After this: Copy a https://1drv.ms/... link to clipboard → alert emitted if the linked file is T3/T4. Sync-folder files get stricter ABAC policy applied.

- [x] **S05: S05** `risk:low` `depends:[]`
  > After this: Run full UAT: cloud upload blocked, print blocked, share link detected, all audit events flow to SIEM, admin CLI configures thresholds, TC-30..33 and TC-50..52 pass.

## Boundary Map

## Boundary Map

### S01 → S02
Produces:
- Hook DLL (`dlp_hook.dll`) — exports: `HookCreateFileW`, `HookNtCreateFile`, `UnhookAll`
- WFP filter management module — `register_filter()`, `unregister_filter()`, `add_process_block(pid)`
- Named pipe protocol — `HookRequest { path, action }` / `HookResponse { decision, reason }`
- Agent service initialization — starts hook injector + WFP filter on service start

Consumes: nothing (first slice)

### S01 → S04
Produces: nothing direct — print uses different APIs

Consumes: nothing

### S04 → S05
Produces:
- `PrintEnforcer` module — `watch_spool()`, `parse_shd()`, `parse_xps()`, `cancel_job()`
- `Action::PRINT` ABAC variant
- Admin config schema — `print_enabled`, `print_xps_timeout_ms`, `print_unclassifiable_action`
- Audit event shape for print operations

Consumes: nothing

### S02 → S03
Produces:
- Sync folder path resolver — `resolve_sync_paths() -> Vec<SyncPath>`
- `Action::CLOUD_UPLOAD` ABAC variant
- Cloud provider registry discovery module
- Stricter ABAC policy context for sync-folder files

Consumes from S01:
- Hook DLL → injection target list populated with sync paths
- Named pipe protocol → classification requests for cloud uploads

### S02 → S05
Produces: Cloud interception integration verified end-to-end

Consumes from S01: Hook framework, WFP fallback

### S03 → S05
Produces: Share link detection + stricter policy integration verified

Consumes from S02: Sync folder path resolver, stricter ABAC context
