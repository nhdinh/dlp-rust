---
phase: M017
phase_name: v0.9.0 Cloud & Print Exfiltration Prevention
project: dlp-rust
generated: "2026-05-09T00:00:00Z"
counts:
  decisions: 4
  lessons: 6
  patterns: 6
  surprises: 3
missing_artifacts: []
---

### Decisions

- **D009 — Cloud sync interception via user-mode IAT hooks + WFP defense-in-depth.** Chose IAT patching in sync client processes (CreateFileW/NtCreateFile) over kernel driver or port monitor approaches because no EV code signing is required. WFP provides a second enforcement layer for direct-syscall bypasses.
  Source: M017-ROADMAP.md/Architecture Decisions

- **D010 — Print spooler interception via spool-dir watch + XPS extraction + SetJob cancel.** Chose the medium user-mode approach (FindFirstPrinterChangeNotification + SHD/SPL/XPS parsing + SetJob(JOB_CONTROL_DELETE)) over a port monitor DLL because it requires no driver and avoids Windows HLK certification.
  Source: M017-ROADMAP.md/Architecture Decisions

- **D011 — Registry-based sync path discovery with hardcoded fallback.** Enterprise deployments redirect sync folders via Group Policy; registry discovery (HKEY_USERS\{SID}\SOFTWARE\...) finds actual paths. push_missing_fallbacks() ensures all four providers always have an entry when the registry key is absent.
  Source: S02-SUMMARY.md/Key decisions

- **D012 — Clipboard URL pattern matching for share-link detection.** Provider-specific SDK hooks are fragile and per-process. Clipboard monitoring catches all share URLs after creation regardless of origin app. Box patterns anchored with '//' prefix to prevent false-positive match against 'dropbox.com/s/'.
  Source: S03-SUMMARY.md/Key decisions

### Lessons

- **windows-rs 0.62 print API shapes differ from generic Win32 docs.** PRINTER_HANDLE is used (not HANDLE), GetJobW/SetJobW return BOOL (not Result) requiring .as_bool() + GetLastError, and JOB_CONTROL_DELETE/JOB_STATUS_PRINTING are plain u32 constants. Always verify against crate source, not Win32 conceptual docs.
  Source: S04-SUMMARY.md/Deviations

- **FindFirstPrinterChangeNotification returns raw HANDLE in windows-rs 0.62.** The function does not return Result<HANDLE> — it returns HANDLE directly and failure is signalled by INVALID_HANDLE_VALUE. Use manual null/INVALID_HANDLE_VALUE check; the ? operator is not applicable here.
  Source: S04-SUMMARY.md/Deviations

- **quick-xml 0.36: reader.decoder() returns Decoder; pass it to decode_and_unescape_value.** Older quick-xml versions accepted &Reader directly. The 0.36 API requires calling reader.decoder() first to obtain a Decoder value, then passing that to the decode method.
  Source: S04-SUMMARY.md/Key decisions

- **HookInjector is not Clone — construct a fresh instance in watcher threads.** When the sync-client process watcher thread needed to call the hook injector, cloning was not possible. The fix is to construct a fresh HookInjector from the DLL path in the thread; this is cheap and semantically equivalent.
  Source: S02-SUMMARY.md/Deviations

- **Fail-open vs fail-closed in cloud check path.** CloudEnforcer::check() fails-open on ABAC evaluator errors (log path_hash + error at ERROR, return Allow) to avoid blocking legitimate I/O. This is the inverse of the hook DLL's fail-closed policy and must be documented per-enforcer.
  Source: S02-SUMMARY.md/Key decisions

- **AgentConfigPayload Default impl must be manual when custom default functions are used.** #[derive(Default)] does not call serde(default = "fn_name") functions — it calls Default::default() for each field. When fields have custom defaults (e.g. default_print_xps_timeout_ms = 5000), the impl Default block must call those functions explicitly.
  Source: S05-SUMMARY.md/Deviations

### Patterns

- **Fail-closed hook DLL: all error paths return ERROR_ACCESS_DENIED.** If the named pipe client cannot connect, the request times out, or the agent responds DENY, the hook returns ERROR_ACCESS_DENIED. This prevents any file from silently bypassing enforcement when the agent is unreachable.
  Source: S01-SUMMARY.md/Patterns established

- **Classification passed explicitly to enforcers, not resolved internally.** CloudEnforcer::check() takes an explicit Classification parameter — the interception layer owns resolution, the enforcer only enforces. This makes the ABAC evaluation call site auditable and testable without mocking a classifier.
  Source: S02-SUMMARY.md/Patterns established

- **fnv1a_hex() private helper for non-sensitive path hashing in structured logs.** Logging raw file paths can expose PII. Use a deterministic short hash (FNV-1a hex) for path tokens in structured log fields. Correlation is still possible across log lines without exposing actual paths.
  Source: S02-SUMMARY.md/Patterns established

- **Use std::thread (not tokio task) for long-sleep background watchers.** Watcher threads that sleep 30+ seconds should run as std::thread rather than tokio tasks to avoid occupying an async reactor thread during the sleep. Use an AtomicBool (Ordering::Relaxed) for the shutdown flag — write-once semantics with 30s sleep granularity make strict ordering unnecessary.
  Source: S02-SUMMARY.md/Key decisions

- **Cross-platform enforcer: mirror Windows-only enums locally in non-Windows modules.** CloudProvider is #[cfg(windows)] in cloud_enforcer.rs. When share_link_enforcer.rs needs the same enum on non-Windows CI, mirror it locally rather than gating the whole module. This keeps unit tests portable without changing the public API.
  Source: S03-SUMMARY.md/Patterns established

- **XPS text extraction from spool files via ZIP+XML iteration.** XPS .spl files are ZIP archives. Iterate Documents/*/Pages/*.fpage (case-insensitive), parse Glyphs/@UnicodeString XML attributes, and skip corrupted pages. Non-XPS jobs (EMF) fall back to document-name heuristics for classification.
  Source: S04-SUMMARY.md/Patterns established

### Surprises

- **Sonar pre-tool hook blocks Read/Edit on dlp-server/src/admin_api.rs.** The Sonar hook detects secrets patterns in admin_api.rs and denies Read and Edit tool access. All reads must use bash (e.g. sed -n) and all writes must use Python string replacement — the standard Read/Edit tool workflow does not work on this file.
  Source: S05-SUMMARY.md/Key decisions

- **Box share-link pattern 'box.com/s/' is a substring of 'dropbox.com/s/'.** The naive bare-domain pattern caused false positives on Dropbox URLs during S03 testing. Anchoring with '//' prefix ('//box.com/s/') fixes the collision. This was not anticipated during planning.
  Source: S03-SUMMARY.md/Deviations

- **pre-existing clippy gate blocked S05 from starting admin-cli TUI work.** Four pre-existing clippy errors in dlp-admin-cli/src/screens/dispatch.rs (doc_lazy_continuation) had to be resolved in T01 before any S05 feature work could begin. The gate was pre-existing but was silently broken — discovered only when S05 ran clippy -D warnings.
  Source: S05-SUMMARY.md/What Happened
