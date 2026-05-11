# Project Research Summary

**Project:** DLP-RUST — v0.10.0 Real-Time File Access Prevention
**Domain:** Windows endpoint DLP — user-mode hybrid enforcement (universal IAT hook + ntdll trampoline + NTFS DACL tripwire + ETW Kernel-File bypass detection); no kernel driver, no EV cert
**Researched:** 2026-05-12
**Confidence:** HIGH on direction; MEDIUM on operational edges (EDR coexistence, performance under build workloads, ETW timing tolerance)

## Executive Summary

v0.10.0 converts DLP-RUST's general file I/O path from passive audit-trail into active real-time blocking by stacking four user-mode enforcement layers on the v0.9.0 baseline: a universal hook DLL (extends the proven `dlp-hook-dll` cloud-sync IAT pattern to every user process), an ntdll syscall-stub trampoline (closes the direct-syscall bypass that v0.9.0's IAT-only hooks leave open), an NTFS DACL deny-ACE tripwire on T3/T4 root paths (kernel-enforced backstop that holds even when the hook is unloaded or crashes), and an ETW `Microsoft-Windows-Kernel-File` consumer (catches operations that escape the hook and feeds a new Bypass Alerts admin TUI screen). The architecture is grounded in existing v0.9.0 code — `hook_injector.rs`, `hook_ipc.rs`, `wfp_manager.rs`, `dlp-hook-dll/src/lib.rs::patch_iat` — every new module has a working v0.9.0 analog.

The recommended approach is **agent-driven `CreateRemoteThread` as the primary injection vector** (AppInit_DLLs is silently inert under Secure Boot, which is required on Windows 11 and the default in enterprise fleets), driven by an ETW `Microsoft-Windows-Kernel-Process` ProcessStart subscription (sub-millisecond latency; WMI Win32_ProcessStartTrace is too slow). Hot-path decisions go through an in-DLL shared-memory classification cache (~2 MiB, ~40k entries, double-buffered with atomic version flip) so per-open latency stays under 50 µs p95 even when the pipe is saturated. Fail semantics are asymmetric and tier-gated: fail-closed for T3/T4, fail-open for T1/T2 (a hook DLL that always fails closed becomes a session-wide DoS the first time the agent restarts).

The dominant risks are operational, not architectural. **CRIT-06: AV/EDR vendors will treat `OpenProcess + WriteProcessMemory + CreateRemoteThread` as malware** — CrowdStrike, SentinelOne, Defender for Endpoint, Carbon Black all ship behavioural rules matching this exact pattern. Mitigation: per-vendor allowlist procedure in the deployment guide, Authenticode signing of every binary, and a startup compatibility detector that disables ntdll patching when an EDR is present. **CRIT-03: ntdll patch collision with EDR ntdll hooks** is closely related — the patcher must detect-before-patch (`stub[0] == 0xE9` means an EDR is already there), never restore "clean" bytes from disk (DoppelGate gets us classified as evasion malware), and ship the ntdll-trampoline behind a feature flag. **CRIT-04: build-workload death spiral** — `cargo build` opens 50,000 files/minute and saturates the pipe — is mitigated by an in-DLL trusted-path allowlist (System32, WinSxS, Program Files\WindowsApps), per-process host allowlist (devenv, cargo, msbuild), and a benchmark gate. **CRIT-05: PPL processes (lsass, MsMpEng, CrowdStrike) are an accepted coverage gap** — the DACL tripwire is the kernel-enforced backstop.

## Key Findings

### Recommended Stack

Additive-only over the v0.9.0 stack. All recommended crates are MIT/Apache-2.0/BSD-2 and MSRV ≤ 1.75.

**Core technologies:**
- **`retour` 0.3.1** (BSD-2, MSRV 1.60) — Detours-style inline trampolines for ntdll syscall-stub patching. Used only for ntdll stubs; the kernel32 surface stays on the existing v0.9.0 IAT-patching pattern.
- **`ferrisetw` 1.2.0** (MIT/Apache-2.0) — High-level ETW real-time consumer for `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`) and `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`). Drives both bypass detection and the ProcessStart injection trigger.
- **`moka` 0.12** sync flavour (MSRV 1.71.1) — In-DLL `path → classification` cache. Sync (not async) — the hook runs on whatever thread the host chose; no Tokio guaranteed.
- **`minhook` `=0.6.0`** (BSD-2, edition 2021, gated behind `minhook-fallback` Cargo feature) — Strict pin. Versions 0.7+ bump MSRV to 1.85 and break the workspace floor — **never bump**.
- **Raw `windows` 0.62** — `SetEntriesInAclW` / `SetNamedSecurityInfoW` for DACL tripwire writes. Rejected `windows-acl` (5-year-stale).

**What NOT to use:** AppInit_DLLs as primary injection (Secure Boot kills it); `minhook` 0.7+ (MSRV 1.85); `lru` ≥ 0.13 (MSRV 1.85); `windows-acl` (abandoned); `retour` 0.4.0-alpha (pre-release); `krabsetw`/`etw_helpers` (do not exist on crates.io); `dashmap` 7.0-rc (no TTL); any GPL crate; anything "minifilter" / "kernel hook" (PROJECT.md "What This Is Not").

### Expected Features

**Must have (table stakes):**
- Universal hook-DLL injection into every user-mode process
- Expanded IAT/inline hook surface: `CreateFileW/A`, `CreateFile2`, `NtCreateFile`, `NtOpenFile`, `WriteFile`/`WriteFileEx`, `NtWriteFile`, `MoveFileExW`, `CopyFileExW`, `CopyFile2`, `DeleteFileW`, `ReplaceFileW`, `SetFileInformationByHandle`, `NtSetInformationFile`
- ntdll syscall-stub Detours-style 5-byte JMP patching
- Per-process AV/EDR allowlist (signer-cert match for top 10 EDRs, operator-extendable)
- DACL tripwire (explicit `ACCESS_DENIED_ACE` at top of DACL on T3/T4 roots with inheritance)
- DACL repair watcher (`ReadDirectoryChangesW` with `FILE_NOTIFY_CHANGE_SECURITY` + 60s poll backstop)
- Shared-memory classification cache in the hook DLL (double-buffered with atomic version word)
- Asymmetric fail semantics (HEALTHY → DEGRADED → ISOLATED → RESYNC state machine)
- ETW Kernel-File consumer + bypass correlator (hook-DLL journal ring buffer; ±5 ms QPC tolerance)
- Admin CLI Protected Paths screen (mirrors `screens/usb_enforcement.rs`)
- Admin CLI Bypass Alerts screen (mirrors `screens/print_config.rs`)
- SIEM relay + alert router wiring for bypass events
- 19-field audit-event enrichment
- **Monitor-only / audit-only per-policy deployment mode** — every industry DLP requires this for safe production rollout
- Deployment guide: per-vendor AV/EDR allowlist procedure for top 6 EDRs
- SD/optical/virtual drive enumeration (SEED-004 fold-in)

**Should have (differentiators):**
- Diagnostic mode admin-CLI screen (full decision tree per event)
- Override-with-justification user dialog + admin TTL-bounded approval
- Scheduled enforcement windows (engine already supports)
- Block-event SHA-256 hash evidence (hash, NOT bytes)
- Hook-DLL self-health telemetry; AV/EDR coexistence dashboard

**Defer (to v0.10.1 / v1.x):** Browser extension (already deferred v1.3); inline content scanning in hook (anti-feature); real-time reclassification on write; IMAPI2 optical-burn hooking; ISO content introspection; bypass auto-remediation; DRM.

### Architecture Approach

Three-plane layout grounded in existing v0.9.0 code paths.

**Major components:**
1. **`dlp-hook-dll` (unified single DLL)** — Replaces the v0.9.0 cloud-sync DLL (not duplicated; INT-01). DllMain: self-allowlist PEB check → `iat_patcher::patch_all_modules()` → `trampoline::patch_ntdll_syscall_stubs()` (suspend-all-threads protocol) → `OpenFileMappingW(Global\DlpClassificationCache)` → lazy pipe connect. Ships x64 + x86 (`i686-pc-windows-msvc`) per WoW64 redirection.
2. **`dlp-agent` realtime subsystem** — `dlp-agent/src/realtime/`: `process_watcher.rs` (ETW + WMI), `universal_injector.rs`, `appinit_bootstrap.rs`, `dacl_tripwire.rs`, `dacl_repair_watcher.rs`, `etw_kernel_file.rs`, `bypass_correlator.rs`, `classification_pusher.rs`.
3. **`dlp-server` control plane** — `AppState` gains `protected_paths`, `bypass_alerts`, `classification_publisher` Arcs. Eight new admin API routes; three new SQLite tables.
4. **`dlp-admin-cli` TUI** — Two new screens via existing `mod.rs`/`dispatch.rs`/`render.rs`/`client.rs` pattern.

**Key patterns:** IAT-patching for kernel32, `retour::RawDetour` for ntdll; named-pipe IPC at `\\.\pipe\DlpHookPipe` (length-prefix bincode, extended protocol); two-phase staged DACL updates; hook-DLL journal ring buffer + bypass correlator with correlation-reason enum.

### Critical Pitfalls

1. **CRIT-01 — AppInit_DLLs silently disabled under Secure Boot.** Win11 requires Secure Boot. **Mitigation:** primary injection is agent-driven `CreateRemoteThread` via ETW Kernel-Process. Agent emits `siem.appinit_dlls_disabled` audit at boot. Hook DLL fires "hello" pipe message within 500 ms of attach.
2. **CRIT-02 — Hook DLL crash terminates host process.** Rust panic in `extern "system"` = UB → host abort → P0. **Mitigation:** `std::panic::catch_unwind`, fall through to original (fail-OPEN); cap `pcwstr_to_string` at 32K chars; pre-allocate pipe buffers in `init()`; replace `format!` with stack `core::fmt::Write`; SEH `__try/__except`.
3. **CRIT-03 — ntdll patch collides with EDR ntdll hooks.** **Mitigation:** detect-before-patch — `stub[0] == 0xE9` → skip + chain. NEVER restore clean ntdll bytes (DoppelGate = evasion malware). Default-off feature flag with per-customer rollout.
4. **CRIT-04 — Performance death spiral on `cargo build` (50k CreateFile/min).** **Mitigation:** in-DLL trusted-path allowlist (System32/WinSxS/WindowsApps); per-host allowlist (devenv/cargo/msbuild); benchmark gate (block-merge if overhead > 25%).
5. **CRIT-06 — AV/EDR vendors quarantine `CreateRemoteThread` as malware.** **Mitigation:** Authenticode-sign every binary (~$300/yr, does NOT require EV); per-vendor allowlist procedures (Defender Indicators, CrowdStrike ML/IOA exclusions, SentinelOne Path/Hash exclusions, Carbon Black Allow & Log, Sophos, Trend Micro); submit binaries to Microsoft `wdsi/filesubmission`; "DLP-Hook-Loader" thread-name; vendor outreach kicks off Phase 48.

Also material: CRIT-05 PPL accepted gap; MOD-01 `RequireSignedAppInit_DLLs` default-on; MOD-02 WoW64 redirection needs both DLL builds; MOD-03 canonical ACE order (subtree-walk replace-not-append); MOD-04 DACL repair TOCTOU; MOD-05 ETW event drop (256 KB×200 buffers); MOD-06 process-startup race; MOD-07 Go direct-syscall bypass; MOD-08 named-pipe storm; MOD-09 AD-DC DoS on group lookup; INT-04 audit-volume explosion.

## Implications for Roadmap

The BLOCK chain (universal injection → expanded surface → cache → ntdll patching) is the spine and longest dependency chain. **Continuous numbering: Phase 47 was last shipped, so v0.10.0 starts at Phase 48.** Eleven phases recommended; first eight are MVP-required.

### Phase 48: Hook DLL Surface Expansion + Crash Hardening + Build Harness
**Rationale:** Lowest-risk first phase — extends a proven shipped pattern. Establishes unified-DLL decision (INT-01) and Authenticode signing pipeline (MOD-01) before anything else depends on it. CRIT-02 panic-catch + SEH hardens the v0.9.0 hook path simultaneously.
**Delivers:** Expanded IAT hook list (WriteFile, MoveFileExW, CopyFileExW, DeleteFileW, ReplaceFileW, SetFileInformationByHandle, NtOpenFile, NtWriteFile, NtSetInformationFile); `catch_unwind` + SEH wrappers; 32K-char cap on wide strings; pre-allocated pipe buffer; agent self-allowlist; x86 sibling DLL with CI matrix; Authenticode signing pipeline.

### Phase 49: Universal Injection — ETW Process Watcher + Allowlist + AppInit Fallback
**Rationale:** Without this the wider hook surface only fires on processes v0.9.0 already injected. Must encode Secure Boot reality (CRIT-01) and PPL gap (CRIT-05) from day one.
**Delivers:** `process_watcher.rs` (ferrisetw on Kernel-Process Event ID 1, WMI backstop); `universal_injector.rs` (allowlist categories: self / AV-EDR signer / system-critical / PPL / WoW64-dispatched); `appinit_bootstrap.rs` tertiary fallback; startup `EnumProcesses` sweep; Secure Boot detection at agent start; hook-DLL "hello" pipe within 500 ms.

### Phase 50: Shared-Memory Classification Cache + Fail-Mode State Machine
**Rationale:** Must precede ntdll patching — once direct-syscall hooks fire, fail-closed cases hammer the pipe; cache is what makes hooks survivable (CRIT-04 mitigation). Fail-state machine is the source of truth for FAIL- semantics.
**Delivers:** `classification_pusher.rs` (double-buffered 2 MiB `Global\DlpClassificationCache`, atomic version flip); hook-DLL `classification_cache.rs` (read-only mapping + thread-local LRU); extended `HookRequest`/`HookResponse` with `pid/tid/file_object/journal_seq/op` and `cache_hint/cache_version`; `HookMessage::CacheDelta` server-to-DLL push; HEALTHY/DEGRADED/ISOLATED/RESYNC state machine; per-tier staleness budgets (T4=30s, T3=60s, T2=5min, T1=30min); in-DLL trusted-path + per-host allowlist; session-scoped AD group cache; pipe pooling with frame multiplexing; 19-field audit enrichment.

### Phase 51: ntdll Syscall-Stub Trampoline Patching + EDR-Coexistence Detection
**Rationale:** Closes direct-syscall bypass (PROJECT.md HIGH-severity debt) and Go-binary gap. Sequenced after cache. Feature-flagged default-off per CRIT-03; per-customer rollout.
**Delivers:** `trampoline.rs` (`retour::RawDetour` 5-byte JMP on `NtCreateFile/NtOpenFile/NtWriteFile/NtSetInformationFile`; suspend-all-other-threads + RIP boundary check; atomic 8-byte aligned write; `FlushInstructionCache`); 30s re-verification thread; detect-before-patch; startup EDR-process detection; `enable_ntdll_patching` policy flag (default off).
**Research flag:** **HEAVY.** ntdll stub layout varies per Windows build; validate against ≥ 3 OS builds.

### Phase 52: DACL Tripwire Writer + Repair Watcher + Protected Paths Storage
**Rationale:** Largely independent of hook spine; can land in parallel from Phase 50. Kernel-enforced backstop holds when hooks are unloaded (CRIT-02 aftermath), uninjected (CRIT-01), unreachable (CRIT-05). HARD-01 DPAPI-recovery handoff folds in as ops doc.
**Delivers:** `dacl_tripwire.rs` (`SetNamedSecurityInfoW` + `PROTECTED_DACL_SECURITY_INFORMATION`; `ACCESS_DENIED_ACE` with inheritance for `S-1-5-11`; subtree-walk replace-not-append); `dacl_repair_watcher.rs`; `protected_paths` + `protected_path_aces` SQLite tables; admin API CRUD; two-phase staged updates; 60 KB ACL guard; HARD-01 DPAPI-recovery doc folded in.

### Phase 53: ETW Kernel-File Consumer + Bypass Correlator + Hook Journal Ring
**Rationale:** Requires Phases 50+51 (journal must exist + ntdll patching must produce operations to correlate).
**Delivers:** `etw_kernel_file.rs` (Kernel-File 256 KB×200 buffers; keyword filter to CREATE/WRITE/DELETE; consumer-side System32/WinSxS drop); `bypass_correlator.rs` (±5 ms QPC tolerance); hook-DLL `Global\DlpHookJournal_<pid>` 64 KiB ring; `bypass_alerts` table + repository; `POST /audit/bypass`; SIEM + alert router wiring; lost-event subscription.
**Research flag:** Medium — empirically tune ±5 ms tolerance via `wpr.exe` on Win11.

### Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens
**Rationale:** UX layer; needs Phase 52+53 endpoints. Pure pattern reuse.
**Delivers:** `screens/protected_paths.rs` + `screens/bypass_alerts.rs`; mod/dispatch/render/app.rs extensions; eight new client methods.

### Phase 55: Monitor-Only / Audit-Only Per-Policy Enforcement Mode
**Rationale:** Every industry DLP requires safe-rollout via monitor mode. Cannot deploy v0.10.0 to production without it.
**Delivers:** `enforcement_mode: Audit | Block | AuditAndBlock` policy field; admin TUI dropdown in Conditions Builder; `policy_mode` audit field; hook DLL respects mode.

### Phase 56: SD / Optical / Virtual Drive Enumeration + Volume-Class ABAC Attribute (SEED-004)
**Rationale:** Independent of hook spine. Most enforcement is free from universal hook; the UX is the explicit work.
**Delivers:** Volume-class disambiguation (`Win32_DiskDrive` + `Win32_LogicalDisk`); `source_volume_class` + `destination_volume_class` ABAC attributes (5→7 attrs); admin TUI device-list extension; `WM_DEVICECHANGE` branch for virtual mounts; condition-builder dropdown; documented anti-features.

### Phase 57: Operational Deployment Guide + Per-Vendor AV/EDR Allowlist + UAT
**Rationale:** Vendor outreach starts in Phase 48 so reference customers exist by here. UAT folds HARD-05 informally. **This phase is the ship gate.**
**Delivers:** `docs/operations/deployment-guide.md` covering per-vendor allowlist procedures (Defender, CrowdStrike, SentinelOne, Carbon Black, Sophos, Trend Micro); pre-install hash publishing; Authenticode sign-and-timestamp; Microsoft binary submission flow; Secure Boot reality + AppInit-inert callout; SeSystemProfilePrivilege preservation; PPL coverage-gap statement; UAT plan with HARD-05 criteria; HARD-01 DPAPI-recovery reference; CRIT-04 benchmark gate.
**Research flag:** Medium — vendor allowlist UIs evolve; verify each procedure during planning.

### Phase 58: Differentiators Bundle (cut to v0.10.1 if scope pressure)
**Rationale:** None required to ship milestone goal; all materially improve deployability. Bundle as one phase for binary cut decision.
**Delivers:** Override-with-justification user dialog + admin TTL approval workflow; diagnostic-mode admin TUI screen; SHA-256 hash evidence capture (hash, NOT bytes); hook self-health telemetry; AV/EDR coexistence dashboard.

### Phase Ordering Rationale

- **Spine first, branches later.** Phases 48 → 49 → 50 → 51 form the BLOCK chain; each depends on a stability invariant from its predecessor.
- **Backstops parallel to spine.** Phase 52 (DACL) is independent and can land from Phase 50 onwards if extra hands available. Phase 53 (ETW) operationally requires Phase 51.
- **UX after server endpoints.** Phase 54 waits on 52+53.
- **Safety gate before ship gate.** Phase 55 (monitor mode) before Phase 57 (UAT in monitor mode first).
- **OPS gate at end.** Phase 57 is the final ship gate.
- **Continuous numbering preserves history.** Phase 47 shipped 2026-05-11; v0.10.0 begins at Phase 48 with no gaps.

### Research Flags

Needs research (use `/gsd-research-phase` during planning):
- **Phase 51 (ntdll trampolines):** stub layout varies per Windows build; supported-EDR matrix needs empirical validation; retour disassembler edge cases. **HEAVY.**
- **Phase 53 (ETW correlation):** ±5 ms tolerance is engineering judgment; tune empirically. **MEDIUM.**
- **Phase 57 (OPS deployment guide):** per-vendor allowlist UIs evolve. **MEDIUM.**

Standard patterns (likely skip phase research): Phases 48, 49, 50, 52, 54, 55, 56, 58.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Every crate verified against crates.io API 2026-05-12; MSRV/license/maintenance checked; Microsoft Learn cited for AppInit_DLLs and ETW GUIDs; no GPL crates; pins resist breaking-MSRV bumps. |
| Features | MEDIUM-HIGH | Table stakes convergent across Microsoft Purview / Forcepoint / Symantec / ManageEngine. Performance targets (50 µs p95 / 2 ms p99) are engineering judgment — need UAT validation in Phase 57. |
| Architecture | HIGH | Every component has a working v0.9.0 analog read directly from working tree. New shared-memory cache pattern is MEDIUM (novel for this codebase but well-trodden in Windows). |
| Pitfalls | HIGH on Microsoft-documented behaviour (AppInit/Secure Boot, PPL, ACE order, ETW buffers, WoW64); MEDIUM on vendor-specific AV/EDR procedures and EDR ntdll-coexistence (well-documented in offensive-security literature; EDR vendors don't publish hook details). |

**Overall confidence:** HIGH on direction and phase ordering; MEDIUM on operational edges needing empirical validation.

### Gaps to Address

- **EDR coexistence matrix is empirical.** Phase 51 startup detection logs `ntdll_patching: enabled/disabled-by-edr-detected` per endpoint; Phase 57 deployment guide documents matrix as it grows.
- **Hot-path latency target is engineering judgment.** Phase 50 must include hot-path benchmark before merge.
- **ETW correlation tolerance default (±5 ms).** Validate empirically in Phase 53.
- **PPL coverage gap (CRIT-05) is permanent.** Documented in deployment guide.
- **UNC-share DACL tripwire gap.** SYSTEM has no remote ACL write; local-NTFS-only.
- **Authenticode signing cert procurement timeline (~5-10 business days).** Kick off at v0.10.0 kickoff, not Phase 48 start.
- **Vendor outreach lead time.** Start at Phase 48 kickoff.

---

*Synthesis: 2026-05-12 from STACK.md, FEATURES.md, ARCHITECTURE.md, PITFALLS.md.*
