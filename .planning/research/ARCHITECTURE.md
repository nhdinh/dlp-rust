# Architecture Research — v0.10.0 Real-Time File Access Prevention

**Domain:** Windows endpoint DLP — user-mode hybrid enforcement (hook DLL + DACL + ETW)
**Researched:** 2026-05-12
**Confidence:** HIGH (architecture grounded in existing v0.9.0 code at `dlp-hook-dll/src/lib.rs`, `dlp-agent/src/hook_injector.rs`, `dlp-agent/src/hook_ipc.rs`); MEDIUM on Windows-specific edges (PPL exclusions, AppInit_DLLs reliability under Secure Boot)

---

## 1. System Overview

```
┌─────────────────────────────── ADMIN PLANE ─────────────────────────────────┐
│   dlp-admin-cli (operator workstation TUI)                                  │
│   ├─ screens/protected_paths.rs   ── CRUD T3/T4 root paths                  │
│   ├─ screens/bypass_alerts.rs     ── ETW-detected bypass feed               │
│   └─ screens/hook_health.rs       ── per-host injection coverage status     │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │ HTTPS + JWT
┌──────────────▼──────── CENTRAL CONTROL PLANE (dlp-server) ──────────────────┐
│   AppState { pool, crypto, policy_store, siem, alert, ad,                   │
│              + protected_paths_store,        ← NEW                          │
│              + bypass_alerts_store,          ← NEW                          │
│              + classification_publisher    } ← NEW                          │
│   admin_api routes:                                                         │
│     GET/POST/DELETE /admin/protected-paths/:id                              │
│     GET            /admin/bypass-alerts                                     │
│     POST           /admin/bypass-alerts/:id/ack                             │
│     GET            /agents/:id/classification-cache  (delta polling)        │
│     POST           /audit/bypass                     (agent → server)       │
│   db/repositories/protected_paths.rs  bypass_alerts.rs  classification.rs   │
└──────────────┬──────────────────────────────────────────────────────────────┘
               │ HTTPS + JWT  (existing engine_client / server_client)
┌──────────────▼─────────────── ENDPOINT PLANE ───────────────────────────────┐
│                                                                             │
│   dlp-agent (Windows Service, SYSTEM, session 0)                            │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ existing: cloud_enforcer, disk_enforcer, usb_enforcer, hook_ipc...  │   │
│   │ NEW modules under dlp-agent/src/realtime/:                          │   │
│   │   process_watcher.rs   ── ETW Microsoft-Windows-Kernel-Process       │   │
│   │   universal_injector.rs── allowlist gate + CreateRemoteThread       │   │
│   │   appinit_bootstrap.rs ── HKLM AppInit_DLLs writer + verifier       │   │
│   │   dacl_tripwire.rs     ── Deny-ACE writer for T3/T4 roots           │   │
│   │   dacl_repair_watcher.rs── ReadDirectoryChangesW(SEC_DESC_CHANGE)   │   │
│   │   etw_kernel_file.rs   ── Microsoft-Windows-Kernel-File consumer    │   │
│   │   bypass_correlator.rs ── (pid, tid, file_obj, ts) ↔ hook journal   │   │
│   │   classification_pusher.rs── pipe-broadcasts cache deltas to DLLs   │   │
│   │ hook_ipc.rs (existing): extended protocol — see §3                  │   │
│   └──────────┬───────────────────────────────────┬──────────────────────┘   │
│              │ named pipe \\.\pipe\DlpHookPipe   │ ETW real-time session     │
│              │ (per-process duplex)              │ (kernel)                  │
│              ▼                                   ▲                           │
│   ┌──────────────────────────────────────────────┴──────────────────────┐   │
│   │ dlp-hook-dll.dll  (injected into EVERY user-mode process modulo     │   │
│   │                    allowlist; both x64 and WoW64 x86 variants)      │   │
│   │  ┌─────────────────────────────────────────────────────────────┐   │   │
│   │  │ DllMain → init():                                            │   │   │
│   │  │   1. self-allowlist check (PEB image name vs hard list)      │   │   │
│   │  │   2. iat_patcher.rs       ── all-modules IAT walk            │   │   │
│   │  │   3. trampoline.rs        ── Detours-style 5-byte JMP on     │   │   │
│   │  │                              ntdll syscall stubs             │   │   │
│   │  │   4. pipe_client.rs       ── lazy connect to agent           │   │   │
│   │  │   5. classification_cache.rs── shared-memory + local         │   │   │
│   │  │   6. fail_state.rs        ── §9 state machine                │   │   │
│   │  └─────────────────────────────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Single File-Open Component Diagram (one operation)

```
[ user.exe calls WriteFile(handle, ...) ]
                    │
                    ▼
[ hook DLL: HookWriteFile trampoline in user.exe address space ]
                    │
                    ▼  (1) lookup path-from-handle, normalize NT path
[ classification_cache.get(path) ]
       │                       │
   cache miss            cache hit T3/T4
       │                       │
       │                       ▼
       │              [ DENY immediately, SetLastError(ACCESS_DENIED) ]
       ▼
[ pipe_client.send(HookRequest{path, action:WRITE, pid, tid, file_object, seq}) ]
                    │
                    │ ~ < 5 ms p99 (existing v0.9.0 benchmark)
                    ▼
[ dlp-agent hook_ipc::accept_loop → handler ]
                    │
                    ▼
[ agent runs ABAC: subject=session_identity.resolve(pid),
                   resource=classification.classify(path),
                   action=WRITE, environment=now ]
                    │
              ┌─────┴─────┐
              ▼           ▼
       agent: call POST /evaluate on dlp-server (existing engine_client.rs)
                          │
                          ▼
              [ dlp-server ABAC engine → Decision ]
                          │
                          ▼  (Decision returned over pipe)
              [ HookResponse { decision: DENY/ALLOW, cache_hint, version } ]
                          │
                          ▼
[ hook DLL: if DENY → return BOOL(0) + ERROR_ACCESS_DENIED
            if ALLOW → call original WriteFile via saved trampoline target ]
                    │
                    ▼ (2) hook journal entry recorded in DLL shared-memory
[ dlp-agent etw_kernel_file consumer simultaneously sees IRP_MJ_WRITE for same file_object ]
                    │
                    ▼
[ bypass_correlator: did journal[file_object, ts±5ms] exist?
                     NO → emit BypassAlert ]
                    │
                    ▼
[ POST /audit/bypass → server → siem + alert_router + admin_cli bypass screen ]
```

Two new files in `dlp-common/src/`:

- `dlp-common/src/realtime.rs` — `HookRequest` extended with `pid: u32, tid: u32, file_object: u64, op: FileOp`; `BypassAlert { agent_id, pid, image, path, op, ts, file_object }`; `ClassificationDelta { added: Vec<(PathBuf, Tier)>, removed: Vec<PathBuf>, version: u64 }`.
- `dlp-common/src/protected_path.rs` — `ProtectedPath { id, root, source: PolicyDerived|OperatorOverride, tier, deny_aces: Vec<AceSpec> }`.

---

## 3. Hook DLL Internal Architecture

### 3.1 Patched IAT entries + fail-closed return values

| Win32 symbol | Module | Signature suffix | Fail-closed return | Hooked because |
|---|---|---|---|---|
| `CreateFileW` | kernel32 | `... -> HANDLE` | `INVALID_HANDLE_VALUE` + `SetLastError(ERROR_ACCESS_DENIED)` | already in v0.9.0 |
| `CreateFileA` | kernel32 | `... -> HANDLE` | same | ANSI fallback |
| `CreateFile2` | kernel32 | `... -> HANDLE` | same | UWP path |
| `WriteFile` | kernel32 | `... -> BOOL` | `BOOL(0)` + `SetLastError(ERROR_ACCESS_DENIED)` | data egress on existing handle |
| `WriteFileEx` | kernel32 | `... -> BOOL` | `BOOL(0)` + same | async variant |
| `MoveFileExW` | kernel32 | `... -> BOOL` | `BOOL(0)` + same | rename-out-of-T3 |
| `CopyFileExW` | kernel32 | `... -> BOOL` | `BOOL(0)` + same | classic copy |
| `CopyFile2` | kernel32 | `... -> HRESULT` | `E_ACCESSDENIED (0x80070005)` | UWP copy |
| `DeleteFileW` | kernel32 | `... -> BOOL` | `BOOL(0)` + same | T4 destruction |
| `ReplaceFileW` | kernel32 | `... -> BOOL` | `BOOL(0)` + same | atomic swap exfil |
| `SetFileInformationByHandle` | kernel32 | `... -> BOOL` | `BOOL(0)` + same | rename via class `FileRenameInfo` |
| `NtCreateFile` | ntdll | `... -> NTSTATUS` | `STATUS_ACCESS_DENIED (0xC0000022)` | already in v0.9.0 |
| `NtOpenFile` | ntdll | `... -> NTSTATUS` | same | open-only path |
| `NtWriteFile` | ntdll | `... -> NTSTATUS` | same | direct write syscall |
| `NtSetInformationFile` | ntdll | `... -> NTSTATUS` | same | rename/disposition |
| `ZwCreateFile` etc. | ntdll | aliases | same | Zw* and Nt* share stubs |

Existing pattern in `dlp-hook-dll/src/lib.rs` (lines 100-130) walks all imports per-module via `find_iat_entry`. New `iat_patcher::patch_all_modules()` extends this to walk every loaded module's IAT (not just the host module), and re-walks on `LdrRegisterDllNotification` callback so DLLs loaded after `DLL_PROCESS_ATTACH` (typical for plugin hosts) are also patched.

### 3.2 Trampoline layout (Detours-style)

For ntdll syscall-stub patching only — IAT patching alone is bypassed by direct `Nt*` calls resolved via PEB walk.

```
ntdll!NtCreateFile (16 bytes typical stub on Win10+):
  4C 8B D1            mov  r10, rcx
  B8 55 00 00 00      mov  eax, 55h           ← SSN, OS-version dependent
  F6 04 25 ...        test byte ptr [7FFE0308h], 1
  75 03               jne  +3
  0F 05               syscall
  C3                  ret

Patched layout (5-byte JMP rel32 overlays first 5 bytes):
  E9 ?? ?? ?? ??      jmp  HookNtCreateFile      ← our trampoline target
  (remaining bytes preserved for non-Wow64 path, but trampoline below
   reconstructs them for original-call passthrough)

Allocated trampoline (one VirtualAlloc page near ntdll +/- 2GB so
rel32 reaches; use NtAllocateVirtualMemory with MEM_RESERVE on a
region within [ntdll_base - 0x7FFF_FFFF, ntdll_base + 0x7FFF_FFFF]):
  <displaced 5 bytes copied verbatim>
  E9 ?? ?? ?? ??      jmp  ntdll!NtCreateFile+5   ← resume in original
```

New module: `dlp-hook-dll/src/trampoline.rs`. Patcher must:

1. `VirtualProtect(stub, 16, PAGE_EXECUTE_READWRITE, ...)` (mirrors `patch_iat` at lib.rs:241).
2. **Atomic write** via documented Detours trick: write an 8-byte aligned word containing the JMP + first padding byte; never use a torn multi-instruction write.
3. Flush instruction cache: `FlushInstructionCache(GetCurrentProcess(), stub, 16)`.

**Race condition called out:** if thread T1 is mid-syscall stub when the patcher overwrites bytes 0-4, T1 may have already moved past byte 4 and be unaffected, but T1 at byte 0 lands on our JMP. Edge: T1 IP exactly at byte 3 mid-`mov eax, imm32` — torn read possible. Mitigation: enumerate threads via `Thread32First`, `SuspendThread`, check `GetThreadContext().Rip ∈ [stub, stub+5]`, single-step until past, then patch. This is the documented Detours suspend-all-threads-during-attach protocol.

### 3.3 Agent named-pipe discovery

**Decision:** hard-coded pipe name `\\.\pipe\DlpHookPipe` (matches existing `DEFAULT_PIPE_NAME` constant in `dlp-agent/src/hook_ipc.rs:35`). No env-var, no registry. Rationale:

- Hook DLL runs in *every* user process — registry reads at `DLL_PROCESS_ATTACH` are slow and fragile (loader-lock risk; only `kernel32.dll` is guaranteed loaded at this point).
- Env vars don't propagate to PPL/protected children.
- Single canonical pipe is a SYSTEM-owned resource secured by SDDL (existing `PipeSecurity::new` in `dlp-agent/src/ipc/pipe_security.rs`); no per-deployment customization needed.

### 3.4 Extended hook-IPC protocol

Building on the existing `HookRequest`/`HookResponse` shape in `dlp-common`:

```rust
// dlp-common/src/realtime.rs (NEW)
pub enum HookOp { Create, Open, Write, Rename, Delete, SetInfo }

pub struct HookRequest {
    pub path: String,
    pub action: String,        // legacy field — keep for v0.9.0 wire compat
    pub op: HookOp,            // NEW
    pub pid: u32,              // NEW
    pub tid: u32,              // NEW
    pub file_object: u64,      // NEW (handle value used for ETW correlation)
    pub journal_seq: u64,      // NEW (DLL-local monotonic seq for ETW correlation)
}

pub struct HookResponse {
    pub decision: Decision,
    pub reason: String,
    pub cache_hint: Option<(PathBuf, Tier, u64 /*ttl_secs*/)>,  // NEW
    pub cache_version: u64,                                     // NEW
}
```

Bincode + length-prefix framing unchanged. The `cache_hint` field lets every classification round-trip warm the DLL cache opportunistically.

A second pipe message kind (tagged enum wrapper):

```rust
pub enum HookMessage {
    Request(HookRequest),
    CacheDelta(ClassificationDelta),   // server → DLL push
    Heartbeat,
}
```

### 3.5 Local classification cache location

In the DLL only. **Chosen:** `OpenFileMappingW(L"Global\\DlpClassificationCache")` shared memory region (created and owned by agent), read-only mapped into every hooked process. Sized 2 MiB (~40k entries × 50 bytes). DLL keeps a `thread_local!` LRU of last-128 path lookups to amortize linear scans. Cache builder lives in `dlp-agent/src/realtime/classification_pusher.rs`; rebuilds atomically by double-buffering two named mappings and flipping a global atomic version word. Read-only from DLL's POV — eliminates cross-process synchronization concerns.

---

## 4. Universal Hook DLL Injection

### 4.1 Where process-creation events come from

Add `dlp-agent/src/realtime/process_watcher.rs`. **Primary mechanism is ETW**, per STACK.md finding that WMI `Win32_ProcessStartTrace` is too slow for "inject before main module runs userland code":

1. **Primary:** ETW `Microsoft-Windows-Kernel-Process` provider, `ProcessStart` event (GUID `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`, Event ID 1). Sub-millisecond latency. Same `ferrisetw` session as the Kernel-File consumer (§7).
2. **Backstop:** WMI `Win32_ProcessStartTrace` consumer via the existing `wmi` 0.14 dependency. Latency ~10-50 ms but covers cases where ETW session dropped under memory pressure.

Hooked PIDs are tracked in a `HashSet<u32>` so duplicates from both sources collapse to one injection attempt.

### 4.2 Allowlist and self-injection guard

```
boot order:
1. dlp-agent service starts as SYSTEM
2. agent reads HKLM\...\DLP\Agent\HookAllowlist  (operator-managed)
3. agent registers static self-exclusion: own PID + own image path
4. agent starts hook_ipc::HookIpcServer (existing) on \\.\pipe\DlpHookPipe
5. agent starts process_watcher; iterates EnumProcesses(); for each existing PID:
     - check allowlist (image name, signer cert subject, PPL flag)
     - inject if not excluded
6. on each new ProcessStart: same check + inject
```

Allowlist categories:

- **Self:** `dlp-agent.exe`, `dlp-user-ui.exe`, `dlp-admin-cli.exe`, `dlp-server.exe`
- **AV/EDR:** signer-cert-subject match (CrowdStrike, SentinelOne, Microsoft Defender, Sophos, Trend Micro, Cylance, ESET, Bitdefender, McAfee, Symantec, Carbon Black) — operator-extendable
- **System critical:** PIDs 0, 4, csrss, smss, wininit, services, lsass, fontdrvhost, dwm
- **Protected Process Light (PPL):** detected via `GetProcessMitigationPolicy(ProcessProtectionPolicy)` — cannot inject anyway, suppress error noise (PITFALLS CRIT-05)
- **WoW64:** detected via existing `IsWow64Process` (already in `dlp-agent/src/hook_injector.rs:172`); routes to x86 DLL path. v0.10.0 ships both `dlp_hook_dll.dll` (x64) and `dlp_hook_dll_x86.dll` (i686-pc-windows-msvc target added to workspace).

### 4.3 Primary mechanism vs AppInit_DLLs fallback

**Primary:** `CreateRemoteThread + LoadLibraryW` — already implemented in `dlp-agent/src/hook_injector.rs::HookInjector::inject_into_process` (line 210). Already handles arch dispatch, MAX_PATH check, exit-code verification.

**Fallback (lab-only on Win11):** AppInit_DLLs registry write at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` + `LoadAppInit_DLLs = 1`. Only triggers for processes linked to user32.dll (most GUI apps; misses console-only and service processes).

**Critical caveat (PITFALLS CRIT-01):** AppInit_DLLs is **disabled when Secure Boot is on**, which is required for Windows 11. AppInit_DLLs is effectively inert in target enterprise environments. Treat it purely as a tertiary backstop covering the boot-window gap. The OPS deployment guide MUST flag this prominently — Secure Boot environments rely entirely on agent-driven injection.

### 4.4 PPL / WoW64 / 32-on-64 issues

| Scenario | Behavior | Notes |
|---|---|---|
| Target is PPL (e.g., AntimalwareLight, WinTcb) | `OpenProcess(PROCESS_ALL_ACCESS)` fails with `ERROR_ACCESS_DENIED` | Suppress error; add to permanent skip set. DACL tripwire still applies to anything PPL processes touch on T3/T4. |
| Target is 32-bit on 64-bit Windows (WoW64) | `IsWow64Process` returns true; route to x86 DLL | Existing in `hook_injector.rs`; needs x86 DLL build target added |
| Anti-Cheat / EAC / BattlEye | Detect signer + image name; allowlist | These will terminate themselves on injection — refusing to inject is the friendly behavior |
| Bootstrap order — agent injecting into itself | Self-PID excluded; PEB image-path check in DllMain as belt-and-suspenders | The DLL adds an early-exit check before `init()` runs |

### 4.5 Unification with v0.9.0 cloud-sync hook DLL — DECISION

**Unify into a single DLL** (`dlp-hook-dll.dll`) — replace, not duplicate.

Rationale:

1. The v0.9.0 hook surface is already a strict subset of v0.10.0's. The same `HookCreateFileW` / `HookNtCreateFile` trampolines that v0.9.0 ships at `dlp-hook-dll/src/lib.rs:298,369` are exactly what v0.10.0 needs.
2. Two DLLs in one process → two IAT patch passes → two trampolines on the same syscall stub → invariant-breaking, hard to reason about.
3. Cloud-sync–specific filtering is a policy concern, not a hook concern. The agent's ABAC evaluator already decides. The DLL stays generic.
4. Risk of regression mitigated by: (a) cloud-sync path tests in `dlp-e2e/` remain green-bar gates; (b) v0.9.0 enforcement logic lives in `dlp-agent/src/cloud_enforcer.rs` and is policy-side — untouched by the DLL refactor.

Migration: Phase 1 of v0.10.0 expands the existing `dlp-hook-dll` crate (does not create a new crate). The crate's name and pipe name stay identical for installer-level continuity.

---

## 5. ntdll Syscall-Stub Patching

### 5.1 Where the patcher runs

**Inside the hook DLL, during `DllMain(DLL_PROCESS_ATTACH)` — same as IAT patching**. Lifecycle:

```
NtCreateUserProcess(target.exe) — kernel creates process
  → loader maps target.exe + ntdll.dll into memory
  → loader runs ntdll!_LdrpInitializeProcess
  → loader maps static imports (kernel32, ...) and walks their DllMain
  → at some point: dlp_hook_dll.dll is loaded
    [Three injection arrival paths converge here:
       (a) static import → never
       (b) AppInit_DLLs   → loaded by user32!ClientThreadSetup
       (c) CreateRemoteThread+LoadLibraryW → loaded by remote thread ]
  → DllMain(DLL_PROCESS_ATTACH) runs:
      1. self-allowlist check (PEB image name)
      2. SuspendAllOtherThreads() — see §3.2 race note
      3. iat_patcher::patch_all_modules()
      4. trampoline::patch_ntdll_syscall_stubs()
         — for each of NtCreateFile, NtOpenFile, NtWriteFile,
           NtSetInformationFile, NtReadFile (optional):
             a. GetProcAddress to locate stub
             b. allocate trampoline within ±2GB of ntdll
             c. copy displaced 5 bytes to trampoline
             d. emit JMP-back at trampoline+5
             e. atomic 8-byte write of JMP rel32 at stub
             f. FlushInstructionCache
      5. ResumeAllOtherThreads()
      6. pipe_client::lazy_connect() (deferred until first hook fires)
      7. classification_cache::map_shared_memory()
```

The agent does **not** inject a separate ntdll patcher. Single DLL, single patch point, single thing to audit.

### 5.2 Interaction with EDRs that also patch ntdll

This is the main operational risk for v0.10.0 (PITFALLS CRIT-03). Three scenarios:

1. **EDR patches first, then we load:** EDR's JMP is at byte 0 of the stub. We read those 5 bytes — they're already EDR's JMP. If we blindly copy them to our trampoline and write our own JMP at byte 0, we've broken the EDR. **Detection:** on patch, check `stub[0] == 0xE9` (JMP rel32). If so, walk the JMP target. If it lands in a known-EDR module's address range (`GetModuleHandleW` enum at startup), chain: our trampoline's JMP-back goes to the EDR's hook instead of stub+5. EDR sees the call, decides ALLOW, and resumes original syscall.
2. **We patch first, then EDR loads:** EDR's installer will overwrite our 5 bytes. Detection: hook DLL keeps a thread that re-verifies bytes 0..5 every 30s; on mismatch, raise `BypassAlert(reason=HookOverwritten)` via pipe to agent, then re-patch (chain through EDR if applicable).
3. **Both patch with non-trivial mutual chaining:** Fragile. The agent's bypass detector (§7) catches any operations that escape the user-mode hook regardless of who broke the chain. This is the entire reason ETW Kernel-File exists as the backstop.

The deployment guide (OPS-) MUST list each tested EDR with chain compatibility. Untested EDRs: documented as "may produce bypass-alert noise; coordinate with vendor or allowlist endpoint in DLP policy."

---

## 6. DACL Tripwire

### 6.1 Where the writer lives

New module `dlp-agent/src/realtime/dacl_tripwire.rs`. Runs in the agent (SYSTEM).

API uses `windows::Win32::Security::Authorization::SetNamedSecurityInfoW` with `DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION`. ACE shape:

```
ACE Type:     ACCESS_DENIED_ACE
ACE Flags:    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
Access Mask:  FILE_WRITE_DATA | FILE_APPEND_DATA |
              DELETE | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER
SID:          S-1-5-11 (Authenticated Users) — leaves SYSTEM and the
                DLP-Admin group implicitly allowed by their pre-existing
                Allow ACEs higher in the ACL.
```

ACE placed **at the top of the DACL** (canonical ACL ordering — Deny before Allow, per MS-DTYP spec). Existing allow ACEs unchanged. Read access preserved (write-deny only — read protection is policy-driven through the hook DLL, not NTFS).

### 6.2 Sourcing T3/T4 root paths

**Both** policy-derived defaults *and* operator overrides. Stored together in a new SQLite table:

```sql
CREATE TABLE protected_paths (
    id              INTEGER PRIMARY KEY,
    root            TEXT NOT NULL,                   -- normalized NT path
    tier            TEXT NOT NULL,                   -- T3 | T4
    source          TEXT NOT NULL,                   -- 'policy_derived' | 'operator'
    policy_id       INTEGER NULL REFERENCES policies(id),
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(root)
);
CREATE TABLE protected_path_aces (
    id              INTEGER PRIMARY KEY,
    protected_path_id INTEGER NOT NULL REFERENCES protected_paths(id) ON DELETE CASCADE,
    sid             TEXT NOT NULL,
    access_mask     INTEGER NOT NULL,
    ace_flags       INTEGER NOT NULL,
    UNIQUE(protected_path_id, sid, access_mask, ace_flags)
);
```

Repository: `dlp-server/src/db/repositories/protected_paths.rs`. The admin TUI Protected Paths screen renders the two `source` classes side-by-side with a visible diff.

### 6.3 Repair watcher — trigger source

**Chosen:** `ReadDirectoryChangesW` with `FILE_NOTIFY_CHANGE_SECURITY` on each root, plus a 60-second backstop poll comparing the live security descriptor against the expected one.

**Rejected:** SACL audit events — require enabling System ACL auditing globally and parsing Security event log entries; cross-machine ACL noise; permission model is hairy. Polling backstop covers cases where `ReadDirectoryChangesW` misses events (documented as best-effort).

### 6.4 Legitimate removal vs tampering

Detector cannot tell intent. All removals are tamper events by definition: any reduction of the expected ACE set is alertable.

Operators who legitimately need to remove protection use the admin TUI Protected Paths screen:
1. Marks the row `enabled=0` in `protected_paths`.
2. Pushes config delta to agent.
3. Agent removes the ACE via the same writer.
4. Repair watcher consults the in-memory `expected` map → sees ACE legitimately removed → no alert.

Out-of-band removals (someone runs `icacls` directly) surface as tamper events via SIEM and admin TUI Bypass Alerts.

**Race condition called out:** between (1) ACE removal by repair routine and (2) policy update arriving from server, operator-initiated removal can briefly trigger a tamper alert. Mitigation: policy push uses a two-phase update — server sends `protected_paths_pending_change` first, agent stages the expected-state diff, then on the next ACE event the watcher knows.

---

## 7. ETW Kernel-File Consumer

### 7.1 Where it runs

Inside dlp-agent (NOT a separate service). New module `dlp-agent/src/realtime/etw_kernel_file.rs`. Uses `ferrisetw 1.2.0` per STACK.md.

Real-time consumer subscribes to:

- Provider: `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`)
- Keywords: `KERNEL_FILE_KEYWORD_CREATE | KERNEL_FILE_KEYWORD_WRITE | KERNEL_FILE_KEYWORD_DELETE_PATH | KERNEL_FILE_KEYWORD_OP_END` — verify against current SDK
- Level: `TRACE_LEVEL_INFORMATION`

Requires `SeSystemProfilePrivilege` and being SYSTEM — agent already is. No EV cert needed.

### 7.2 Event correlation: ETW says yes-block but hook said no

Each hook invocation writes a journal entry into a per-process ring buffer (shared memory: `Global\DlpHookJournal_<pid>`, 64 KiB ring), tagged `(seq, file_object, op, path_hash, ts_qpc)`. DLL writes this *before* deciding ALLOW/DENY so even denials are journaled.

Agent's `bypass_correlator` (new module) consumes ETW events and looks up `(file_object, op)` in the matching process's journal within a ±5ms QPC timestamp window:

```
match journal.find(file_object, ts ± 5ms):
  Some(entry) if entry.op == etw.op:
      → operation was hook-visible; nothing to do.
  Some(entry) if entry.op != etw.op:
      → suspicious mismatch (rare); emit InfoLevel bypass alert.
  None:
      → SUSPECTED SYSCALL BYPASS;
        construct BypassAlert {agent_id, pid, image, path, op, ts, file_object};
        POST /audit/bypass to server.
```

Timing tolerance: 5 ms covers worst-case hook→ETW skew. Configurable, default 5 ms.

**Process exclusions:** kernel-file events from allowlisted PIDs (AV/EDR, self) are dropped before correlation.

### 7.3 Alert flow to admin TUI

```
agent.etw_kernel_file → bypass_correlator → BypassAlert
  → server POST /audit/bypass
  → bypass_alerts repository INSERT
  → siem_connector.relay() (existing pipeline)
  → alert_router.send() if policy.severity ≥ ALERT
  → admin-cli pulls via GET /admin/bypass-alerts (poll)
  → screens/bypass_alerts.rs renders list with ack/dismiss actions
```

New `bypass_alerts` table:

```sql
CREATE TABLE bypass_alerts (
    id              INTEGER PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    pid             INTEGER NOT NULL,
    image_path      TEXT NOT NULL,
    image_sha256    TEXT NULL,
    file_path       TEXT NOT NULL,
    operation       TEXT NOT NULL,                   -- Create|Write|Delete|...
    file_object     INTEGER NOT NULL,
    qpc_timestamp   INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    severity        TEXT NOT NULL,                   -- 'info'|'warn'|'crit'
    ack_by          TEXT NULL REFERENCES admin_users(username),
    ack_at          TEXT NULL,
    correlation_reason TEXT NOT NULL                 -- 'no_hook_journal'|'op_mismatch'|'hook_overwritten'
);
```

Repository: `dlp-server/src/db/repositories/bypass_alerts.rs`.

---

## 8. Local Classification Cache (freshness loop)

Shared-memory layout in §3.5. Additional freshness details:

- **Sizing:** 2 MiB shared mapping = ~40k entries × 50 bytes avg. Typical T3/T4 fileset on enterprise endpoint: ≤ 5k paths once tier-roll-up. Comfortable headroom.
- **Per-process working set cost:** shared mapping is COW — only pages actually read are committed. Real working-set cost: ≤ 64 KiB hot pages.
- **Refresh mechanism:** agent's `classification_pusher` rebuilds the second buffer, atomically flips a global `cache_version: AtomicU64`. Hooked DLLs see the new version on their next lookup. Wait-free for readers.
- **Push trigger:** on any policy edit affecting classification, on agent startup, every 5 minutes as backstop (mirrors `PolicyStore` 5-min refresh from `policy_sync.rs`).

### Staleness budget (per-tier)

| Tier | Default staleness budget | After expiry |
|---|---|---|
| T4 (Restricted) | 30 s | Fall back to fail-closed for path |
| T3 (Confidential) | 60 s | Fall back to fail-closed for path |
| T2 (Internal) | 5 min | Fall back to fail-open |
| T1 (Public) | 30 min | Fall back to fail-open |

Shared mapping carries a per-entry `ttl_bits` field; DLL stamps `cache_version_seen_at` on each successful pipe round-trip.

---

## 9. Fail-mode State Machine

DLL state when pipe goes unreachable (`pipe_client.send` returns `PipeError::ConnectionRefused | Timeout | Broken`):

```
                    ┌─────────────┐
        startup ──► │   HEALTHY   │  ◄──── pipe round-trip ok
                    └──────┬──────┘
                           │ N consecutive pipe failures (N=3, 100ms each)
                           ▼
                    ┌─────────────┐
                    │  DEGRADED   │ ── pipe round-trip ok ──► HEALTHY
                    └──────┬──────┘
                           │ M=10 consecutive failures
                           │ OR cache_version is now stale (> tier_ttl)
                           ▼
                    ┌─────────────┐
                    │  ISOLATED   │ ── pipe ok AND fresh cache delta received ──► RESYNC
                    └─────────────┘

Decision policy per state:

HEALTHY:
  cache hit T3/T4 → return cached decision (skip pipe — saves latency)
                     EXCEPT for op ∈ {Write, Delete, Rename, SetInfo} which always pipe
  cache hit T1/T2 → return ALLOW immediately
  cache miss      → pipe; on success: store result + cache hint; on fail: → DEGRADED, re-decide

DEGRADED:
  cache hit T3/T4 → DENY (cached classification authoritative for fail-closed tiers)
  cache hit T1/T2 → ALLOW
  cache miss      → conservative path lookup against shared-memory root-prefix table:
                      under T3/T4 root → DENY (fail-closed)
                      not under T3/T4 root → ALLOW (fail-open)

ISOLATED:
  cache hit T3/T4 (any age) → DENY
  cache hit T1/T2 (within max staleness 2× tier_ttl) → ALLOW
  cache hit T1/T2 stale > 2× → fall through to path-prefix rule
  cache miss      → path under T3/T4 root → DENY; else → ALLOW

RESYNC:
  agent pipe recovered AND new ClassificationDelta with monotonically greater
  cache_version delivered → reset retry counter, flush thread-local LRU,
  → HEALTHY
```

---

## 10. Admin TUI Screens

Both new screens go under `dlp-admin-cli/src/screens/`. Pattern to mirror:

- **Protected Paths screen** → mirrors `dlp-admin-cli/src/screens/usb_enforcement.rs`. Both manage a list of operator-curated roots/devices with allow/deny actions, both sync to a server table, both show source provenance (operator vs derived).
- **Bypass Alerts screen** → mirrors a hybrid of `dlp-admin-cli/src/screens/cloud_config.rs` (list-with-detail) and `dlp-admin-cli/src/screens/print_config.rs` (paginated event list with ack/dismiss). Closer to print_config because of the temporal event-stream nature.

Files:

```
dlp-admin-cli/src/screens/
├── mod.rs                  (modify: add `mod protected_paths; mod bypass_alerts;`)
├── dispatch.rs             (modify: route new screen events)
├── render.rs               (modify: add render arms for new screen variants)
├── protected_paths.rs      (NEW — list + add/remove + diff view)
└── bypass_alerts.rs        (NEW — paginated event feed + ack)
```

State enum in `dlp-admin-cli/src/app.rs` gets two new screen variants. Client extensions in `dlp-admin-cli/src/client.rs`: `list_protected_paths()`, `create_protected_path(...)`, `delete_protected_path(id)`, `list_bypass_alerts(filter)`, `ack_bypass_alert(id)`.

---

## 11. Recommended Build Order

Eight phases, ordered by dependency:

| Phase | Focus | Why this position | Depends on |
|---|---|---|---|
| **1. Hook DLL surface expansion** | Add new IAT entries (WriteFile, MoveFileEx, CopyFileEx, DeleteFile, Replace, SetInfo, NtWrite, NtSetInfo, NtOpen). Unify with v0.9.0 cloud-sync DLL. Build x86 sibling DLL. | Lowest-risk change: extends an already-shipped, well-tested pattern. Validates unification decision. | v0.9.0 baseline |
| **2. Universal injection** | `process_watcher.rs` (ETW + WMI process-start), `universal_injector.rs` with full allowlist, AppInit_DLLs fallback bootstrap, self-injection guard, WoW64 dispatch. | Without this, the wider hook surface from Phase 1 only fires on processes that v0.9.0 already injected. | Phase 1; existing `HookInjector` |
| **3. Shared-memory classification cache + fail-mode state machine** | `classification_pusher.rs` in agent, shared-memory map, DLL-side reader + LRU, full §9 state machine. Extend `HookRequest`/`HookResponse` with `cache_hint`. | Must precede ntdll patching: once direct-syscall hooks fire, fail-closed cases will hammer the pipe. Cache makes hooks survivable at scale. | Phases 1, 2 |
| **4. ntdll syscall-stub trampoline patching** | `trampoline.rs` in DLL with Detours-style 5-byte JMP, suspend-threads protocol, EDR coexistence chain detection. | Closes direct-syscall bypass. Must be after cache. | Phase 3 |
| **5. DACL tripwire writer + repair watcher** | `dacl_tripwire.rs`, `dacl_repair_watcher.rs`, `protected_paths` table + repository, server CRUD endpoints, agent pull. | Independent of hook-DLL path — can run earlier in theory, but cluster it just before UX. | Existing policy_sync |
| **6. ETW Kernel-File consumer + bypass correlator + journal ring buffer** | `etw_kernel_file.rs`, `bypass_correlator.rs`, hook-DLL journal shared-memory ring, `bypass_alerts` table, server endpoints, SIEM relay wire-up. | Requires Phase 4 (syscall hooks) to be meaningfully testing. | Phase 4 |
| **7. Admin TUI: Protected Paths + Bypass Alerts screens** | New screens, client extensions, dispatch + render integration. | UX layer; needs Phases 5 & 6 server endpoints. | Phases 5, 6 |
| **8. SD / optical / virtual drive enumeration (SEED-004)** | Extends existing `disk_enforcer.rs` device enumeration. Admin TUI: extend `usb_enforcement.rs` pattern. | Largely independent of the hook-DLL pipeline. | Existing disk_enforcer |

Phase 1 + 2 together unlock real-time blocking on the existing v0.9.0 hook surface. Phase 4 closes the syscall bypass. Phase 6 is the safety net. Phase 5 is the "even if everything else fails" backstop.

---

## 12. Changes to AppState / DB Schema / API Routes

### AppState additions (`dlp-server/src/lib.rs::AppState`)

```rust
pub struct AppState {
    pub pool: Arc<db::Pool>,
    pub crypto: Arc<crypto::SecretCrypto>,
    pub policy_store: Arc<PolicyStore>,
    pub siem: siem_connector::SiemConnector,
    pub alert: alert_router::AlertRouter,
    pub ad: Option<AdClient>,
    // NEW v0.10.0
    pub protected_paths: Arc<protected_paths_store::ProtectedPathsStore>,
    pub bypass_alerts: Arc<bypass_alerts_store::BypassAlertsStore>,
    pub classification_publisher: Arc<classification_publisher::Publisher>,
}
```

### New DB tables (with migrations under `dlp-server/src/db/`)

- `protected_paths` (§6.2)
- `protected_path_aces` (§6.2)
- `bypass_alerts` (§7.3)
- `classification_cache_entries` — server-side mirror of what's pushed to endpoints

### New repositories

- `dlp-server/src/db/repositories/protected_paths.rs`
- `dlp-server/src/db/repositories/bypass_alerts.rs`
- `dlp-server/src/db/repositories/classification_cache.rs`

### New admin API routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/protected-paths` | List |
| POST | `/admin/protected-paths` | Create operator-override entry |
| PUT | `/admin/protected-paths/:id` | Enable/disable |
| DELETE | `/admin/protected-paths/:id` | Remove operator-override |
| GET | `/admin/bypass-alerts` | Paginated feed (filters: agent_id, since, severity) |
| POST | `/admin/bypass-alerts/:id/ack` | Acknowledge |
| GET | `/agents/:id/classification-cache?since_version=N` | Agent delta polling |
| POST | `/audit/bypass` | Agent → server bypass alert ingest |

---

## 13. Race Conditions Called Out

1. **DllMain loader-lock** — defer pipe I/O and registry reads; only the PEB image-name check + shared-memory map + atomic patching happen in DllMain.
2. **Syscall stub patch in flight** — SuspendThread + GetThreadContext + verify RIP not in [stub, stub+5] for every other thread before write.
3. **Process-create race** — 10-50 ms gap between process creation and injection. DACL tripwire (Phase 5) is the always-on backstop independent of injection timing; ETW bypass correlator (Phase 6) catches what slipped.
4. **DACL repair vs operator config edit** — two-phase staged update.
5. **Cache delta version flip** — double-buffer + atomic version flip; monotonic policy.
6. **Pipe connection storm on agent restart** — exponential backoff (50ms → 200ms → 800ms → 3.2s capped) plus jitter (±20%); fail-mode state machine keeps decisions correct during storm.
7. **EDR re-patching ntdll under us** — 30s verification thread; re-patch + chain or alert.
8. **Bypass correlator timestamp skew** — 5 ms tolerance window; on sustained misses (> 100/sec), agent dials the window wider and logs at WARN.

---

## 14. Integration Points (file + function)

| Existing file | Existing symbol | Change |
|---|---|---|
| `dlp-hook-dll/src/lib.rs` | `init()` (line 90) | Extend to invoke `iat_patcher::patch_all_modules` and `trampoline::patch_ntdll_syscall_stubs` |
| `dlp-hook-dll/src/lib.rs` | `HookCreateFileW` (line 298), `HookNtCreateFile` (line 369) | Use shared-memory classification cache before pipe round-trip; emit journal entry |
| `dlp-hook-dll/src/pipe_client.rs` | `send_request` | Lazy connect; exponential reconnect backoff; pump `CacheDelta` push messages from agent |
| `dlp-agent/src/hook_injector.rs` | `HookInjector::inject` (line 86) | Called from new `universal_injector.rs` for every non-allowlisted PID |
| `dlp-agent/src/hook_ipc.rs` | `HookIpcServer::run`, `handle_connection` (line 165) | Handle new `HookMessage` variants; push CacheDelta to clients on classification updates |
| `dlp-agent/src/cloud_enforcer.rs` | existing classification logic | Becomes one of the producers feeding `classification_publisher` |
| `dlp-agent/src/main.rs` | service startup | Wire `process_watcher`, `universal_injector`, `dacl_tripwire`, `dacl_repair_watcher`, `etw_kernel_file`, `bypass_correlator`, `classification_pusher` |
| `dlp-agent/src/service.rs` | service lifecycle | Spawn the new modules on `Start`; coordinate shutdown |
| `dlp-server/src/lib.rs` | `AppState` (line 37) | Add three new Arc fields (§12) |
| `dlp-server/src/admin_api.rs` | router composition | Add eight new routes (§12) |
| `dlp-server/src/db/repositories/mod.rs` | repo exports | Add three new repository modules |
| `dlp-server/src/policy_sync.rs` | existing policy refresh | Extend to publish ClassificationDelta updates when classification-touching policies change |
| `dlp-admin-cli/src/screens/mod.rs` | screen registry | Register two new screen modules |
| `dlp-admin-cli/src/screens/dispatch.rs` | `handle_event` | Add two new screen dispatch arms |
| `dlp-admin-cli/src/screens/render.rs` | `draw` | Add two new screen render arms |
| `dlp-admin-cli/src/client.rs` | API client | Add eight new client methods |
| `dlp-admin-cli/src/app.rs` | screen state enum | Add two new variants |
| `dlp-common/src/lib.rs` | type exports | Add `realtime::{HookOp, HookMessage, ClassificationDelta, BypassAlert}` and `protected_path::ProtectedPath` |
| `Cargo.toml` (workspace) | crate set | Add x86 build target spec for `dlp-hook-dll`; add `ferrisetw 1.2.0`, `retour 0.3.1`, `moka 0.12.15` workspace deps; add `i686-pc-windows-msvc` to CI matrix |
| `installer/DLPAgent.wxs` | installer | Ship `dlp_hook_dll.dll` (x64) and `dlp_hook_dll_x86.dll` (x86); set `AppInit_DLLs` and `LoadAppInit_DLLs` registry on install; deny-write ACL on installed DLLs |

---

## 15. Sources & Confidence

- **HIGH** (existing code, all paths verified): hook DLL architecture, IAT patching pattern, pipe IPC, injector implementation, AppState shape, repository pattern — all read directly from working tree.
- **HIGH** (well-documented Windows patterns): Detours-style 5-byte JMP trampoline; `ReadDirectoryChangesW(FILE_NOTIFY_CHANGE_SECURITY)`; AppInit_DLLs Secure Boot caveat (Microsoft Learn, Windows Internals 7e).
- **MEDIUM** (operationally sensitive, needs UAT in Phase 6): ETW Kernel-File correlation tolerance (5 ms default — empirical); EDR chain compatibility (vendor-specific, must be enumerated by testing).
- **MEDIUM** (architecturally sound but novel for this codebase): shared-memory classification cache (chosen pattern, less common than HashMap-per-process but materially better for memory/freshness).
- **LOW** for any specific EDR's behavior — explicitly flagged as deployment-guide deliverable.

---

*Architecture research: 2026-05-12.*
