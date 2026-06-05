---
phase: 57
reviewers: [claude, opencode]
reviewed_at: 2026-06-05T10:15:00Z
plans_reviewed:
  - 57-01-PLAN.md
  - 57-02-PLAN.md
  - 57-03-PLAN.md
  - 57-04-PLAN.md
  - 57-05-PLAN.md
  - 57-06-PLAN.md
---

# Cross-AI Plan Review -- Phase 57 (Cycle 2)

## Claude Review

### Plan 01 (57-01): Master Deployment Guide Foundation

**Summary:** A well-structured foundational plan that correctly establishes the document scaffold, pre-flight checks, architecture reality documentation, and RELEASE_NOTES.md template. The addition of explicit HTML comment placeholder markers directly addresses the cycle 1 concern about deterministic replacement. The plan correctly educates operators about system limitations before they encounter vendor-specific procedures.

**Strengths:**
- Explicit `<!-- PLACEHOLDER: ...-START/END -->` markers enable deterministic content replacement by downstream plans
- Verification strengthened from generic header counting to grepping for 10 expected section titles
- Architecture Reality Check honestly documents Secure Boot inertness, PPL gaps, DACL backstop, and privilege requirements
- Pre-flight checks include exact PowerShell commands with expected outputs
- Cross-references to DEPLOYMENT.md, OPERATIONAL.md, and dpapi-recovery.md are bidirectional

**Concerns:**
- **MEDIUM:** Interface file existence checks are still mentioned in `must_haves` but no actual fallback behavior is documented in the task actions. If dpapi-recovery.md or DEPLOYMENT.md were renamed, the deployment guide would contain broken links.
- **LOW:** The `Confirm-SecureBootUEFI` command fails on legacy BIOS systems (non-UEFI). The plan mentions this command but doesn't document what the operator should do if the cmdlet throws an exception rather than returning `$false`.

**Suggestions:**
- Add explicit fallback text in the References section: "If any cross-referenced document has been moved, check `docs/` for the latest location."
- Document the BIOS vs UEFI fallback: "If `Confirm-SecureBootUEFI` throws 'Cmdlet not supported on this platform,' the system uses legacy BIOS. Secure Boot is not applicable; AppInit_DLLs may be active."

**Risk Assessment:** LOW-MEDIUM. The placeholder strategy and verification improvements resolve the primary cycle 1 concerns. Remaining risks are edge-case handling.

---

### Plan 02 (57-02): Microsoft Defender + CrowdStrike Allowlist

**Summary:** Well-researched vendor documentation with all cycle 1 fixes applied. The FalconPy example is now correctly labeled as Python with a PowerShell `Invoke-RestMethod` alternative. ASR rule guidance and Defender module prerequisites are included. The plan replaces content between explicit placeholder markers, eliminating the append-ordering ambiguity.

**Strengths:**
- FalconPy correctly labeled as Python; PowerShell alternative provided via `Invoke-RestMethod`
- Defender PowerShell module prerequisite explicitly noted for Windows Server
- ASR rule guidance addresses a real deployment foot-gun that hash indicators alone don't prevent
- 40-minute CrowdStrike propagation warning is prominently displayed
- Consistent vendor format (Console URL, Required Role, Propagation Time, Methods, Verification)

**Concerns:**
- **MEDIUM:** The `New-MpThreatIntelIndicator` PowerShell example uses `$hash = "SHA256_HASH_FROM_RELEASE_NOTES"` as a placeholder, but the plan doesn't specify how the operator obtains this hash at deployment time. If RELEASE_NOTES.md only contains placeholder text (Plan 04 populates commands, not actual hashes), the operator can't complete this step without generating the hash themselves.
- **LOW:** The ASR rule guidance mentions "Block Office applications from injecting code into other processes" but doesn't reference a specific ASR rule GUID (e.g., `d4f940ab-401b-4efc-aadc-ad5f3c50688a`). Operators navigating the Defender console may find the rule by different names across tenants.

**Suggestions:**
- Cross-reference the hash generation command from Plan 04: "Generate the SHA-256 hash using the PowerShell command documented in RELEASE_NOTES.md."
- Add ASR rule GUID for precision: "ASR Rule: d4f940ab-401b-4efc-aadc-ad5f3c50688a (Block Office applications from injecting code into other processes)."

**Risk Assessment:** LOW-MEDIUM. Cycle 1 fixes are thorough. The hash availability concern is minor since operators can generate hashes independently.

---

### Plan 03 (57-03): SentinelOne + Carbon Black + Sophos + Trend Micro

**Summary:** Comprehensive coverage of the remaining four vendors with the critical cycle 1 race condition fixed (`depends_on: [57-01, 57-02]`). The honest documentation of Sophos's hash limitation and Trend Micro's PE-only restriction is exactly what operators need. Registry and service detection robustness improvements are applied.

**Strengths:**
- Race condition resolved: Plan 03 now serializes after Plan 02
- SentinelOne registry check probes both native and WoW6432Node paths
- Carbon Black console URL uses `[REGION]` placeholder without typo
- Trend Micro service detection uses `Get-Service | Where-Object` wildcard pattern
- Sophos explicitly states "does NOT support hash-based allowlisting"

**Concerns:**
- **MEDIUM:** Plan 02 replaces content between `EDR-VENDORS-START/END` markers with Microsoft+CrowdStrike content. Plan 03 says "Append... immediately after the CrowdStrike section (between the EDR-VENDORS placeholder markers)." The insertion mechanism is not precisely specified -- an automated executor must find the exact end of the CrowdStrike section within the replaced content and insert before the `EDR-VENDORS-END` marker. This requires parsing markdown section boundaries, which is error-prone. A simpler approach would have Plan 03 also replace the entire marker content with all 6 vendors, or use sub-markers per vendor pair.
- **MEDIUM:** Carbon Black's "file must be known" requirement is documented, but the workaround ("Deploy to a test endpoint first without reputation blocking") creates a chicken-and-egg problem: the operator needs to install DLP to make the file known, but can't install DLP without the exclusion. The plan should clarify that this means deploying to a pilot endpoint with a temporary path exclusion first.
- **LOW:** The SentinelOne verification command outputs version information via `Write-Host` but doesn't programmatically validate that the version is >= 25.1.1. An operator running this manually needs to visually compare versions.

**Suggestions:**
- Use sub-placeholders within the EDR-VENDORS section (e.g., `<!-- AFTER-CROWDSTRIKE -->`) for deterministic insertion, OR have Plan 03 replace the entire EDR-VENDORS content with all 4 vendors and rely on Plans 02+03 running sequentially.
- Clarify Carbon Black workaround: "Deploy DLP to a single pilot endpoint with a temporary path exclusion (`C:\Program Files\DLP\*`), let Carbon Black observe the file, then add the hash to the Approved List."
- Add a version comparison to the SentinelOne verification: `[version]$version -ge [version]"25.1.1"`.

**Risk Assessment:** MEDIUM. The insertion precision concern is the main remaining risk. The dependency fix resolves the race condition, but the append semantics introduce a new fragility.

---

### Plan 04 (57-04): RELEASE_NOTES.md Hashes + WDSI + Authenticode

**Summary:** Solid supply chain integrity documentation with all cycle 1 fixes applied. The plan now clearly states it populates commands and templates only, not actual hash values. The WDSI email gateway warning and certificate renewal impact are included. Multi-signature output is documented as expected.

**Strengths:**
- Explicitly states "This plan populates COMMANDS and TEMPLATES only. Actual hash values are generated at release time."
- WDSI ZIP password "infected" triggers an enterprise email gateway warning
- Certificate renewal and root CA update impact documented
- `signtool verify /all /pa` multi-signature output noted as expected
- Reproducible PowerShell hash generation loop for all 6 binaries

**Concerns:**
- **MEDIUM:** The hash generation command lists `dlp_hook_dll_x86.dll` as the x86 binary, but `.github/workflows/release.yml` (referenced in Plan 01 interfaces) lists the x86 binary as `dlp_hook_dll.dll (x86)`. The naming convention should be verified against the actual build pipeline to avoid mismatch.
- **LOW:** The WDSI submission notes "Expected turnaround: 24-48 hours typical" but doesn't address what the operator should do if the release is time-sensitive and WDSI hasn't responded. A contingency note would be valuable.
- **LOW:** `signtool verify /pa` uses the default Authenticode policy, which may not include the organization's private root CA if it's not in the machine trust store. The plan documents the error message but doesn't provide the `certutil` command to install the root CA (this is only in the deployment-guide.md section, not RELEASE_NOTES.md).

**Suggestions:**
- Verify binary naming: confirm whether the x86 hook DLL is `dlp_hook_dll_x86.dll` or `dlp_hook.dll` (x86) in the actual build output.
- Add WDSI contingency: "If WDSI response exceeds 72 hours, consider deploying with path-based Defender exclusions as a temporary measure and removing the indicator after WDSI approval."
- Include the `certutil` root CA installation command in RELEASE_NOTES.md for self-containment.

**Risk Assessment:** LOW. Cycle 1 fixes are comprehensive. The binary naming concern is minor and easily verified.

---

### Plan 05 (57-05): UAT PowerShell Scripts (REVISED)

**Summary:** Excellent structural improvement from cycle 1. The overloaded ActiveBlocking script is now split into 6 focused scripts, each with a single responsibility. Custom binary dependencies are eliminated: ETW bypass uses suspend/resume, and ntdll testing verifies behavior rather than implementation details. The benchmark script gracefully handles missing Rust/cargo and runs baseline measurements first.

**Strengths:**
- 6 focused scripts each test a single capability area -- much more maintainable
- ETW bypass test uses suspend/resume instead of a custom bypass binary
- ntdll test verifies behavior (STATUS_ACCESS_DENIED) not implementation (JMP trampolines)
- Benchmark checks for `cargo` presence and skips gracefully with WARN
- CloudSync warns about clipboard destruction before testing
- Benchmark design: all baseline measurements first, then all hooked measurements -- reduces cache and warmup effects
- All scripts follow the proven Uat-UsbBlock.ps1 pattern

**Concerns:**
- **MEDIUM:** Uat-EtwNtdll.ps1's suspend/resume approach for bypass detection is timing-sensitive. The description says "suspend it before hook injection, perform the write, then resume and check alerts." On a fast system, the ETW watcher may inject the hook before the test script can suspend the process. The plan doesn't specify retry logic or a timeout for this race condition.
- **MEDIUM:** Uat-Benchmark.ps1's `Measure-OfficeLaunch` description says "Measure from process start to main window visible" but the implementation notes say "Use .NET ProcessStartInfo and WaitForInputIdle." These are contradictory -- `WaitForInputIdle` returns when the process's message loop starts, which is *before* the window is visible (especially for Click-to-Run Office). This was flagged in cycle 1 and is not fixed.
- **MEDIUM:** Uat-EtwNtdll.ps1's `Test-MonitorMode` creates a temporary policy change. If the script crashes between setting Audit mode and restoring Block mode, the system could remain in Audit mode (a security degradation). The plan mentions "Cleanup in finally block (restores policies)" which is correct, but the task description should explicitly state this requirement.
- **LOW:** Uat-HookDll.ps1's `Test-StartupSweepCoverage` claims to verify "all running non-allowlisted user processes" have the hook DLL, but the sweep may miss processes that started before the agent or processes that exit before enumeration completes. The test could produce false failures on busy systems.

**Suggestions:**
- Add retry logic to ETW bypass test: "If the bypass alert is not detected within 5 seconds, retry up to 3 times with a new process before marking FAIL."
- Fix Office launch timing: use `Win32::FindWindow` or `Get-Process | Where-Object { $_.MainWindowHandle -ne 0 }` to detect actual window visibility, not just message loop readiness.
- Explicitly state in the MonitorMode task: "The finally block MUST restore the original policy mode regardless of test result."
- Add a tolerance to StartupSweepCoverage: "Consider the test PASS if >= 90% of eligible processes have the hook DLL, rather than requiring 100%."

**Risk Assessment:** LOW-MEDIUM. The script split and elimination of custom binaries dramatically reduces risk. Timing concerns in ETW and Office launch are manageable with minor adjustments.

---

### Plan 06 (57-06): UAT Results Template + Deployment Guide Update

**Summary:** Well-structured closing plan that creates a comprehensive test matrix template and integrates it into the deployment guide. All cycle 1 fixes are applied: Group 6 (Volume Class) is marked OPTIONAL, the Actual column format guide is provided, benchmark preconditions reference the script, and the three-role sign-off table provides accountability. The plan correctly has `autonomous: false` requiring human verification.

**Strengths:**
- 30+ test cases with consistent TC-ID format across all capability areas
- Group 6 (Volume Class) explicitly marked OPTIONAL with pass criteria clarifying skipped optional tests don't block completion
- Actual column format guide: "paste error code, output snippet, or 'As expected'"
- CRIT-04 benchmark gate documented with exact 25% threshold and pass/fail criteria
- Benchmark preconditions reference the script rather than duplicating
- Sign-off table with Tester, QA Lead, Release Manager roles
- Human checkpoint for final verification

**Concerns:**
- **MEDIUM:** The UAT pass criteria say "All automated scripts exit with code 0" but scripts like Uat-Benchmark.ps1 may skip workloads (e.g., no Rust/cargo, no Office) and still exit 0. The criteria should distinguish between "exit 0 with all tests PASS" vs "exit 0 with some tests skipped." A skipped benchmark workload due to missing software should be WARN, not PASS.
- **MEDIUM:** The Prerequisites Checklist includes "Physical SD card available (optional)" and "Optical drive available (optional)" but the UAT pass criteria say optional tests don't block completion. However, the prerequisites checklist doesn't distinguish between "required for UAT" and "required only for optional tests." An operator might be confused about whether they need to source an SD card to complete UAT.
- **LOW:** Plan 06 creates `.planning/milestones/v0.10.0-UAT.md` but doesn't ensure the `.planning/milestones/` directory exists. The executor should create parent directories if needed.
- **LOW:** The test matrix references specific error codes (`ERROR_ACCESS_DENIED`, `ERROR_WRITE_PROTECT`, `STATUS_ACCESS_DENIED`) in Expected results, but the Actual column format guide doesn't explicitly encourage recording the observed error code. Adding "For denied operations: record the exact HRESULT, NTSTATUS, or Win32 error code" would improve traceability.

**Suggestions:**
- Split prerequisites checklist into "Required for UAT completion" and "Required only for optional tests" sections.
- Add to Actual column format guide: "For denied operations: record the exact HRESULT, NTSTATUS, or Win32 error code (e.g., 0x80070005 for ERROR_ACCESS_DENIED)."
- Ensure directory creation: `mkdir -p .planning/milestones/` before writing the file.
- Clarify exit code semantics: "Scripts must exit 0 AND produce no FAIL-level results. WARN-level results (e.g., skipped workloads) are acceptable for optional tests but must be documented."

**Risk Assessment:** LOW. The template is comprehensive and well-structured. Remaining concerns are cosmetic or organizational.

---

### Claude: Dependency and Ordering Analysis

| Plan | Wave | depends_on | File Target | Concern |
|------|------|-----------|-------------|---------|
| 57-01 | 1 | [] | deployment-guide.md, RELEASE_NOTES.md | Foundation -- correct |
| 57-02 | 2 | [57-01] | deployment-guide.md (EDR-VENDORS markers) | Replace between markers -- correct |
| 57-03 | 2 | [57-01, 57-02] | deployment-guide.md (append after CrowdStrike) | **Insertion precision** -- see below |
| 57-04 | 2 | [57-01] | RELEASE_NOTES.md, deployment-guide.md (HASH-PUBLISHING markers) | Replace between markers -- correct |
| 57-05 | 3 | [57-01, 57-02, 57-03, 57-04] | 6 new script files | Independent files -- correct |
| 57-06 | 3 | [57-01..57-05] | v0.10.0-UAT.md, deployment-guide.md (UAT-MATRIX markers) | Replace between markers -- correct |

**Plan 03 Insertion Precision Issue:**
Plan 02 replaces the content between `EDR-VENDORS-START` and `EDR-VENDORS-END` with Microsoft+CrowdStrike sections. Plan 03 then needs to insert SentinelOne+Carbon Black+Sophos+Trend Micro within the same marker boundaries, after the CrowdStrike section. The task description says "Append... immediately after the CrowdStrike section (between the EDR-VENDORS placeholder markers)" but doesn't specify the mechanism for finding the insertion point. An automated executor would need to parse markdown section boundaries or search for the `---` separator after CrowdStrike. **Recommendation:** Add an explicit insertion marker in Plan 02's output, e.g., `<!-- INSERT-REMAINING-VENDORS-AFTER-HERE -->`, which Plan 03 can target deterministically.

---

### Claude: Security Considerations

| Concern | Severity | Location | Mitigation |
|---------|----------|----------|------------|
| Policy restoration on crash | MEDIUM | Uat-EtwNtdll.ps1 Test-MonitorMode | Ensure finally block restores original policy mode |
| Service stopped during test | MEDIUM | Uat-DaclTripwire.ps1 | Ensure finally block restarts dlp-agent service |
| Clipboard data destruction | LOW | Uat-CloudSync.ps1 | Warning in .DESCRIPTION is sufficient |
| Path exclusions increase attack surface | MEDIUM | Sophos, CrowdStrike sections | Documented as known limitation; install path has restricted ACLs |

---

### Claude: Consensus on Cycle 1 Fix Effectiveness

| Cycle 1 Concern | Fix Applied | Resolves? | Notes |
|-----------------|-------------|-----------|-------|
| Race condition Plans 02+03 | Plan 03 now `depends_on: [57-02]` | **Yes** | Serialization eliminates concurrent writes |
| ActiveBlocking overloaded | Split into 6 focused scripts | **Yes** | Much more maintainable |
| Custom binary dependencies | ETW suspend/resume; ntdll behavior test | **Yes** | No external binaries needed |
| Missing placeholder markers | HTML comment markers in Plan 01 | **Yes** | Deterministic replacement enabled |
| FalconPy Python-in-PowerShell | Labeled as Python + Invoke-RestMethod alt | **Yes** | Both options provided |
| ASR rules missing | Added to Plan 02 Defender section | **Yes** | Addresses real deployment foot-gun |
| Defender module prerequisite | Added Windows Server note | **Yes** | Clear prerequisite |
| Carbon Black typo | Fixed to `[REGION]` placeholder | **Yes** | No typo |
| SentinelOne registry fragility | Checks both native + WoW6432Node | **Yes** | Robust across architectures |
| Trend Micro service variability | Uses `Get-Service` wildcard | **Yes** | Works across versions |
| WDSI email gateway | Added warning about "infected" password | **Yes** | Prevents delivery failure |
| Certificate renewal | Documented in both plans | **Yes** | Trust store update guidance |
| Multi-signature output | Noted as expected for dual-signed DLLs | **Yes** | Prevents operator confusion |
| Benchmark Rust skip | Checks cargo presence, skips gracefully | **Yes** | Prevents hard failure |
| Clipboard warning | Added to CloudSync .DESCRIPTION | **Yes** | Operator informed |
| Baseline-first benchmark | All baseline measurements first | **Yes** | Reduces cache effects |
| Optional test blocking | Clarified skipped optional tests don't block | **Yes** | UAT can complete without SD card |

---

### Claude: Overall Risk Assessment

**Risk Level: LOW-MEDIUM**

**Justification:** The cycle 1 fixes comprehensively addressed the three highest-severity issues:

1. **Race condition (HIGH -> RESOLVED):** Plan 03 now serializes after Plan 02, eliminating concurrent writes to deployment-guide.md.
2. **Missing test binaries (HIGH -> RESOLVED):** The suspend/resume ETW approach and behavioral ntdll testing eliminate all custom binary dependencies.
3. **Overloaded ActiveBlocking (HIGH -> RESOLVED):** Six focused scripts replace the monolithic script, dramatically reducing implementation risk.

The remaining concerns are minor:
- Plan 03's append semantics require precise insertion (MEDIUM), mitigable with an explicit sub-marker.
- Uat-Benchmark's Office launch timing uses `WaitForInputIdle` instead of true window visibility (MEDIUM), which could skew measurements for Click-to-Run Office.
- A few edge-case handling gaps (BIOS fallback, WDSI contingency, policy restoration on crash) are LOW severity.

**Recommendation:** This phase is ready for execution with two minor pre-execution tweaks:
1. Add an explicit insertion marker in Plan 02's CrowdStrike section for Plan 03 to target.
2. Fix the Office launch timing in Uat-Benchmark.ps1 to use actual window visibility detection.

With these adjustments, the phase risk drops to **LOW**.

---

## OpenCode Review

### Plan 57-01 -- Master Deployment Guide Foundation

**Summary:** Solid structural foundation. The use of deterministic placeholders and clearly defined sections sets up downstream plans well. However, validation via simple greps is too weak for something acting as a ship gate artifact.

**Strengths:**
- Clear separation of concerns: structure first, content later
- HTML comment placeholders enable deterministic patching by later plans
- "Architecture Reality Check" section aligns with critical invariant communication
- Minimal dependency surface (good for parallelism)

**Concerns:**
- **MEDIUM:** Grep-based verification is shallow; does not ensure placeholder integrity or ordering
- **MEDIUM:** No schema or contract for placeholders (risk of drift across plans)
- **LOW:** Section naming brittleness (renames break downstream replacements silently)

**Suggestions:**
- Define a strict placeholder contract (exact marker names + required count)
- Add a structural validation script (e.g., check all required markers exist exactly once)
- Include a "DO NOT EDIT BETWEEN MARKERS" comment to prevent manual corruption
- Add a version header inside the doc to detect stale generation

**Risk Assessment:** LOW-MEDIUM. Foundation is sound, but weak validation could allow silent breakage in later plans.

---

### Plan 57-02 -- Microsoft Defender + CrowdStrike Allowlist

**Summary:** High-value and realistic coverage of the two most common EDRs. The dual approach (PowerShell + API/Python) is pragmatic. However, operational correctness depends heavily on environment prerequisites and tenant-specific permissions.

**Strengths:**
- Covers multiple Defender mechanisms (hash, cert, ASR, IOC) -- good depth
- Acknowledges FalconPy vs PowerShell tradeoff
- Fits cleanly into placeholder replacement model
- Practical, operator-oriented commands

**Concerns:**
- **HIGH:** Defender features vary by SKU (Defender for Endpoint vs built-in AV); not gated or detected
- **HIGH:** CrowdStrike API requires scoped API keys + region-specific endpoints; not addressed
- **MEDIUM:** No rollback/removal instructions for allowlists
- **MEDIUM:** ASR exclusions can weaken security posture if misapplied
- **LOW:** No verification step (e.g., confirm exclusion is active)

**Suggestions:**
- Add environment detection: Defender module presence (`Get-MpPreference`), MDE onboarding state
- Explicitly document required permissions/scopes for CrowdStrike APIs
- Add verification commands after each allowlist step
- Include rollback commands (remove exclusion)
- Add warning box for ASR exclusions scope

**Risk Assessment:** MEDIUM-HIGH. Technically correct but operational fragility (permissions, SKU variance) could block deployment or create inconsistent results.

---

### Plan 57-03 -- Remaining EDR Vendors

**Summary:** Good expansion to full vendor coverage with realistic constraints per vendor. The dependency fix resolves the prior race condition. The plan correctly reflects limitations (e.g., Sophos path-only), but reliability varies significantly across vendors.

**Strengths:**
- Dependency ordering issue correctly fixed
- Vendor-specific nuances captured (Carbon Black "known file", Trend Micro PE-only)
- Honest constraints (no overpromising capabilities)
- Registry checks for SentinelOne improve robustness

**Concerns:**
- **HIGH:** Carbon Black "known file" requirement is underspecified (how to make file known?)
- **HIGH:** Sophos path-only exclusion is weak and risky; no mitigation guidance
- **MEDIUM:** SentinelOne version dependency (S-25.1.1+) not enforced or detected
- **MEDIUM:** No centralized validation across vendors
- **LOW:** Appending between markers assumes no prior corruption from Plan 02

**Suggestions:**
- For Carbon Black: Add explicit step: upload binary or wait for reputation sync
- For Sophos: Add strong warning + recommend certificate-based trust if available
- Add version detection snippets (e.g., registry/service checks per vendor)
- Add post-install validation per vendor (e.g., confirm policy applied)
- Consider a summary table comparing strength of each allowlist method

**Risk Assessment:** MEDIUM. Coverage is complete, but vendor-specific operational gaps (especially Carbon Black and Sophos) could cause deployment failure or weak protection.

---

### Plan 57-04 -- RELEASE_NOTES + Signing + WDSI

**Summary:** Covers essential release integrity and trust chain steps. The inclusion of verification commands is good, but the plan stops short of enforcing correctness or automating validation.

**Strengths:**
- Includes both SHA-256 and SHA-512 (good compliance practice)
- signtool verification commands are correct and explicit
- WDSI submission included (often missed in similar plans)
- Mentions certificate lifecycle impact

**Concerns:**
- **HIGH:** Hashes are not generated deterministically within the plan (manual step risk)
- **MEDIUM:** No check that signed binaries match published hashes
- **MEDIUM:** WDSI submission process is underspecified (portal vs API, turnaround time)
- **LOW:** No timestamping verification (`/tr` or `/td`)

**Suggestions:**
- Add a script to generate hashes and inject into RELEASE_NOTES.md
- Add verification step: Compare computed hash vs published hash
- Include timestamp verification in signtool output
- Document expected WDSI turnaround and fallback if delayed
- Add CI-friendly commands for repeatability

**Risk Assessment:** MEDIUM. Security intent is strong, but lack of automation introduces human error risk at ship gate.

---

### Plan 57-05 -- UAT PowerShell Scripts

**Summary:** The split into focused scripts is a major improvement and resolves prior overload issues. The scenarios are realistic and aligned with DLP behavior. However, reliability and reproducibility across environments remain concerns.

**Strengths:**
- Clean separation into 6 scripts -- improves debuggability
- Removal of custom binaries reduces AV/EDR friction
- Coverage aligns with real-world exfil vectors (cloud, print, USB, ETW, DACL)
- Benchmark script includes baseline-first approach

**Concerns:**
- **HIGH:** Auto-detection (cloud clients, printers) may be unreliable across environments
- **HIGH:** No standardized output format (hard to aggregate results)
- **MEDIUM:** ETW/ntdll behavioral tests may produce inconsistent results across Windows builds
- **MEDIUM:** Benchmark variability (no CPU/memory normalization)
- **LOW:** No retry or timeout handling

**Suggestions:**
- Standardize output: JSON or structured logs for each script
- Add explicit success/failure criteria per test
- Add environment checks (e.g., installed apps, permissions)
- For benchmark: Pin CPU affinity or document variability expectations
- Add a master orchestrator script to run all tests and collect results

**Risk Assessment:** MEDIUM-HIGH. Functional coverage is strong, but lack of determinism and structured output could make UAT results hard to trust.

---

### Plan 57-06 -- UAT Results Template + Guide Update

**Summary:** Provides necessary structure for sign-off and aligns with ship gate expectations. The inclusion of CRIT-04 benchmark gating is correct. However, integration with actual test execution is weak.

**Strengths:**
- Clear grouping and coverage (30+ test cases)
- Explicit sign-off roles (good governance)
- CRIT-04 threshold defined (<=25%)
- Optional group clearly marked

**Concerns:**
- **HIGH:** No enforced linkage between scripts (57-05) and template (manual transcription risk)
- **MEDIUM:** No pass/fail aggregation logic
- **MEDIUM:** Optional group could be skipped without justification tracking
- **LOW:** No audit trail or timestamping

**Suggestions:**
- Auto-populate template from script outputs (tie to structured logs from 57-05)
- Add a summary section: Total tests, pass rate, blockers
- Require justification field for skipped optional tests
- Add timestamps and environment metadata (OS version, EDR present)
- Consider a "go/no-go" computed field

**Risk Assessment:** MEDIUM. Good structure, but manual processes weaken reliability at the final ship gate.

---

### OpenCode: Overall Assessment

**Summary:** Cycle 1 fixes meaningfully improved the plan set -- especially resolving the dependency race and decomposing UAT into manageable scripts. The architecture is now coherent and executable. The main remaining risk is not design correctness but **operational reliability and determinism** across diverse Windows + EDR environments.

**Key Cross-Plan Risks:**
- HIGH: Lack of end-to-end automation (hashes, allowlists, UAT results)
- HIGH: Environment variability (EDR versions, permissions, Windows builds)
- MEDIUM: Weak validation (greps, manual checks)
- MEDIUM: Missing rollback/verification steps in multiple plans

**Final Risk Level: MEDIUM-HIGH**

The plans are **functionally complete and aligned with goals**, but as a *ship gate*, they rely too much on manual correctness. Tightening validation, automation, and environment detection would bring this down to LOW risk.

---

## Consensus Summary

### Agreed Strengths
- Both reviewers confirm cycle 1 race condition is fixed (Plan 03 depends_on: [57-01, 57-02])
- Both reviewers confirm ActiveBlocking split into 6 scripts resolves overload issues
- Both reviewers confirm custom binary dependencies are eliminated
- Both reviewers praise placeholder markers and deterministic replacement strategy
- Both reviewers acknowledge honest vendor limitation documentation (Sophos no hash, Trend Micro PE-only)
- Both reviewers find the test matrix structure and sign-off table appropriate for a ship gate

### Agreed Concerns (Highest Priority)

1. **HIGH/MEDIUM -- Plan 03 insertion precision**: Claude flags that Plan 03's "append after CrowdStrike" semantics are imprecise for automated execution. OpenCode notes "appending between markers assumes no prior corruption from Plan 02." Both agree the dependency fix is correct but the insertion mechanism needs refinement.

2. **HIGH -- Environment variability and operational fragility**: OpenCode rates this HIGH (Defender SKU variance, CrowdStrike API permissions, auto-detection reliability). Claude rates this MEDIUM-LOW, noting the documentation is correct but operators may encounter tenant-specific issues.

3. **MEDIUM -- Weak validation and lack of automation**: Both reviewers note grep-based verification is shallow. OpenCode calls for structural validation scripts and automation. Claude notes the verification improvements from cycle 1 are adequate but not exhaustive.

4. **MEDIUM -- UAT determinism and structured output**: OpenCode flags lack of standardized output format and master orchestrator. Claude flags timing sensitivity in ETW bypass test and Office launch measurement inaccuracy.

5. **MEDIUM -- Carbon Black "known file" chicken-and-egg**: Claude specifically flags this as a deployment foot-gun. OpenCode also flags it as underspecified.

### Divergent Views

- **Overall risk level**: Claude rates LOW-MEDIUM (ready for execution with minor tweaks). OpenCode rates MEDIUM-HIGH (operational reliability concerns across heterogeneous environments).
- **Defender SKU variance**: OpenCode calls this HIGH; Claude does not mention it.
- **CrowdStrike API permissions**: OpenCode calls this HIGH; Claude considers it addressed by the documented required roles.
- **Hash automation**: OpenCode calls manual hash generation HIGH risk; Claude considers it LOW since operators can generate hashes independently.
- **UAT output format**: OpenCode wants JSON/structured logs and master orchestrator; Claude focuses on individual script correctness.
- **Office launch timing**: Claude specifically flags WaitForInputIdle vs window visibility (cycle 1 carryover); OpenCode does not mention this.

### Cycle 1 Fix Effectiveness (Both Reviewers Agree)

| Cycle 1 Concern | Status |
|-----------------|--------|
| Race condition Plans 02+03 | **FULLY RESOLVED** |
| ActiveBlocking overloaded | **FULLY RESOLVED** |
| Custom binary dependencies | **FULLY RESOLVED** |
| Missing placeholder markers | **FULLY RESOLVED** |
| FalconPy Python/PowerShell | **FULLY RESOLVED** |
| ASR rules missing | **FULLY RESOLVED** |
| Defender module prerequisite | **FULLY RESOLVED** |
| Carbon Black typo | **FULLY RESOLVED** |
| SentinelOne registry fragility | **FULLY RESOLVED** |
| Trend Micro service variability | **FULLY RESOLVED** |
| WDSI email gateway | **FULLY RESOLVED** |
| Certificate renewal | **FULLY RESOLVED** |
| Multi-signature output | **FULLY RESOLVED** |
| Benchmark Rust skip | **FULLY RESOLVED** |
| Clipboard warning | **FULLY RESOLVED** |
| Baseline-first benchmark | **FULLY RESOLVED** |
| Optional test blocking | **FULLY RESOLVED** |

### New Concerns Raised in Cycle 2

| Concern | Severity | Plan | Description |
|---------|----------|------|-------------|
| Plan 03 insertion precision | MEDIUM | 57-03 | Append semantics after CrowdStrike section are imprecise for automated execution |
| Defender SKU variance | HIGH | 57-02 | Defender for Endpoint vs built-in AV feature differences not gated |
| CrowdStrike API permissions | HIGH | 57-02 | API key scopes and region-specific endpoints not addressed |
| Carbon Black known-file workaround | MEDIUM | 57-03 | Chicken-and-egg deployment problem needs clearer pilot endpoint guidance |
| ETW bypass timing race | MEDIUM | 57-05 | Suspend/resume approach may miss injection window on fast systems |
| Office launch timing accuracy | MEDIUM | 57-05 | WaitForInputIdle != window visibility for Click-to-Run Office |
| UAT output standardization | MEDIUM | 57-05, 57-06 | No structured output format or master orchestrator |
| Policy restoration on crash | MEDIUM | 57-05 | MonitorMode test must restore policy in finally block |
| Manual hash generation risk | MEDIUM | 57-04 | Lack of automation introduces human error at ship gate |
| Prerequisites checklist clarity | LOW | 57-06 | Optional vs required prerequisites not visually distinguished |

---

## Recommendations for Cycle 3 (if needed)

1. **Add insertion marker in Plan 02**: Include `<!-- INSERT-REMAINING-VENDORS-AFTER-HERE -->` at end of CrowdStrike section for Plan 03 to target deterministically.
2. **Add Defender SKU detection note**: Document that `Get-MpComputerStatus` can verify MDE onboarding state before attempting hash indicators.
3. **Fix Office launch timing**: Use `FindWindow` or `MainWindowHandle` detection instead of `WaitForInputIdle`.
4. **Add ETW bypass retry logic**: Specify 3 retries with new processes if bypass alert not detected within 5 seconds.
5. **Clarify Carbon Black pilot flow**: Explicitly state "deploy to pilot endpoint with temporary path exclusion first."
6. **Distinguish optional prerequisites**: Visually separate required vs optional prerequisites in the UAT checklist.
7. **Explicit policy restoration requirement**: State in Plan 05 MonitorMode task that finally block MUST restore original policy mode.

With these 7 tweaks, the phase would achieve consensus LOW risk and be ready for execution.
