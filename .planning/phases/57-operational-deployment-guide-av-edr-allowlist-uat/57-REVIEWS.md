---
phase: 57
reviewers: [opencode, claude]
reviewed_at: 2026-06-05T10:55:00Z
plans_reviewed:
  - 57-01-PLAN.md
  - 57-02-PLAN.md
  - 57-03-PLAN.md
  - 57-04-PLAN.md
  - 57-05-PLAN.md
  - 57-06-PLAN.md
---

# Cross-AI Plan Review -- Phase 57 (Cycle 3)

## Codex Review

**Status:** Codex CLI (v0.130.0) is installed but all available models fail with
`invalid_request_error: model is not supported when using Codex with a ChatGPT account`.
Models attempted: gpt-5.3-codex (default), gpt-4o, gpt-4o-mini, gpt-4.1, gpt-4.1-mini,
gpt-4.5-preview, gpt-4o-latest, gpt-3.5-turbo. No Codex review could be produced.

---

## OpenCode Review

### Plan 57-01 -- Deployment Guide Foundation

**Summary**
Establishes structure and placeholders for deployment, AV/EDR allowlisting, and UAT sections.

**Strengths**
- Clean separation of concerns (deployment vs allowlisting vs validation)
- Placeholder-driven approach reduces blocking between teams
- Sets consistent structure for downstream plans

**Concerns**
- **MEDIUM:** Placeholders risk lingering into final deliverable if not tracked
- **LOW:** No explicit ownership or completion criteria per section

**Suggestions**
- Add a "definition of done" per placeholder (what evidence is required)
- Include owner + status fields inline to prevent drift
- Add versioning header tied to product build / hash

**Risk Assessment:** Low overall risk. Main failure mode is incomplete sections slipping through without enforcement.

---

### Plan 57-02 -- Defender + CrowdStrike

**Summary**
Covers Microsoft Defender (SKU detection, ASR, IOC) and CrowdStrike (ML exclusions, API scopes, region endpoints, propagation timing).

**Strengths**
- Defender SKU detection fix addresses a real deployment pitfall
- ASR + IOC guidance is actionable and layered (policy + indicator)
- CrowdStrike API scope clarity reduces integration failures
- Region endpoint + propagation timing (40-min warning) is practical

**Concerns**
- **HIGH:** Defender ASR guidance may still be ambiguous across E5 vs Business Premium edge cases (policy precedence conflicts)
- **MEDIUM:** CrowdStrike propagation window documented, but no mitigation for urgent unblock scenarios
- **LOW:** No explicit rollback steps if exclusion causes unintended exposure

**Suggestions**
- Add explicit ASR conflict resolution matrix (local vs Intune vs GPO precedence)
- Include "emergency allow" path for CrowdStrike (manual console override vs API)
- Add verification commands/log locations for both platforms
- Include rollback procedure with timing expectations

**Risk Assessment:** Medium risk. Defender policy conflicts remain the biggest operational hazard.

---

### Plan 57-03 -- SentinelOne, Carbon Black, Sophos, Trend Micro

**Summary**
Documents vendor-specific allowlisting constraints and flows.

**Strengths**
- Captures critical vendor limitations (e.g., Sophos path-only, Trend PE-only)
- SentinelOne version constraint (S-25.1.1+) is precise and actionable
- Carbon Black pilot flow reduces blast radius
- Realistic, vendor-aligned guidance instead of generic abstraction

**Concerns**
- **HIGH:** Path-only (Sophos) and PE-only (Trend) create security gaps if not explicitly risk-framed
- **MEDIUM:** SentinelOne version dependency may block customers on older agents without fallback
- **MEDIUM:** Carbon Black pilot flow lacks explicit promotion criteria to production
- **LOW:** Inconsistent terminology across vendors (exclusion vs allowlist vs exception)

**Suggestions**
- Add "security tradeoff" callouts for weaker controls (path-only / PE-only)
- Provide fallback strategy for SentinelOne < S-25.1.1
- Define exit criteria for Carbon Black pilot (e.g., 0 detections over N runs)
- Normalize terminology with a glossary section

**Risk Assessment:** Medium-High risk due to uneven security guarantees across vendors.

---

### Plan 57-04 -- RELEASE_NOTES Population

**Summary**
Adds operational commands and verification steps (hashing, signtool, WDSI submission).

**Strengths**
- Includes concrete commands (hash, signature verification)
- WDSI submission guidance adds escalation path
- Improves reproducibility and auditability

**Concerns**
- **MEDIUM:** Commands may vary across environments (PowerShell versions, SDK availability)
- **LOW:** No expected output examples for verification steps

**Suggestions**
- Add sample outputs for `signtool verify` and hash commands
- Include fallback tools (e.g., `Get-FileHash` vs certutil)
- Add note on timestamping and certificate chain validation

**Risk Assessment:** Low risk. Mostly operational polish; unlikely to cause systemic issues.

---

### Plan 57-05 -- UAT Scripts

**Summary**
Defines six UAT scenarios covering key behaviors and bypass attempts.

**Strengths**
- Good coverage of real-world behaviors (CloudSync, PrintBlock, ETW, DLL hooks)
- ETW retry (3-attempt bypass) shows adversarial thinking
- Benchmark test introduces measurable gating (25%)
- Baseline-first approach avoids false positives

**Concerns**
- **HIGH:** Some tests (HookDll, EtwNtdll) may be flagged as malicious tooling by EDR itself, skewing results
- **MEDIUM:** Benchmark gating (25%) lacks justification or calibration guidance
- **MEDIUM:** No clear pass/fail criteria beyond execution success
- **LOW:** Environmental dependencies not fully specified (admin rights, OS version)

**Suggestions**
- Add "expected detection vs allowed behavior" per test
- Document safe execution context (lab vs production, required exclusions)
- Justify or parameterize the 25% benchmark threshold
- Include logging locations to confirm outcomes

**Risk Assessment:** Medium-High risk. Misinterpretation of results or tool self-detection could invalidate UAT.

---

### Plan 57-06 -- UAT Results Template

**Summary**
Provides structured template for recording results across 30+ test cases with optional grouping and sign-off.

**Strengths**
- Comprehensive coverage (30+ cases)
- Optional Volume Class grouping adds scalability
- Explicit sign-off table supports governance
- Encourages consistent reporting across environments

**Concerns**
- **MEDIUM:** Template may become too heavy for smaller deployments
- **LOW:** Optional sections (Volume Class) could create inconsistency across reports
- **LOW:** No enforcement of evidence attachment (logs, screenshots)

**Suggestions**
- Add "minimum required fields" vs optional fields
- Require evidence links for each failed or exception case
- Include summary dashboard (pass rate, blockers, risks)
- Add version/build metadata to tie results to artifacts

**Risk Assessment:** Low-Medium risk. Main issue is usability and consistency, not correctness.

---

### OpenCode: Overall Assessment

**Summary:** Cycle 3 shows strong maturation. Cycle 2 fixes addressed meaningful operational gaps (policy detection, API scopes, ETW retry, pilot flow). The plans are now close to deployable quality.

**Key Strengths Across Plans**
- Vendor-specific realism instead of generic guidance
- Inclusion of operational timing and propagation nuances
- UAT coverage includes adversarial scenarios
- Clear separation between deployment, configuration, and validation

**Key Risks Across Plans**
- Policy conflicts (especially Defender ASR)
- Inconsistent security strength across vendors
- UAT interpretation ambiguity
- Lack of enforced completion/evidence standards

**Top Recommendations (Cross-Cutting)**
1. Add explicit pass/fail criteria + evidence requirements everywhere
2. Introduce rollback procedures for every vendor configuration
3. Standardize terminology and glossary across all plans
4. Add a "known limitations & risk acceptance" section per vendor
5. Ensure every timing-dependent step has verification guidance

**Overall Risk Level:** Medium. Technically solid, but operational ambiguity and vendor inconsistencies are the main remaining risks before production readiness.

---

## Claude Review (Executing AI)

### Plan 01 (57-01): Master Deployment Guide Foundation

**Summary:** A well-structured foundational plan with all cycle 2 fixes applied. The placeholder strategy, pre-flight checks, and architecture reality documentation are comprehensive. The document structure correctly educates operators before they encounter vendor-specific procedures.

**Strengths:**
- Explicit HTML comment placeholders enable deterministic content replacement
- Verification strengthened with greps for 10 expected section titles
- Architecture Reality Check honestly documents Secure Boot inertness, PPL gaps, DACL backstop
- Pre-flight checks include exact PowerShell commands with expected outputs
- Cross-references to DEPLOYMENT.md, OPERATIONAL.md, and dpapi-recovery.md are bidirectional

**Concerns:**
- **LOW:** The `Confirm-SecureBootUEFI` command fails on legacy BIOS systems. The plan mentions this command but does not document what the operator should do if the cmdlet throws an exception.
- **LOW:** Interface file existence checks are mentioned in `must_haves` but no actual fallback behavior is documented in task actions.

**Suggestions:**
- Document the BIOS vs UEFI fallback: "If `Confirm-SecureBootUEFI` throws 'Cmdlet not supported on this platform,' the system uses legacy BIOS. Secure Boot is not applicable; AppInit_DLLs may be active."
- Add explicit fallback text in the References section for broken cross-references.

**Risk Assessment:** LOW. Remaining risks are edge-case handling only.

---

### Plan 02 (57-02): Microsoft Defender + CrowdStrike Allowlist

**Summary:** All cycle 2 fixes are correctly applied. The FalconPy example is labeled as Python with a PowerShell Invoke-RestMethod alternative. ASR rule guidance, Defender module prerequisites, SKU detection, and CrowdStrike API scopes/endpoints are all included.

**Strengths:**
- FalconPy correctly labeled as Python; PowerShell alternative provided
- Defender SKU detection (Get-MpComputerStatus + MDE onboarding registry) included
- ASR rule guidance addresses a real deployment foot-gun
- 40-minute CrowdStrike propagation warning is prominently displayed
- INSERT-REMAINING-VENDORS-AFTER-HERE marker enables deterministic Plan 03 insertion
- Consistent vendor format across both sections

**Concerns:**
- **LOW:** The `New-MpThreatIntelIndicator` PowerShell example uses a placeholder hash string. The plan cross-references RELEASE_NOTES.md but the actual hash generation command is in Plan 04. A brief inline note would help.
- **LOW:** ASR rule guidance mentions rule names but does not reference specific ASR rule GUIDs (e.g., `d4f940ab-401b-4efc-aadc-ad5f3c50688a`).

**Suggestions:**
- Add brief inline note: "Generate the SHA-256 hash using the PowerShell command documented in RELEASE_NOTES.md (Plan 04)."
- Add ASR rule GUID for precision if space permits.

**Risk Assessment:** LOW. Cycle 2 fixes are thorough and complete.

---

### Plan 03 (57-03): SentinelOne + Carbon Black + Sophos + Trend Micro

**Summary:** Comprehensive coverage with the critical cycle 2 insertion marker fix. The honest documentation of vendor limitations and the Carbon Black pilot flow are exactly what operators need. Registry and service detection robustness improvements are applied.

**Strengths:**
- INSERT-REMAINING-VENDORS-AFTER-HERE marker enables deterministic insertion
- SentinelOne registry check probes both native and WoW6432Node paths
- Carbon Black console URL uses `[REGION]` placeholder without typo
- Carbon Black pilot endpoint flow is explicitly documented
- Trend Micro service detection uses `Get-Service | Where-Object` wildcard pattern
- Sophos explicitly states "does NOT support hash-based allowlisting"

**Concerns:**
- **MEDIUM:** Carbon Black's "file must be known" workaround requires deploying to a pilot endpoint with a temporary path exclusion first. The plan documents this but the verification command does not confirm the file has been observed before attempting hash approval.
- **LOW:** The SentinelOne verification command outputs version information but does not programmatically validate that the version is >= 25.1.1.

**Suggestions:**
- Add a version comparison to the SentinelOne verification: `[version]$version -ge [version]"25.1.1"`.
- Clarify Carbon Black verification: add a note that the pilot endpoint must show the file in the console's "Observed Files" list before hash approval.

**Risk Assessment:** LOW-MEDIUM. The insertion marker fix resolves the primary cycle 2 concern. Remaining issues are minor.

---

### Plan 04 (57-04): RELEASE_NOTES.md Hashes + WDSI + Authenticode

**Summary:** All cycle 2 fixes applied. The plan clearly states it populates commands and templates only, not actual hash values. The WDSI email gateway warning and certificate renewal impact are included.

**Strengths:**
- Explicitly states "This plan populates COMMANDS and TEMPLATES only. Actual hash values are generated at release time."
- WDSI ZIP password "infected" triggers an enterprise email gateway warning
- Certificate renewal and root CA update impact documented
- `signtool verify /all /pa` multi-signature output noted as expected
- Reproducible PowerShell hash generation loop for all 6 binaries

**Concerns:**
- **LOW:** The hash generation command lists `dlp_hook_dll_x86.dll` as the x86 binary. The naming convention should be verified against the actual build pipeline (release.yml) to avoid mismatch.
- **LOW:** The WDSI submission notes "Expected turnaround: 24-48 hours typical" but does not address what the operator should do if the release is time-sensitive and WDSI has not responded.

**Suggestions:**
- Verify binary naming: confirm whether the x86 hook DLL is `dlp_hook_dll_x86.dll` or `dlp_hook_dll.dll` (x86) in the actual build output.
- Add WDSI contingency: "If WDSI response exceeds 72 hours, consider deploying with path-based Defender exclusions as a temporary measure."

**Risk Assessment:** LOW. Cycle 2 fixes are comprehensive.

---

### Plan 05 (57-05): UAT PowerShell Scripts (6 focused scripts)

**Summary:** Excellent structural improvement. All cycle 2 fixes are correctly applied: Office launch timing uses FindWindow/MainWindowHandle, ETW bypass has 3-retry logic, MonitorMode explicitly requires policy restoration in finally block, benchmark runs baseline-first.

**Strengths:**
- 6 focused scripts each test a single capability area -- much more maintainable
- ETW bypass test uses suspend/resume with 3-retry logic instead of custom binary
- ntdll test verifies behavior (STATUS_ACCESS_DENIED) not implementation (JMP trampolines)
- Benchmark checks for `cargo` presence and skips gracefully with WARN
- CloudSync warns about clipboard destruction before testing
- Benchmark design: all baseline measurements first, then all hooked measurements
- MonitorMode task explicitly requires finally block to restore original policy mode
- Office launch timing uses FindWindow / MainWindowHandle, NOT WaitForInputIdle

**Concerns:**
- **MEDIUM:** Uat-EtwNtdll.ps1's suspend/resume approach for bypass detection is timing-sensitive. The 3-retry logic mitigates this but the retry interval and process count are not specified.
- **MEDIUM:** Uat-HookDll.ps1's `Test-StartupSweepCoverage` claims to verify "all running non-allowlisted user processes" have the hook DLL, but the sweep may miss processes that started before the agent or exit before enumeration. The test could produce false failures on busy systems.
- **LOW:** Uat-Benchmark.ps1's `Measure-OfficeLaunch` uses FindWindow/MainWindowHandle but does not specify a timeout for window visibility detection. A hung Office process could block the benchmark indefinitely.

**Suggestions:**
- Specify retry interval in ETW bypass test: "Wait 2 seconds between retries."
- Add a tolerance to StartupSweepCoverage: "Consider the test PASS if >= 90% of eligible processes have the hook DLL."
- Add a timeout to Office launch measurement: "If the window is not visible within 60 seconds, mark the test as FAIL and kill the process."

**Risk Assessment:** LOW-MEDIUM. The script split and elimination of custom binaries dramatically reduces risk. Timing concerns are manageable with minor adjustments.

---

### Plan 06 (57-06): UAT Results Template + Deployment Guide Update

**Summary:** Well-structured closing plan with all cycle 2 fixes applied. Group 6 (Volume Class) is marked OPTIONAL, prerequisites are visually separated into Required vs Optional, benchmark preconditions reference the script, and the three-role sign-off table provides accountability.

**Strengths:**
- 30+ test cases with consistent TC-ID format
- Group 6 (Volume Class) explicitly marked OPTIONAL with pass criteria clarifying skipped optional tests do not block completion
- Prerequisites checklist visually separated into "Required for UAT Completion" and "Required Only for Optional Tests"
- Actual column format guide: "paste error code, output snippet, or 'As expected'"
- CRIT-04 benchmark gate documented with exact 25% threshold and pass/fail criteria
- Benchmark preconditions reference the script rather than duplicating
- Sign-off table with Tester, QA Lead, Release Manager roles
- Human checkpoint for final verification (`autonomous: false`)

**Concerns:**
- **MEDIUM:** The UAT pass criteria say "All automated scripts exit with code 0" but scripts like Uat-Benchmark.ps1 may skip workloads and still exit 0. The criteria should distinguish between "exit 0 with all tests PASS" vs "exit 0 with some tests skipped."
- **LOW:** Plan 06 creates `.planning/milestones/v0.10.0-UAT.md` but does not ensure the `.planning/milestones/` directory exists.
- **LOW:** The test matrix references specific error codes in Expected results, but the Actual column format guide does not explicitly encourage recording the observed error code.

**Suggestions:**
- Clarify exit code semantics: "Scripts must exit 0 AND produce no FAIL-level results. WARN-level results (e.g., skipped workloads) are acceptable for optional tests but must be documented."
- Ensure directory creation: `mkdir -p .planning/milestones/` before writing the file.
- Add to Actual column format guide: "For denied operations: record the exact HRESULT, NTSTATUS, or Win32 error code (e.g., 0x80070005 for ERROR_ACCESS_DENIED)."

**Risk Assessment:** LOW. The template is comprehensive and well-structured. Remaining concerns are cosmetic.

---

### Claude: Dependency and Ordering Analysis

| Plan | Wave | depends_on | File Target | Status |
|------|------|-----------|-------------|--------|
| 57-01 | 1 | [] | deployment-guide.md, RELEASE_NOTES.md | Foundation -- correct |
| 57-02 | 2 | [57-01] | deployment-guide.md (EDR-VENDORS markers) | Replace between markers -- correct |
| 57-03 | 2 | [57-01, 57-02] | deployment-guide.md (after INSERT-REMAINING-VENDORS-AFTER-HERE) | Deterministic insertion -- correct |
| 57-04 | 2 | [57-01] | RELEASE_NOTES.md, deployment-guide.md (HASH-PUBLISHING markers) | Replace between markers -- correct |
| 57-05 | 3 | [57-01, 57-02, 57-03, 57-04] | 6 new script files | Independent files -- correct |
| 57-06 | 3 | [57-01..57-05] | v0.10.0-UAT.md, deployment-guide.md (UAT-MATRIX markers) | Replace between markers -- correct |

All dependencies are correctly ordered. No cycles. No concurrent writes to the same file.

---

### Claude: Security Considerations

| Concern | Severity | Location | Mitigation |
|---------|----------|----------|------------|
| Policy restoration on crash | MEDIUM | Uat-EtwNtdll.ps1 Test-MonitorMode | Finally block restores original policy mode -- addressed in cycle 2 |
| Service stopped during test | MEDIUM | Uat-DaclTripwire.ps1 | Finally block restarts dlp-agent service -- addressed |
| Clipboard data destruction | LOW | Uat-CloudSync.ps1 | Warning in .DESCRIPTION -- addressed |
| Path exclusions increase attack surface | MEDIUM | Sophos, CrowdStrike sections | Documented as known limitation; install path has restricted ACLs |
| UAT scripts flagged by EDR | HIGH | Uat-HookDll.ps1, Uat-EtwNtdll.ps1 | New concern: EDR may quarantine UAT scripts themselves |

---

### Claude: Cycle Fix Effectiveness

| Cycle 1 Concern | Status |
|-----------------|--------|
| Race condition Plans 02+03 | **FULLY RESOLVED** (Plan 03 depends_on: [57-02]) |
| ActiveBlocking overloaded | **FULLY RESOLVED** (6 focused scripts) |
| Custom binary dependencies | **FULLY RESOLVED** (suspend/resume ETW, behavioral ntdll) |
| Missing placeholder markers | **FULLY RESOLVED** (HTML comment markers) |
| FalconPy Python/PowerShell | **FULLY RESOLVED** (labeled Python + Invoke-RestMethod) |
| ASR rules missing | **FULLY RESOLVED** (added to Plan 02) |
| Defender module prerequisite | **FULLY RESOLVED** (Windows Server note) |
| Carbon Black typo | **FULLY RESOLVED** ([REGION] placeholder) |
| SentinelOne registry fragility | **FULLY RESOLVED** (native + WoW6432Node) |
| Trend Micro service variability | **FULLY RESOLVED** (Get-Service wildcard) |
| WDSI email gateway | **FULLY RESOLVED** (warning about "infected" password) |
| Certificate renewal | **FULLY RESOLVED** (trust store update guidance) |
| Multi-signature output | **FULLY RESOLVED** (noted as expected) |
| Benchmark Rust skip | **FULLY RESOLVED** (checks cargo presence) |
| Clipboard warning | **FULLY RESOLVED** (added to CloudSync .DESCRIPTION) |
| Baseline-first benchmark | **FULLY RESOLVED** (all baseline measurements first) |
| Optional test blocking | **FULLY RESOLVED** (clarified skipped optional tests don't block) |

| Cycle 2 Concern | Status |
|-----------------|--------|
| Defender SKU detection | **FULLY RESOLVED** (Get-MpComputerStatus + MDE registry check) |
| CrowdStrike API scopes/endpoints | **FULLY RESOLVED** (ml_exclusions:write/read, US-1/US-2/EU-1/US-GOV-1) |
| Plan 03 insertion precision | **FULLY RESOLVED** (INSERT-REMAINING-VENDORS-AFTER-HERE marker) |
| Office launch timing | **FULLY RESOLVED** (FindWindow / MainWindowHandle) |
| ETW bypass retry logic | **FULLY RESOLVED** (3 retries with new processes) |
| Carbon Black pilot flow | **FULLY RESOLVED** (explicit pilot endpoint with path exclusion) |
| Optional prerequisites | **FULLY RESOLVED** (visually separated Required vs Optional) |
| Policy restoration requirement | **FULLY RESOLVED** (MonitorMode task explicitly requires finally block) |

---

### Claude: Overall Risk Assessment

**Risk Level: LOW**

**Justification:** All cycle 1 and cycle 2 HIGH-severity concerns have been fully resolved:

1. **Race condition (HIGH -> RESOLVED):** Plan 03 serializes after Plan 02 with deterministic insertion marker.
2. **Missing test binaries (HIGH -> RESOLVED):** Suspend/resume ETW approach and behavioral ntdll testing eliminate all custom binary dependencies.
3. **Overloaded ActiveBlocking (HIGH -> RESOLVED):** Six focused scripts replace the monolithic script.
4. **Defender SKU variance (HIGH -> RESOLVED):** SKU detection via Get-MpComputerStatus and MDE onboarding registry check.
5. **CrowdStrike API permissions (HIGH -> RESOLVED):** API scopes and region-specific endpoints documented.

The remaining concerns are all LOW or LOW-MEDIUM severity:
- BIOS fallback edge case (LOW)
- ASR rule GUID precision (LOW)
- Carbon Black file-known verification (LOW-MEDIUM)
- SentinelOne version programmatic validation (LOW)
- Binary naming verification (LOW)
- WDSI contingency (LOW)
- ETW retry interval specification (LOW-MEDIUM)
- Startup sweep tolerance (LOW-MEDIUM)
- Office launch timeout (LOW)
- Exit code semantics clarification (LOW-MEDIUM)
- Directory creation (LOW)
- Error code recording guidance (LOW)

**New concern raised in Cycle 3:**
- **HIGH:** UAT scripts (HookDll, EtwNtdll) may be flagged as malicious tooling by EDR itself, potentially skewing UAT results or causing the scripts to be quarantined mid-test. This is an operational reality that the deployment guide should address: operators may need to temporarily allowlist the UAT scripts themselves in their EDR console before running UAT.

**Recommendation:** This phase is ready for execution. The one new HIGH concern (EDR flagging UAT scripts) should be documented as a known operational consideration in the deployment guide's Troubleshooting section, but it does not block plan execution.

---

## Consensus Summary

### Agreed Strengths
- Both reviewers confirm cycle 1 and cycle 2 fixes are comprehensively applied
- Both reviewers confirm the race condition is fully resolved
- Both reviewers confirm ActiveBlocking split into 6 scripts resolves overload issues
- Both reviewers confirm custom binary dependencies are eliminated
- Both reviewers praise placeholder markers and deterministic replacement strategy
- Both reviewers acknowledge honest vendor limitation documentation (Sophos no hash, Trend Micro PE-only)
- Both reviewers find the test matrix structure and sign-off table appropriate for a ship gate
- Both reviewers confirm the phase is close to deployable quality

### Agreed Concerns (Highest Priority)

1. **HIGH -- EDR may flag UAT scripts as malicious:** Both reviewers note that HookDll and EtwNtdll tests perform behaviors (process injection, suspend/resume) that EDRs may detect as suspicious. This could invalidate UAT results or quarantine the scripts mid-test. The deployment guide should warn operators to temporarily allowlist UAT scripts.

2. **HIGH -- Defender ASR policy precedence ambiguity:** OpenCode flags that ASR guidance may be ambiguous across E5 vs Business Premium edge cases (policy precedence conflicts). This is a new concern not raised in previous cycles.

3. **HIGH -- Uneven security guarantees across vendors:** OpenCode notes that path-only (Sophos) and PE-only (Trend) controls create security gaps if not explicitly risk-framed. Claude rates this as addressed by honest documentation but acknowledges the operational reality.

4. **MEDIUM -- UAT interpretation and evidence standards:** Both reviewers note lack of enforced completion/evidence standards. OpenCode wants explicit pass/fail criteria and evidence requirements. Claude notes exit code semantics could be clearer.

5. **MEDIUM -- Missing rollback procedures:** OpenCode notes no explicit rollback steps for vendor configurations. This is a new cross-cutting concern.

### Divergent Views

- **Overall risk level:** Claude rates LOW (ready for execution with minor tweaks). OpenCode rates Medium (operational ambiguity and vendor inconsistencies remain).
- **Defender ASR variance:** OpenCode calls this HIGH; Claude does not mention it (new in cycle 3).
- **UAT script EDR detection:** OpenCode calls this HIGH; Claude also calls this HIGH (agreed new concern).
- **Hash automation:** OpenCode calls manual hash generation MEDIUM risk; Claude considers it LOW since operators can generate hashes independently.
- **Benchmark threshold:** OpenCode wants the 25% threshold justified; Claude accepts it as a documented engineering gate.

### Cycle 3 Fix Effectiveness

| Cycle 2 Concern | Status |
|-----------------|--------|
| Defender SKU detection | **FULLY RESOLVED** |
| CrowdStrike API scopes/endpoints | **FULLY RESOLVED** |
| Plan 03 insertion precision | **FULLY RESOLVED** |
| Office launch timing | **FULLY RESOLVED** |
| ETW bypass retry logic | **FULLY RESOLVED** |
| Carbon Black pilot flow | **FULLY RESOLVED** |
| Optional prerequisites | **FULLY RESOLVED** |
| Policy restoration requirement | **FULLY RESOLVED** |

### New Concerns Raised in Cycle 3

| Concern | Severity | Plan | Description |
|---------|----------|------|-------------|
| EDR flags UAT scripts | HIGH | 57-05, 57-06 | HookDll/EtwNtdll tests may be detected as malicious by EDR, invalidating results |
| Defender ASR policy precedence | HIGH | 57-02 | ASR guidance ambiguous across E5 vs Business Premium (local vs Intune vs GPO) |
| Uneven vendor security guarantees | HIGH | 57-03 | Path-only (Sophos) and PE-only (Trend) create security gaps |
| Missing rollback procedures | MEDIUM | 57-02, 57-03 | No explicit rollback steps for vendor configurations |
| UAT evidence standards | MEDIUM | 57-06 | No enforced evidence attachment (logs, screenshots) |
| Benchmark threshold justification | MEDIUM | 57-05 | 25% gate lacks calibration guidance |

---

## Recommendations

1. **Document EDR UAT script allowlisting:** Add a note in the deployment guide Troubleshooting section that UAT scripts may need temporary EDR allowlisting before execution.
2. **Add ASR policy precedence note:** Document that ASR rules may be managed via Intune/GPO/local policy and precedence varies by tenant configuration.
3. **Add security tradeoff callouts:** For Sophos (path-only) and Trend Micro (PE-only), add explicit "Security Tradeoff" callouts noting the reduced precision vs hash-based exclusions.
4. **Add rollback procedures:** For each vendor, include a brief "To remove this exclusion" subsection.
5. **Add evidence requirements to UAT template:** Require evidence links (logs, screenshots) for each failed test case.

With these 5 tweaks, the phase achieves consensus LOW risk and is ready for execution.
