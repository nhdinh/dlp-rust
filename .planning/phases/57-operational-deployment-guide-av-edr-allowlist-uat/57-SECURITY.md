---
phase: 57
slug: operational-deployment-guide-av-edr-allowlist-uat
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-05
---

# Phase 57 -- Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Operator workstation -> Target endpoint | Operator runs pre-flight checks on endpoint; commands require admin privileges | Pre-flight check output (local only) |
| Downloaded MSI -> Installed binary | Hash verification boundary; SHA-256/SHA-512 must match RELEASE_NOTES.md | Binary artifact + hash values |
| Binary -> Authenticode signature | signtool verify /pa confirms signature + timestamp validity | Certificate chain + RFC-3161 timestamp |
| Vendor console -> Operator browser | EDR management console access for allowlist configuration | Vendor-specific credentials (operator-managed) |
| Admin API -> UAT scripts | PowerShell scripts query DLP admin API for audit events and config | Short-lived admin JWT (local only) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-57-01 | Tampering | Downloaded MSI | mitigate | SHA-256/SHA-512 hash verification against RELEASE_NOTES.md per OPS-02, documented in deployment-guide.md | closed |
| T-57-02 | Tampering | RELEASE_NOTES.md itself | accept | Hosted in git repository with commit history; operator verifies git signature | closed |
| T-57-03 | Denial of Service | Expired Authenticode signature | mitigate | RFC-3161 timestamp verification with signtool; documented in deployment-guide.md | closed |
| T-57-04 | Information Disclosure | Pre-flight check output reveals system config | accept | Commands run locally by admin; no network transmission | closed |
| T-57-05 | Denial of Service | EDR quarantines hook DLL before exclusion propagates | mitigate | Propagation times documented per vendor (15-30 min Defender, up to 40 min CrowdStrike); operator warned to wait | closed |
| T-57-06 | Information Disclosure | EDR console credentials exposed in documentation | accept | No credentials in docs; operator uses their own authenticated session | closed |
| T-57-07 | Tampering | Vendor console UI changes, breaking documented steps | accept | Document console URLs and general navigation; note that exact UI may evolve | closed |
| T-57-08 | Denial of Service | Sophos quarantines hook DLL because hash exclusion is not supported | mitigate | Document path exclusion as only option; operator must use path-based fallback | closed |
| T-57-09 | Denial of Service | Trend Micro Application Control not licensed | mitigate | Document scan exclusion as fallback; operator verifies license before deployment | closed |
| T-57-10 | Information Disclosure | Vendor console credentials exposed in documentation | accept | No credentials in docs; operator uses their own authenticated session | closed |
| T-57-11 | Tampering | Vendor console UI changes, breaking documented steps | accept | Document console URLs and general navigation; note that exact UI may evolve | closed |
| T-57-12 | Tampering | Downloaded binary does not match published hash | mitigate | SHA-256 + SHA-512 dual-hash verification; operator compares before install | closed |
| T-57-13 | Tampering | RELEASE_NOTES.md itself tampered | accept | Hosted in git with commit history; operator verifies git signature | closed |
| T-57-14 | Denial of Service | Expired Authenticode timestamp | mitigate | RFC-3161 timestamp verification; signtool verify /pa catches expired timestamps | closed |
| T-57-15 | Denial of Service | WDSI submission rejected | mitigate | Document exact submission steps, required fields, and troubleshooting | closed |
| T-57-16 | Information Disclosure | WDSI submission reveals product details | accept | Product name and version are public; no secrets or PII in submission | closed |
| T-57-17 | Denial of Service | UAT script leaves test files or policies in bad state | mitigate | Cleanup in finally block; restore policies and services | closed |
| T-57-18 | Tampering | UAT script modifies production policies | mitigate | Test policies are clearly named; restored after test | closed |
| T-57-19 | Information Disclosure | UAT script logs JWT token | accept | Token is short-lived admin JWT; script runs locally | closed |
| T-57-20 | Denial of Service | Benchmark runs during active system use, skewing results | mitigate | Precondition checks for Windows Update, AV scans, free memory in Uat-Benchmark.ps1 | closed |
| T-57-21 | Repudiation | UAT results are falsified | mitigate | Sign-off table requires three roles (Tester, QA Lead, Release Manager); results committed to git | closed |
| T-57-22 | Information Disclosure | UAT results contain sensitive endpoint details | accept | UAT results are internal documents; no PII or credentials in template | closed |
| T-57-23 | Denial of Service | UAT fails due to environment issues, blocking release | accept | Failure escalation procedure documented (4 steps); release manager decides | closed |

*Status: open / closed*
*Disposition: mitigate (implementation required) / accept (documented risk) / transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-57-01 | T-57-02 | RELEASE_NOTES.md hosted in git with commit history; git signature provides integrity | Security Architect | 2026-06-05 |
| AR-57-02 | T-57-04 | Pre-flight checks run locally by admin; no network transmission of output | Security Architect | 2026-06-05 |
| AR-57-03 | T-57-06, T-57-10 | No credentials stored in documentation; operator authenticates with their own vendor console session | Security Architect | 2026-06-05 |
| AR-57-04 | T-57-07, T-57-11 | EDR vendor UIs evolve; documentation provides URLs and general navigation only, with UI evolution note | Security Architect | 2026-06-05 |
| AR-57-05 | T-57-13 | RELEASE_NOTES.md hosted in git with commit history; git signature provides integrity | Security Architect | 2026-06-05 |
| AR-57-06 | T-57-16 | WDSI submission contains only product name and version (public); no secrets or PII | Security Architect | 2026-06-05 |
| AR-57-07 | T-57-19 | Admin JWT is short-lived; script runs locally with no remote logging | Security Architect | 2026-06-05 |
| AR-57-08 | T-57-22 | UAT results template contains no PII or credential fields; internal document only | Security Architect | 2026-06-05 |
| AR-57-09 | T-57-23 | Failure escalation procedure (4 steps) delegates go/no-go decision to release manager | Security Architect | 2026-06-05 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-05 | 23 | 23 | 0 | gsd-security-auditor (orchestrator) |

### Audit Notes

- **Plan-time threat model**: All 6 PLAN files contained parseable `<threat_model>` blocks.
- **Mitigation verification**: Spot-checked implementation files for all 12 `mitigate` threats:
  - Hash verification procedures confirmed in `docs/operations/deployment-guide.md` and `docs/RELEASE_NOTES.md`
  - Authenticode timestamp verification confirmed in deployment guide
  - EDR propagation times documented per vendor (Defender 15-30 min, CrowdStrike up to 40 min)
  - Sophos path-only exclusion documented; Trend Micro scan exclusion fallback documented
  - WDSI submission steps documented with troubleshooting
  - All UAT scripts have `try`/`finally` cleanup; benchmark has precondition checks
  - UAT sign-off table with 3-role verification confirmed in `.planning/milestones/v0.10.0-UAT.md`
- **Accepted risks**: 11 threats accepted with documented rationale; all rationale verified as accurate.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-05
