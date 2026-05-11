# DLP-RUST — Requirements

## Active Milestone: v1.0.0 — Enterprise Hardening & Scale

Goal: take a feature-complete DLP system through hardening, refactor, scale validation, and operational readiness to a 1.0 release tag.

### Hardening & Refactor

- [ ] **HARD-01** — Encrypt secrets at rest in operator SQLite (PBKDF2 key derivation + machine-bound DPAPI key). Covers JWT signing key, SMTP creds, LDAP bind creds, SIEM webhook tokens. Migration must read existing cleartext rows, write encrypted, retain backup column for one release.
- [ ] **HARD-02** — Split `dlp-server/src/admin_api.rs` (217 KB monolith) into per-domain modules (policies, devices, users, audit, alerts, system). Preserve existing route paths; refactor must be behavior-preserving with 100% test pass-through.
- [ ] **HARD-03** — Append-only audit hash chain. Each `AuditEvent` carries `prev_hash` and `current_hash` (SHA-256 over canonical serialization). Verifier CLI walks the chain and reports any breaks. Tamper detection requirement for compliance (N-SEC-07).

### Test Coverage

- [ ] **HARD-04** — End-to-end test for password-protected service stop. Currently manual-only. Integrate to CI: install service, set password, attempt unauthenticated stop (expect failure), authenticate, stop succeeds.

### Smoke & Acceptance

- [ ] **HARD-05** — Manual smoke test on real Windows host. Real OneDrive/Google Drive/Dropbox/Box clients (not mocks). Real print jobs against real printers. Real USB devices. Record results in `.planning/milestones/v1.0.0-SMOKE.md`. Acceptance gate before release tag.

### Documentation

- [ ] **HARD-06** — Operational runbooks + deployment guides. Coverage: install/upgrade/uninstall, AD bind configuration, certificate management, log shipping, troubleshooting (10 most common issues), disaster recovery. Lives in `docs/operations/`.

### Scale Validation

- [ ] **HARD-07** — Performance baseline at scale. 1000 policies in PolicyStore, 100 simultaneous agents polling, sustained 1000 audit events/sec to server. Document p50/p95/p99 latency for policy evaluation, audit ingest, admin API. Capture in `.planning/milestones/v1.0.0-PERF.md`.

### Release Gate

- [ ] **HARD-08** — SonarQube quality gate clean (zero bugs, zero security issues, ≥80% coverage on new code) + v1.0.0 git tag + release notes. Blocking on all above.

---

## Validated (Shipped)

### v0.2.0 — Feature Completion
- ✓ **REL-01** SIEM relay (webhook + email)
- ✓ **REL-02** Alert routing infrastructure
- ✓ **CFG-01** Agent config polling from server with TOML persistence
- ✓ **SEC-01** JWT hardening (rotation, expiry, signature verification)
- ✓ **TST-01** 364+ workspace tests baseline

### v0.3.0 — Operational Hardening
- ✓ **AUTH-01** AD LDAP integration via `ldap3`
- ✓ **NET-01** Rate limiting via `tower-governor`
- ✓ **AUD-01** Admin audit logging
- ✓ **DB-01** SQLite connection pooling via `r2d2`
- ✓ **POL-01** PolicyStore with 5-min background refresh

### v0.4.0 — Policy Authoring
- ✓ **POL-02** Conditions Builder UI (no raw JSON)
- ✓ **POL-03** Policy CRUD via admin API
- ✓ **POL-04** Policy import/export

### v0.5.0 — Boolean Logic
- ✓ **POL-05** ALL/ANY/NONE boolean composition
- ✓ **POL-06** In-place condition editing
- ✓ **POL-07** Expanded operator set (regex, in-list, range, etc.)

### v0.6.0 — Endpoint Hardening
- ✓ **APP-01** Authenticode application identity
- ✓ **APP-02** AUMID resolution (legacy Win32)
- ✓ **BRW-01** Chrome Enterprise Connector integration
- ✓ **USB-01** USB device enumeration
- ✓ **USB-02** USB trust-tier classification
- ✓ **USB-03** USB device-allowlist policy enforcement

### v0.7.0 — Disk Exfiltration Prevention
- ✓ **DSK-01** Disk enumeration via WMI
- ✓ **DSK-02** BitLocker encryption status verification
- ✓ **DSK-03** WM_DEVICECHANGE event handling
- ✓ **DSK-04** Disk allowlist policy
- ✓ **TUI-01** Admin TUI device-management screen

### v0.7.1 — Operational Hardening
- ✓ **APP-03** AGENT-UNKNOWN sentinel for unresolvable identity
- ✓ **USB-04** Per-user device registry
- ✓ **DEP-01** `wmi` crate upgrade
- ✓ **USB-05** PnP USB enforcement (CM_Disable_DevNode)
- ✓ **DSK-05** Mount-time disk blocking (Volume DACL deny-all)
- ✓ **POL-08** Configurable grace period with escalation
- ✓ **UAT-01** SanDisk full 128-char serial UAT validation

### v0.8.0 — Application-Aware DLP
- ✓ **APP-07** UWP app identity via `GetApplicationUserModelId`
- ✓ **APP-08** Drag-and-drop enforcement (WH_GETMESSAGE hook)
- ✓ **BRW-04** Browser origin-aware clipboard policies
- ✓ **AUDIT-04** Audit enrichment with app identity fields

### v0.8.1 — Deferred Items & Issue Debt
- ✓ **USB-07/08/09** Deferred USB enforcement gaps closed
- ✓ **DSK-06/07** Deferred disk gaps closed
- ✓ **UAT-05** Complete UAT validation for v0.8.0 features

### v0.9.0 — Cloud & Print Exfiltration Prevention
- ✓ **R001** Cloud sync blocking via user-mode IAT hook (CreateFileW/NtCreateFile patching) + registry-based path discovery
- ✓ **R002** Print interception (FindFirstPrinterChangeNotification + XPS ZIP extraction of `<Glyphs UnicodeString>`)
- ✓ **R003** API hook framework: hook DLL with CreateRemoteThread injection, named-pipe bincode classification protocol, fail-closed
- ✓ **R004** WFP defense-in-depth for cloud sync bypass (TCP/443 blocking); validated by M017-S02
- ✓ **R005** Cloud share link clipboard detection (all 4 providers; Box anchored to prevent Dropbox false-positive)
- ✓ **R006** Admin CLI Cloud + Print configuration screens

---

## Out of Scope

- **Mobile app** — Windows-first product, no MDM scope.
- **macOS/Linux agent** — NTFS enforcement requires Windows.
- **Cloud-native policy engine** — on-prem DLP with enterprise AD dependency.
- **File encryption at rest** — NTFS ACLs + ABAC provide access control; full-disk encryption is BitLocker's concern.
- **Raw JSON policy editing** — replaced by Conditions Builder in v0.4.0.
- **Kernel minifilter driver** — user-mode IAT hooks + WFP sufficient; EV cert path not justified by risk.
- **Native browser extension** — deferred to v1.3.

---

## Traceability

Filled in by `gsd-roadmapper` once `ROADMAP.md` is generated. Maps each `HARD-NN` requirement to a phase.

| Requirement | Phase | Status |
|-------------|-------|--------|
| HARD-01 | TBD | Active |
| HARD-02 | TBD | Active |
| HARD-03 | TBD | Active |
| HARD-04 | TBD | Active |
| HARD-05 | TBD | Active |
| HARD-06 | TBD | Active |
| HARD-07 | TBD | Active |
| HARD-08 | TBD | Active |

---

*Last updated: 2026-05-11 from IDEA-DOC.md consolidation.*
