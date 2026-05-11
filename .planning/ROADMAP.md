# Roadmap: DLP-RUST

Phase numbering is continuous across milestones — it never restarts. Phases 0.1–46 cover the shipped milestones below; v1.0.0 starts at Phase 47.

## Milestones

- v0.2.0 Feature Completion — Phases 0.1–12 (shipped 2026-04-13)
- v0.3.0 Operational Hardening — Phases 7–11 (shipped 2026-04-16)
- v0.4.0 Policy Authoring — Phases 13–17 (shipped 2026-04-20)
- v0.5.0 Boolean Logic — Phases 18–21 (shipped 2026-04-21)
- v0.6.0 Endpoint Hardening — Phases 22–30 (shipped 2026-04-29)
- v0.7.0 Disk Exfiltration Prevention — Phases 33–38.2 (shipped 2026-05-06)
- v0.7.1 Operational Hardening — Phases 38.3–38.6 (shipped 2026-05-06)
- v0.8.0 Application-Aware DLP — Phases 39–42 (shipped 2026-05-07)
- v0.8.1 Deferred Items & Issue Debt — Phases 43–46 (shipped 2026-05-08)
- v0.9.0 Cloud & Print Exfiltration Prevention — M017 / Phases 47-pre (shipped 2026-05-09)
- **v1.0.0 Enterprise Hardening & Scale — Phases 47–54 (active)**

## Active Milestone — v1.0.0 Enterprise Hardening & Scale

**Goal:** Take the feature-complete v0.9.0 codebase through hardening, refactor, scale validation, operational documentation, and acceptance testing to a 1.0 release tag with a clean SonarQube quality gate.

**Requirement mapping:** All 8 active requirements (HARD-01..08) are mapped one-to-one to Phases 47..54 below.

---

### Phase 47: Secrets Encryption at Rest
**Goal:** Encrypt all secret fields in the operator SQLite database (JWT signing key, SMTP creds, LDAP bind credentials, SIEM webhook tokens) using PBKDF2 key derivation bound to a machine-protected DPAPI key. Provide migration path with backup column retained for one release.

**Requirements:** HARD-01

**Success Criteria:**
1. New rows write encrypted ciphertext; reads transparently decrypt.
2. Migration successfully upgrades existing cleartext rows in place.
3. Backup column allows rollback within one release window.
4. Key rotation procedure documented and exercised in a test.
5. No cleartext secret appears in any log line (verified by audit-log scan).

---

### Phase 48: admin_api Refactor
**Goal:** Split the 217 KB monolithic `dlp-server/src/admin_api.rs` into per-domain modules (policies, devices, users, audit, alerts, system, common). Refactor is behavior-preserving — existing route paths and contracts unchanged.

**Requirements:** HARD-02

**Success Criteria:**
1. `admin_api.rs` is replaced by a module tree of focused files, each under 50 KB.
2. All existing admin API tests pass without modification.
3. Route registration uses a single composition point; no duplicate routes.
4. `cargo clippy -- -D warnings` clean across the new module tree.
5. Git history preserved via `git mv` where possible.

---

### Phase 49: Audit Hash Chain
**Goal:** Implement append-only audit log with `prev_hash` + `current_hash` SHA-256 chain on every `AuditEvent`. Provide a verifier CLI that walks the chain and reports breaks. Addresses N-SEC-07 tamper-detection requirement.

**Requirements:** HARD-03

**Success Criteria:**
1. Every new `AuditEvent` carries both hash fields.
2. Canonical serialization is deterministic (verified by golden-vector test).
3. Verifier CLI detects insertion, deletion, and modification attacks in golden-vector tests.
4. Existing audit consumers (SIEM relay, admin API queries) tolerate the new fields transparently.
5. Migration of existing audit rows: backfill `prev_hash` chain starting from a genesis row.

---

### Phase 50: E2E Service-Stop Coverage
**Goal:** Promote the manual password-protected service-stop test to a CI-runnable end-to-end test. Use a Windows-flavored CI runner; install the service, configure the password, attempt an unauthenticated stop, then an authenticated stop.

**Requirements:** HARD-04

**Success Criteria:**
1. Test runs on Windows CI runner without manual intervention.
2. Unauthenticated stop attempt fails with the expected error code.
3. Authenticated stop succeeds and the service exits cleanly.
4. Test cleans up installed service + registry state regardless of outcome.
5. Test is wired into the existing CI workflow.

---

### Phase 51: Smoke Test on Real Windows Host
**Goal:** Execute a manual acceptance smoke test against real cloud sync clients (OneDrive, Google Drive, Dropbox, Box), real printers, and real USB devices on a Windows host. Record outcomes in `.planning/milestones/v1.0.0-SMOKE.md`. Acceptance gate for release.

**Requirements:** HARD-05

**Success Criteria:**
1. Cloud sync interception confirmed on each of the 4 providers (block + audit).
2. Print interception confirmed via XPS extraction on a real printer.
3. USB enforcement confirmed against a SanDisk and one non-allowlisted device.
4. Clipboard share-link detection confirmed for each cloud provider URL pattern.
5. Smoke test report committed to repo; any regressions filed as blocking issues.

---

### Phase 52: Operational Documentation
**Goal:** Produce operational runbooks and deployment guides covering install/upgrade/uninstall, AD bind configuration, certificate management, log shipping, troubleshooting for the 10 most common issues, and disaster recovery procedures.

**Requirements:** HARD-06

**Success Criteria:**
1. `docs/operations/install.md` covers fresh install and upgrade paths.
2. `docs/operations/ad-bind.md` covers LDAP configuration including service-account hardening.
3. `docs/operations/troubleshooting.md` covers top 10 issues with diagnostic commands.
4. `docs/operations/disaster-recovery.md` covers backup/restore for SQLite and policy export/import.
5. Docs reviewed against actual install on a clean Windows VM.

---

### Phase 53: Performance Baseline at Scale
**Goal:** Establish a performance baseline at production-relevant scale: 1000 policies loaded, 100 simultaneous agent connections polling, sustained 1000 audit events/sec ingest. Capture p50/p95/p99 latency for policy evaluation, audit ingest, admin API. Document in `.planning/milestones/v1.0.0-PERF.md`.

**Requirements:** HARD-07

**Success Criteria:**
1. Synthetic harness loads 1000 policies and 100 agents reliably.
2. Sustained 1000 audit events/sec achieved without dropped events.
3. p95 policy evaluation latency ≤ 5ms; p99 ≤ 20ms.
4. p95 audit ingest end-to-end latency ≤ 50ms.
5. Performance report committed; any regressions vs. v0.9.0 baseline filed and triaged.

---

### Phase 54: SonarQube Quality Gate & v1.0.0 Release
**Goal:** Bring the SonarQube quality gate to clean — zero bugs, zero security issues, ≥80% coverage on new code — then tag v1.0.0 and publish release notes.

**Requirements:** HARD-08

**Success Criteria:**
1. SonarQube quality gate: PASS.
2. Zero `Bug` severity findings; zero `Vulnerability` findings.
3. New-code coverage ≥80%; line coverage on `dlp-common` and `dlp-server` ≥75%.
4. `v1.0.0` git tag created on a clean working tree with all prior phases merged.
5. Release notes published covering shipped features (v0.2.0–v0.9.0) and v1.0.0 hardening additions.

---

## Phase Numbering

- Integer phases (1, 2, 3, …): Planned milestone work.
- Decimal phases (e.g., 3.1, 38.1, 38.2): Urgent insertions or sub-phases of a parent.
- Continuous numbering across milestones — never restarts.

## Archived Milestones

Phase details and requirement outcomes for shipped milestones live in the legacy workspaces:

- **`.planning.legacy/MILESTONES.md`** — top-level milestone summaries (v0.2.0–v0.8.1)
- **`.planning.legacy/ROADMAP.md`** — full phase listings for v0.2.0–v0.8.0
- **`.planning.legacy/v0.6.0-MILESTONE-AUDIT.md`**, **`v0.8.0-MILESTONE-AUDIT.md`**, **`v0.8.1-MILESTONE-AUDIT.md`** — milestone retrospectives
- **`.gsd.legacy/milestones/M008..M017/`** — slice+task breakdown for v0.7.1, v0.8.0, v0.8.1, v0.9.0 in the milestone-slice-task format

Consult these for context on prior decisions, regression history, and shipped scope.

---

*Last updated: 2026-05-11 — initial v1.0.0 roadmap from IDEA-DOC.md consolidation.*
