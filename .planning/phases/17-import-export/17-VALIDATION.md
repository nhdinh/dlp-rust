---
phase: 17
slug: import-export
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-17
---

# Phase 17 — Validation Strategy

> Per-phase validation contract for import/export policy management in the admin TUI.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | none — existing infrastructure |
| **Quick run command** | `cargo test -p dlp-admin-cli 2>&1` |
| **Full suite command** | `cargo test --all 2>&1` |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p dlp-admin-cli 2>&1`
- **After every plan wave:** Run `cargo test --all 2>&1`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 17-01-01 | 01 | 1 | N/A | — | `rfd` dependency present for native dialogs | config | `cargo check -p dlp-admin-cli` | Cargo.toml | green |
| 17-01-02 | 01 | 1 | D-13 | — | `ImportCaller`, `ImportState`, `Screen::ImportConfirm` types defined and usable | unit | `cargo test -p dlp-admin-cli import_confirm_render_tests import_execution_tests` | app.rs | green |
| 17-01-03 | 01 | 1 | D-01 | — | PolicyMenu renders 9 entries including Import/Export | unit | `cargo test -p dlp-admin-cli policy_menu_render_tests` | render.rs | green |
| 17-01-04 | 01 | 1 | POLICY-07 | — | Export action opens save dialog, fetches policies, writes pretty JSON, shows status | manual | see Manual-Only section | — | manual |
| 17-01-04 | 01 | 1 | POLICY-08 | — | Import action opens file picker, parses JSON, computes conflict diff, transitions to ImportConfirm | manual | see Manual-Only section | — | manual |
| 17-01-05 | 01 | 1 | D-13 | — | ImportConfirm screen renders header, counts, Confirm/Cancel buttons, and state blocks | unit | `cargo test -p dlp-admin-cli import_confirm_render_tests` | render.rs | green |
| 17-02-01 | 02 | 2 | POLICY-08 | — | `PolicyResponse` / `PolicyPayload` typed wire structs with `From` conversion | unit | `cargo test -p dlp-admin-cli import_export_tests` | app.rs | green |
| 17-02-02 | 02 | 2 | POLICY-08 | — | Import execution partitions policies into POST new / PUT existing, aborts on first failure, reports success summary | integration | `cargo test -p dlp-admin-cli import_execution_tests` | dispatch.rs | green |
| 17-02-03 | 02 | 2 | POLICY-08 | — | `action_import_policies` deserializes typed policies and computes conflict diff | integration | `cargo test -p dlp-admin-cli import_execution_tests` | dispatch.rs | green |
| 17-02-04 | 02 | 2 | D-13 | — | `draw_import_confirm` accepts typed `Vec<PolicyResponse>` field transparently | unit | `cargo test -p dlp-admin-cli import_confirm_render_tests` | render.rs | green |
| 17-02-05 | 02 | 2 | POLICY-08 | — | `PolicyResponse` ↔ `PolicyPayload` conversion unit tests | unit | `cargo test -p dlp-admin-cli import_export_tests` | app.rs | green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test stubs needed before Wave 1.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Export action: native save dialog, default filename, file write, success/error status | POLICY-07 | `rfd::FileDialog::save_file()` opens a blocking OS-native modal that cannot be mocked without modifying the implementation | Run `cargo run -p dlp-admin-cli`, authenticate, navigate to Policy Management → Export Policies..., verify the save dialog title/filter/default name, save the file, and confirm the green status message |
| Import action: native file picker, JSON parse, conflict diff, transition to ImportConfirm | POLICY-08 | `rfd::FileDialog::pick_file()` opens a blocking OS-native modal that cannot be mocked without modifying the implementation | Run `cargo run -p dlp-admin-cli`, authenticate, navigate to Policy Management → Import Policies..., select a previously exported JSON file, and verify the ImportConfirm screen appears with correct counts |

---

## Validation Audit

| Metric | Count |
|--------|-------|
| Gaps found | 4 |
| Resolved (automated) | 2 |
| Escalated (manual-only) | 2 |

Resolved gaps:

- `17-01-05` — ImportConfirm rendering: 8 new unit tests in `dlp-admin-cli/src/screens/render.rs`.
- `17-02-02` — Import execution (POST/PUT/abort/success): 8 new wiremock-backed integration tests in `dlp-admin-cli/src/screens/dispatch.rs`.

Escalated gaps:

- `17-01-04` POLICY-07 export action: native save dialog not automatable without impl changes.
- `17-01-04` POLICY-08 import action: native file-open dialog not automatable without impl changes.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter (blocked by 2 manual-only UI/dialog verifications)

**Approval:** pending
