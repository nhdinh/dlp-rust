# Requirements

This file is the explicit capability and coverage contract for the project.

Use it to track what is actively in scope, what has been validated by completed work, what is intentionally deferred, and what is explicitly out of scope.

Guidelines:
- Keep requirements capability-oriented, not a giant feature wishlist.
- Requirements should be atomic, testable, and stated in plain language.
- Every **Active** requirement should be mapped to a slice, deferred, blocked with reason, or moved out of scope.
- Each requirement should have one accountable primary owner and may have supporting slices.
- Research may suggest requirements, but research does not silently make them binding.
- Validation means the requirement was actually proven by completed work and verification, not just discussed.

## Active

### R001 — Cloud sync folder write interception
- Class: core-capability
- Status: active
- Description: T3/T4 files written to OneDrive, Google Drive, Dropbox, or Box sync folders must be blocked before the sync client uploads them. T1/T2 files are allowed.
- Why it matters: Cloud sync is the #1 modern exfiltration vector. A DLP that cannot see cloud uploads has a massive blind spot.
- Source: user
- Primary owning slice: M017/S01
- Supporting slices: M017/S02
- Validation: unmapped
- Notes: Uses user-mode API hooking (IAT) in sync client processes. No kernel driver.

### R002 — Cloud share link detection
- Class: core-capability
- Status: active
- Description: Detect public/anonymous share links copied to clipboard (OneDrive, Google Drive, Dropbox, Box URL patterns). Emit Alert for T3/T4 content.
- Why it matters: Share links bypass traditional file-access controls. Detecting them is a key detective control.
- Source: user
- Primary owning slice: M017/S03
- Supporting slices: none
- Validation: unmapped
- Notes: Clipboard pattern matching. Complemented by stricter ABAC policy for files already in sync folders.

### R003 — Print spooler interception with XPS content extraction
- Class: core-capability
- Status: active
- Description: Intercept Windows print jobs, extract text content from XPS spool files, classify, and cancel the job via SetJob if policy says DENY. T4 = block, T3 = require_auth.
- Why it matters: Printing sensitive documents is a classic exfiltration bypass.
- Source: user
- Primary owning slice: M017/S04
- Supporting slices: none
- Validation: unmapped
- Notes: Medium approach — spool directory watch + XPS parsing. EMF falls back to metadata-only.

### R004 — WFP network egress blocking for sync clients
- Class: core-capability
- Status: active
- Description: Windows Filtering Platform filter blocks outbound HTTPS from cloud sync client processes as defense-in-depth. Catches bypasses (direct syscalls, alternative upload paths).
- Why it matters: API hooking can be bypassed. WFP provides a second layer of defense at the network boundary.
- Source: user
- Primary owning slice: M017/S01
- Supporting slices: M017/S02
- Validation: unmapped
- Notes: Built-in Windows feature. No third-party driver.

### R005 — Admin-configurable print settings
- Class: operability
- Status: active
- Description: Admin can enable/disable print monitoring, configure classification mode (XPS vs metadata-only fallback), and set action thresholds via agent config.
- Why it matters: Operators need control over enforcement aggressiveness and fallback behavior.
- Source: user
- Primary owning slice: M017/S04
- Supporting slices: none
- Validation: unmapped
- Notes: Follows existing agent_config hot-reload pattern.

### R006 — Dynamic cloud sync path discovery
- Class: integration
- Status: active
- Description: Discover sync folder paths dynamically via registry and shell APIs. Support non-default installations and folder redirection.
- Why it matters: Enterprise deployments often redirect sync folders. Hardcoded paths fail in those environments.
- Source: user
- Primary owning slice: M017/S02
- Supporting slices: none
- Validation: unmapped
- Notes: Registry-based discovery with hardcoded path fallback.

### R007 — Native browser extension (Manifest V3)
- Class: core-capability
- Status: active
- Description: Chrome/Edge Manifest V3 extension for browser-level DLP. Content scripts, background service worker, native messaging host.
- Why it matters: Chrome Content Analysis API v1 is limited (no destination_origin). A full extension gives complete browser context.
- Source: user
- Primary owning slice: M018
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M018.

### R008 — Browser-level upload interception
- Class: core-capability
- Status: active
- Description: Intercept file uploads in browser via MV3 extension. Classify file content, apply ABAC policy before bytes leave the browser.
- Why it matters: Web-app uploads (Gmail, web Dropbox, etc.) never touch sync folders. Browser interception is the only way to block them.
- Source: user
- Primary owning slice: M018
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M018.

### R009 — Browser clipboard protection with destination_origin
- Class: core-capability
- Status: active
- Description: Extension intercepts copy/paste in browser with full origin context (source_origin + destination_origin) for ABAC evaluation.
- Why it matters: Chrome Content Analysis API v1 lacks destination_origin. The extension provides it.
- Source: user
- Primary owning slice: M018
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M018.

### R010 — Audit dashboard API
- Class: operability
- Status: active
- Description: Server-side aggregated endpoints for top blocked events, policy hit rates, user risk scores, agent health summary.
- Why it matters: Operators need visibility into what's happening across the fleet. Raw audit JSONL is insufficient.
- Source: inferred
- Primary owning slice: M019
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M019.

### R011 — Agent health monitoring
- Class: failure-visibility
- Status: active
- Description: Track agent heartbeats server-side. Alert when agents go offline. Fleet status dashboard in admin CLI.
- Why it matters: Silent agent failures are a compliance gap. Operators need to know when endpoints are unprotected.
- Source: inferred
- Primary owning slice: M019
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M019.

### R012 — Policy analytics
- Class: operability
- Status: active
- Description: Track policy effectiveness (hits vs false positives). Suggest policy improvements. Detect shadow policies.
- Why it matters: Static policies become stale. Analytics enable continuous improvement.
- Source: inferred
- Primary owning slice: M019
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M019.

### R013 — Multi-admin RBAC
- Class: compliance/security
- Status: active
- Description: Role-based access control for admin API. Multiple admin users with separable permissions.
- Why it matters: Compliance requires separation of duties. Single shared password is insufficient.
- Source: inferred
- Primary owning slice: M019
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M019.

### R014 — Bulk download threshold detection
- Class: differentiator
- Status: active
- Description: Detect anomalous bulk downloads (e.g., 10+ T3+ files in 60 seconds). Emit Alert.
- Why it matters: Insider threats may bypass per-file policy by staying under the radar. Bulk detection catches exfiltration patterns.
- Source: user
- Primary owning slice: M020
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M020.

### R015 — AD working hours integration
- Class: integration
- Status: active
- Description: Integrate Active Directory working hours into ABAC environment conditions. Alert on after-hours T4 access.
- Why it matters: After-hours access is a key risk signal for insider threats.
- Source: user
- Primary owning slice: M020
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M020.

### R016 — User behavior anomaly detection
- Class: differentiator
- Status: active
- Description: Establish per-user access baselines (files/day, tiers touched). Alert on statistically significant deviations.
- Why it matters: Behavioral analytics catch threats that evade static policy rules.
- Source: inferred
- Primary owning slice: M020
- Supporting slices: none
- Validation: unmapped
- Notes: Deferred to M020.

## Deferred

### R017 — Full port monitor DLL for print
- Class: core-capability
- Status: deferred
- Description: Kernel-style port monitor loaded into spoolsv.exe for mid-stream print job interception.
- Why it matters: Would provide the most robust print DLP, but is complex and invasive.
- Source: user
- Primary owning slice: none
- Supporting slices: none
- Validation: unmapped
- Notes: User chose medium (spool directory) approach for M017. Port monitor reserved for future milestone if needed.

### R018 — EMF content extraction for print jobs
- Class: quality-attribute
- Status: deferred
- Description: Extract text from EMF/GDI spool files for classification. Modern print jobs increasingly use XPS.
- Why it matters: EMF fallback would improve coverage for legacy printers.
- Source: inferred
- Primary owning slice: none
- Supporting slices: none
- Validation: unmapped
- Notes: XPS covers majority of modern print jobs. EMF is fallback to metadata-only.

### R019 — Browser extension for Firefox/Safari
- Class: integration
- Status: deferred
- Description: Extend MV3 browser extension to Firefox and Safari.
- Why it matters: Chrome/Edge covers ~70% of enterprise browsers. Firefox/Safari would close the gap.
- Source: inferred
- Primary owning slice: none
- Supporting slices: none
- Validation: unmapped
- Notes: MV3 WebExtensions API is portable, but Safari requires native messaging host differences.

## Out of Scope

### R020 — Kernel minifilter driver
- Class: constraint
- Status: out-of-scope
- Description: Windows kernel minifilter driver for file system interception.
- Why it matters: Would be the "correct" solution for file interception, but requires EV code signing.
- Source: user
- Primary owning slice: none
- Supporting slices: none
- Validation: n/a
- Notes: Explicitly rejected by user — no EV signing certificate available. User-mode API hooking + WFP used instead.

## Traceability

| ID | Class | Status | Primary owner | Supporting | Proof |
|---|---|---|---|---|---|
| R001 | core-capability | active | M017/S01 | M017/S02 | unmapped |
| R002 | core-capability | active | M017/S03 | none | unmapped |
| R003 | core-capability | active | M017/S04 | none | unmapped |
| R004 | core-capability | active | M017/S01 | M017/S02 | unmapped |
| R005 | operability | active | M017/S04 | none | unmapped |
| R006 | integration | active | M017/S02 | none | unmapped |
| R007 | core-capability | active | M018 | none | unmapped |
| R008 | core-capability | active | M018 | none | unmapped |
| R009 | core-capability | active | M018 | none | unmapped |
| R010 | operability | active | M019 | none | unmapped |
| R011 | failure-visibility | active | M019 | none | unmapped |
| R012 | operability | active | M019 | none | unmapped |
| R013 | compliance/security | active | M019 | none | unmapped |
| R014 | differentiator | active | M020 | none | unmapped |
| R015 | integration | active | M020 | none | unmapped |
| R016 | differentiator | active | M020 | none | unmapped |
| R017 | core-capability | deferred | none | none | unmapped |
| R018 | quality-attribute | deferred | none | none | unmapped |
| R019 | integration | deferred | none | none | unmapped |
| R020 | constraint | out-of-scope | none | none | n/a |

## Coverage Summary

- Active requirements: 16
- Mapped to slices: 6 (M017 only; M018-M020 provisional)
- Validated: 0
- Unmapped active requirements: 0
