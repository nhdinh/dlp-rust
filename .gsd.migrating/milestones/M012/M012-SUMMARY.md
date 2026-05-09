---
id: M012
title: "v0.6.0 Endpoint Hardening"
status: complete
completed_at: 2026-05-08T05:52:30.214Z
key_decisions:
  - AppField enum in dlp-common/src/abac.rs — policy DSL type, not identity type
  - From<EvaluateRequest> for AbacContext drops agent field (tracing metadata)
  - UsbEnforcer check() fires before offline.evaluate() — None is zero-cost fast-path
  - check() returns Option<UsbBlockResult> with notify flag and 30s cooldown
  - Chrome pipe thread spawned in both service and console modes
  - Cross-platform compilation: removed #[cfg(windows)] from chrome/mod.rs
  - Protobuf ContentAnalysisRequest/Response via prost with 4 MiB MAX_PAYLOAD cap
key_files:
  - dlp-common/src/endpoint.rs
  - dlp-agent/src/detection/app_identity.rs
  - dlp-agent/src/usb_enforcer.rs
  - dlp-agent/src/chrome/mod.rs
lessons_learned:
  - Shared types must be in dlp-common before any crate can consume them
  - Authenticode verification must run in spawn_blocking to avoid blocking UI message pump
  - USB enforcer should short-circuit before ABAC for zero-cost fast-path
  - Chrome Content Analysis API requires careful protobuf framing and HKLM registration
---

# M012: v0.6.0 Endpoint Hardening

**v0.6.0 Endpoint Hardening shipped with app identity, browser boundary, USB control, and automated UAT.**

## What Happened

v0.6.0 extended enforcement with application identity, browser boundary control, USB device control, and automated UAT infrastructure. All 13 requirements validated.

## Success Criteria Results

- Application-aware DLP working — PASS (S03)
- Browser boundary control working — PASS (S04)
- USB device control with toast working — PASS (S04)
- Automated UAT infrastructure working — PASS (S05)
- All 13 requirements validated — PASS (coverage audit)

## Definition of Done Results

All slices complete with verification evidence. All 13 requirements validated. Cross-slice integration verified. Milestone audit passed.

## Requirement Outcomes

| Requirement | Status | Evidence |
|-------------|--------|----------|
| APP-01..06 | validated | S01,S03,S04: App identity, ABAC, TUI |
| BRW-01..03 | validated | S04: Chrome connector, managed origins |
| USB-01..04 | validated | S02,S03,S04: Enumeration, registry, enforcement, toast |

## Deviations

Native browser extension deferred. USB-05 and USB-06 deferred to v0.7.1. POLICY-F4/F5/F6 deferred.

## Follow-ups

Native browser extension (Chrome/Edge Manifest V3) for post-v0.8.0.
