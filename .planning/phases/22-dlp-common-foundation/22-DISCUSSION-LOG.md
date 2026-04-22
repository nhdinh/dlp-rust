# Phase 22: dlp-common Foundation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-22
**Phase:** 22-dlp-common-foundation
**Areas discussed:** Module Organization, AbacContext vs EvaluateRequest, SignatureState + AppTrustTier, IPC Message Duplication

---

## Module Organization

| Option | Description | Selected |
|--------|-------------|----------|
| Extend abac.rs | Add AppIdentity, DeviceIdentity, UsbTrustTier to existing abac.rs | |
| New endpoint.rs module | Dedicated module for all endpoint-identity types; re-export from lib.rs | ✓ |

**User's choice:** New `dlp-common/src/endpoint.rs` module (auto-selected recommended)
**Notes:** Keeps abac.rs focused on policy/evaluation types; downstream crates import from `dlp_common::endpoint`.

---

## AbacContext vs EvaluateRequest

| Option | Description | Selected |
|--------|-------------|----------|
| Extend EvaluateRequest only | Add app identity fields directly to EvaluateRequest, no AbacContext yet | |
| Extend EvaluateRequest + introduce AbacContext | EvaluateRequest gains fields for wire compat; AbacContext introduced as future evaluate() input | ✓ |
| Rename EvaluateRequest to AbacContext | Full rename across all callers — large refactor | |

**User's choice:** Extend EvaluateRequest with new optional fields AND introduce AbacContext as a separate evaluation-context struct (auto-selected recommended)
**Notes:** AbacContext defined in Phase 22 but not yet wired into evaluate(); Phase 26 does the wiring. Keeps wire format (EvaluateRequest) and internal eval context (AbacContext) as distinct concerns.

---

## SignatureState + AppTrustTier Shape

| Option | Description | Selected |
|--------|-------------|----------|
| SignatureState: Valid/Invalid/NotSigned/Unknown | 4-variant enum covering all WinVerifyTrust outcomes | ✓ |
| SignatureState: bool | Simple signed/unsigned boolean | |
| AppTrustTier: same as UsbTrustTier | Reuse Blocked/ReadOnly/FullAccess | |
| AppTrustTier: Trusted/Untrusted/Unknown (separate) | Application-specific trust vocabulary | ✓ |

**User's choice:** SignatureState with 4 variants; AppTrustTier as separate enum with Trusted/Untrusted/Unknown (auto-selected recommended)
**Notes:** UsbTrustTier stays Blocked/ReadOnly/FullAccess to match DB CHECK constraint (USB-02). AppTrustTier has different semantics — it's about Authenticode trust, not I/O enforcement level.

---

## IPC Message Duplication

| Option | Description | Selected |
|--------|-------------|----------|
| Keep duplication, add fields to both | Add new fields to both messages.rs copies with #[serde(default)] | ✓ |
| Consolidate into dlp-common | Move shared IPC types to dlp-common/src/ipc.rs | |

**User's choice:** Keep duplication, add fields to both copies (auto-selected recommended)
**Notes:** Consolidation is a separate refactor concern, not Phase 22's job. Both files get identical ClipboardAlert changes.

---

## Claude's Discretion

- AppIdentity builder methods — Claude decides based on ergonomics
- AppTrustTier/UsbTrustTier PartialOrd — Claude decides; not required by success criteria
- DeviceIdentity convenience constructor — Claude decides

## Deferred Ideas

- IPC message consolidation into dlp-common (future refactor)
- AppTrustTier PartialOrd for policy range comparisons (Phase 26 if needed)
- UWP app identity via AUMID (APP-07 — separate spike per REQUIREMENTS.md)
