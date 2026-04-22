# Phase 25: App Identity Capture in dlp-user-ui - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-22
**Phase:** 25-app-identity-capture-in-dlp-user-ui
**Areas discussed:** Paste/destination detection, Authenticode cache design, AppTrustTier assignment, Identity resolution failures

---

## Paste/Destination Detection

| Option | Description | Selected |
|--------|-------------|----------|
| WH_KEYBOARD_LL hook | Intercept Ctrl+V globally; capture foreground window at that instant; send second alert to agent for correlation | |
| Foreground at copy time | Use foreground window at WM_CLIPBOARDUPDATE as destination proxy (often wrong — source app is foreground at copy time) | |
| SetWinEventHook foreground tracking | Track foreground changes continuously; at WM_CLIPBOARDUPDATE, previous-foreground slot = destination | ✓ |

**User's choice:** SetWinEventHook foreground tracking heuristic

**Follow-up — History depth:**

| Option | Description | Selected |
|--------|-------------|----------|
| Last 1 entry | Single previous-foreground slot; cleared after each WM_CLIPBOARDUPDATE | ✓ |
| Last 3–5 entries with timestamps | Ring buffer; walk back to find most recent non-source app | |
| Claude's discretion | Claude picks buffer size and staleness threshold | |

**Follow-up — Intra-app copy (source == destination):**

| Option | Description | Selected |
|--------|-------------|----------|
| None | Omit destination when same as source | |
| Same identity as source | Populate destination with same AppIdentity; intra-app copy explicitly modeled | ✓ |

---

## Authenticode Cache Design

| Option | Description | Selected |
|--------|-------------|----------|
| OnceLock<Mutex<HashMap>> static | Process-wide static; same pattern as REGISTRY_CACHE in Phase 24 | ✓ |
| Arc<RwLock<HashMap>> via AppState | Explicit ownership; requires threading through call sites | |
| Claude's discretion | — | |

**Capacity:**

| Option | Description | Selected |
|--------|-------------|----------|
| Unbounded HashMap | No eviction; session-lifetime; safe given ≤200 unique paths in practice | ✓ |
| Fixed-capacity LRU | lru crate dependency; solves a problem that doesn't exist in practice | |

**TTL:**

| Option | Description | Selected |
|--------|-------------|----------|
| No TTL | WinVerifyTrust once per path per session | ✓ |
| TTL (1 hour) | Re-verify periodically; handles cert revocation mid-session | |

**Notes:** User asked Claude to pick the best option for TTL — no TTL selected.

---

## AppTrustTier Assignment

| Option | Description | Selected |
|--------|-------------|----------|
| Derived from SignatureState | Valid→Trusted, Invalid/NotSigned→Untrusted, Unknown→Unknown | ✓ |
| Publisher allowlist | Admin-managed list of trusted publishers; requires Phase 28 TUI | deferred |

**Notes:** User asked Claude to pick best options for areas 3 and 4 together.

---

## Identity Resolution Failures

| Case | Handling | Selected |
|------|----------|----------|
| GetClipboardOwner returns NULL | source_application = None | ✓ |
| Owner found, QueryFullProcessImageNameW fails | Some(AppIdentity) with empty strings and Unknown tiers | ✓ |
| Destination slot empty | destination_application = None | ✓ |
| Destination HWND found, path resolution fails | Some(AppIdentity) with all-Unknown fields | ✓ |

**Notes:** Distinguishes "no owner" from "resolution attempted but failed" for policy evaluator.

---

## Claude's Discretion

- Exact SetWinEventHook registration and teardown lifecycle (thread vs process scope)
- spawn_blocking task structure for WinVerifyTrust → cache-lookup → AppIdentity construction pipeline
- Whether foreground slot is AtomicUsize (HWND as usize) or Mutex<Option<HWND>>

## Deferred Ideas

- Publisher allowlist — Phase 28
- Right-click paste detection (WH_KEYBOARD_LL) — out of scope v0.6.0
- TTL-based cache invalidation for revoked certs — future hardening phase
- APP-07: UWP app identity via AUMID — already deferred in REQUIREMENTS.md
