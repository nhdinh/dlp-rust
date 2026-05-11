---
id: SEED-001
status: active
planted: 2026-04-10
planted_during: v0.2.0 feature completion (Phase 4 planning)
trigger_when: "ABAC attribute surface is extended beyond user/classification/device, OR clipboard/interception subsystems are revisited for smarter policy, OR v0.3.0+ milestone planning begins and the focus is policy expressiveness"
scope: large
---

# SEED-001: Application-aware DLP — distinguish source and destination apps for copy/paste and file flows

## The idea (verbatim from planting)

> DLP can distinguish between authorized and unauthorized applications.
> For instance, it can permit copying data from a secure Word document
> to Excel, but block pasting it into Notepad++, Gmail, or a web browser.

## Why This Matters

Today's DLP policy surface is **tier-only**: a file or clipboard payload
is classified T1/T2/T3/T4, and the policy engine decides ALLOW/DENY/LOG
based on that tier plus the user identity and action (WRITE/READ/PASTE).
There is no notion of **who the destination is**.

The result is a binary choice:
- **Block all T3/T4 paste operations** → frustrates legitimate workflows
  (the finance analyst who needs to paste a confidential figure from Word
  into Excel, the engineer who needs to copy a secret from an internal doc
  into a trusted IDE).
- **Allow all paste operations for classified data** → destroys the
  exfiltration guarantee (the same data can be pasted into Gmail, a
  browser address bar, a pastebin, Notepad++ → Save-As to a non-monitored
  path, a Slack window, a Teams chat).

Users work around binary policies by going around the DLP entirely
(screenshots, retyping, personal devices), which is *worse* than a
calibrated policy that allows the legitimate flow.

Application-awareness is the natural next ABAC dimension after user,
classification, device, and location. Every mature DLP product (Symantec,
Forcepoint, Microsoft Purview, Digital Guardian) supports some form of
source-app / destination-app rules. Without it, this DLP will hit a
ceiling in enterprise deployments.

**Core use cases unlocked:**

| Source | Destination | Today | With this seed |
|---|---|---|---|
| Word (secure) | Excel | blocked (T3) | allowed (trusted analyst workflow) |
| Word (secure) | Notepad++ | blocked (T3) | blocked (save-as bypass risk) |
| Word (secure) | Gmail in browser | blocked (T3) | blocked (exfiltration path) |
| Word (secure) | Slack Desktop | blocked (T3) | policy choice (depends on Slack data boundary) |
| Public PDF | any | allowed (T1) | allowed |
| Any | IDE (VSCode) | ? | configurable (dev workflow vs. source leak) |

## When to Surface

**Trigger conditions** — this seed should be presented during
`/gsd-new-milestone` when the new milestone scope includes any of:

1. ABAC attribute extension (adding new dimensions beyond user/classification/device)
2. Clipboard subsystem changes (any phase that edits `dlp-user-ui/src/clipboard_monitor.rs`
   or the Pipe 3 `ClipboardAlert` contract)
3. Policy engine expressiveness work (adding rule types, rule operators,
   or the ABAC evaluation request shape)
4. Policy authoring UX (admin CLI screens for authoring rules)
5. v0.3.0 milestone planning — regardless of focus, this is a natural
   "next major feature" candidate
6. A pre-sales / enterprise evaluation surfaces "we can't distinguish
   apps" as a blocker

## Scope Estimate

**LARGE** — this spans at least five subsystems and likely warrants its
own milestone (v0.3.0 "Application-Aware Policy") rather than a single
phase. Minimum phase breakdown:

1. **Destination app detection in the clipboard monitor** — `GetForegroundWindow` →
   `GetWindowThreadProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` →
   `QueryFullProcessImageNameW`. Captures image path + possibly signing info at
   paste time. Must handle UWP apps (via AUMID), browsers (need to inspect
   child processes + URL bar where possible), and the inherent race between
   clipboard change and focus change.

2. **Source app detection** — `GetClipboardOwner()` returns the HWND that
   last called `SetClipboardData`; resolve to PID → image path. Must be
   captured at clipboard-change time, not at paste time, because the owner
   window may be closed by the time the paste happens. The current
   `clipboard_monitor::handle_clipboard_change` is the only window to
   capture source — and right now it doesn't.

3. **Anti-spoofing** — a renamed `notepad.exe → excel.exe` must not bypass
   the allowlist. Needs Authenticode signature verification (`WinVerifyTrust`)
   or at minimum a hash allowlist. For browsers, needs canonical publisher
   check (Microsoft/Google/Mozilla/Brave). For UWP apps, the AUMID is
   forgery-resistant — cheaper win.

4. **Policy language extension** — `dlp-common::abac::AbacContext` gains
   `source_application: Option<AppIdentity>` and
   `destination_application: Option<AppIdentity>`. The `AppIdentity` struct
   needs: canonical image path, publisher name, signature state, AUMID (UWP),
   content type hint (browser URL host for HTTP destinations). Policy rules
   become expressible as "IF classification >= T3 AND source_app.publisher=Microsoft
   AND destination_app.publisher=Microsoft THEN ALLOW".

5. **Policy storage + distribution** — policies currently stored as ABAC
   rules in dlp-server's DB. Adding app-awareness means the rule schema
   gains new columns or a JSON blob of conditions. Must be backward-compatible
   with existing rules. Policy sync (Phase 5) must understand the new
   attributes.

6. **Admin authoring UX** — the dlp-admin-cli TUI needs a way to build
   an app allowlist/blocklist per tier. Likely a new screen: "Application
   Policies" listing trusted publishers and allowed image paths, with
   per-tier allow/block matrix. Could also ship a "learn mode" that
   records app pairs seen in audit events and lets the admin approve them
   individually.

7. **Audit event enrichment** — `AuditEvent` already has
   `application_path` and `application_hash` fields (see breadcrumbs).
   They need to be actually populated today (they're `None` in the
   current clipboard alert path) and extended to distinguish source vs
   destination when a paste event fires.

8. **Testing** — the integration tests need mock processes with known
   paths/signatures to drive the decision matrix. This is non-trivial on
   Windows (can't easily spawn a signed binary from a test).

Rough effort: **4-6 phases, potentially a full milestone**.

## Breadcrumbs

**Existing code that already hints at this idea:**

- `dlp-common/src/audit.rs:147,151` — `AuditEvent` already has optional
  fields `application_path: Option<String>` and `application_hash: Option<String>`
  and a builder `with_application(path, hash)`. Today these are always
  `None` on the clipboard alert path. First step is populating them.

- `dlp-common/src/audit.rs:245-252` — `AuditEvent::with_application` builder.

- `dlp-common/src/abac.rs` — current `AbacContext` has no process-level
  attributes. This is where the policy engine would consume the new
  source/destination app identity.

- `dlp-user-ui/src/clipboard_monitor.rs` — `handle_clipboard_change` is
  the choke point for capturing source app identity via `GetClipboardOwner`.
  Currently it only reads the text and classifies.

- `dlp-user-ui/src/ipc/pipe3.rs` — `ClipboardAlert` Pipe 3 message
  would need to grow `source_application: Option<AppIdentity>` and
  `destination_application: Option<AppIdentity>` fields. This is a
  protocol change that ripples into the Phase 99 integration tests.

- `dlp-agent/src/ipc/pipe3.rs:197-233` — the `ClipboardAlert` handler on
  the agent side would need to populate the audit event's application
  fields from the new Pipe 3 payload.

- `dlp-agent/src/detection/` — there is existing detector infrastructure
  for file/network/USB events. A new `detection/application.rs` module
  could house the Win32 calls (`GetForegroundWindow`, `OpenProcess`,
  `QueryFullProcessImageNameW`, `WinVerifyTrust`).

- `docs/ABAC_POLICIES.md` — the ABAC policy doc that would need to be
  extended with the new attributes and example rules.

- `docs/THREAT_MODEL.md` — already discusses clipboard exfiltration as a
  threat (THREAT-016, THREAT-025). Application-awareness is a direct
  mitigation for "data pasted into untrusted app".

- `docs/SRS.md` §2.2 — the co-process model describes what runs where.
  Destination app detection MUST run in dlp-user-ui (user session) because
  `GetForegroundWindow` is per-session. Source detection via
  `GetClipboardOwner` also must be user-session.

## Dependencies on other planned work

- **Phase 99 (DONE)** — clipboard monitoring integration test harness.
  When this seed is implemented, those tests must be extended to cover
  source/destination app combinations.
- **Phase 5 (Pending)** — policy sync for multi-replica. New attributes
  must flow through policy sync without breaking.
- **Phase 7 (Pending)** — AD LDAP integration. User group + app combo
  policies become possible (e.g., "Finance group may paste T3 into
  Excel but not into any other app").

## Risks and Open Questions

1. **Browser coverage is hard.** Detecting that the destination is "Gmail"
   vs "Outlook Web" inside Chrome requires inspecting the current tab URL
   via UIAutomation or browser extension hooks. Simply blocking "any paste
   into Chrome" is too blunt — users need to paste non-sensitive data
   into business web apps constantly.

2. **Electron apps all look alike.** Slack, Teams, VSCode, Discord,
   Notion, ChatGPT Desktop — they are all `electron.exe` under different
   names. Signature-based allowlisting works but requires maintaining a
   publisher allowlist.

3. **Clipboard ownership races.** `GetClipboardOwner` returns the HWND
   of the window that owned the clipboard *at the time of the last
   SetClipboardData*. If that window closes before we capture, we get
   a dead HWND. Need to capture synchronously on WM_CLIPBOARDUPDATE.

4. **UWP apps use AUMID, not image path.** Need a separate code path
   using `IShellItem` / `GetApplicationUserModelId`.

5. **What about drag-drop?** The idea explicitly mentions copy/paste,
   but drag-drop is the other common exfiltration path. Same attack
   surface, different Win32 APIs. Defer or include?

6. **What about print and save-as?** Notepad++ doesn't just paste —
   it saves. A full solution also covers "app X may not save to path
   outside of allowed list", which is file-monitor territory, not
   clipboard.

## Notes

**Inferences made at planting time** (verify before surfacing):
- **Trigger**: I chose multi-condition OR trigger rather than a single
  milestone anchor, because this idea touches several subsystems. The
  first matching trigger should surface it.
- **Scope = large**: I made this call based on the 8-item subsystem list
  above. If you disagree (e.g., you want to ship a minimal "block paste
  into non-signed apps at T3+" phase-sized slice first), edit the frontmatter.
- **Planted during v0.2.0** — the current milestone. Changing this won't
  affect triggering, just the audit trail.

**Minimum viable slice** (if you want to ship a phase-sized version
before the full milestone):
- Capture destination process image path at paste time
- Hardcode a trusted list: Microsoft Office family + VSCode + a dev-tool set
- Block T3+ paste into anything not on the list
- No source tracking, no signature validation, no per-user policies
- One phase, ~3-5 days of work

This minimum slice would prove the concept end-to-end and surface the
real UX issues before committing to the full milestone.
