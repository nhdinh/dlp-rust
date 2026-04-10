---
id: SEED-002
status: dormant
planted: 2026-04-10
planted_during: v0.2.0 feature completion (Phase 4 planning)
trigger_when: "browser integration phase planning begins, OR web-based exfiltration is identified as a priority threat, OR Microsoft Purview / Chrome Enterprise Connector integration is evaluated, OR SEED-001 (application-aware DLP) is being executed and the team hits the 'all browser traffic looks the same' wall"
scope: large
related_seeds: ["SEED-001"]
---

# SEED-002: "Protected Clipboard" browser boundary — trusted/untrusted web app distinction

## The idea (verbatim from planting)

> "Protected Clipboard" in Browsers: Modern DLP tools, particularly
> within Edge for Business, create "trusted boundaries." Data copied
> from a protected, managed application is prevented from being pasted
> into unmanaged apps, such as personal webmail or Generative AI websites.

## Why This Matters

**The browser is the #1 data exfiltration vector in 2025-era enterprises.**
Users routinely have sensitive corporate SaaS open alongside personal
Gmail, ChatGPT, Claude, Google Drive (personal), and pastebin-style
sites — all inside the same `chrome.exe` or `msedge.exe` process.

SEED-001 (application-aware DLP) partially addresses this by treating
"the browser" as an untrusted destination. But that's a sledgehammer:
blocking *all* browser paste destroys legitimate web workflows (ticket
systems, internal wikis, approved SaaS, Salesforce, Jira, Confluence).
Conversely, allowing all browser paste means a T4 classified payload
can walk out of a managed SharePoint tab straight into a ChatGPT prompt
in the adjacent tab, with zero telemetry.

**The core technical gap:** at the OS level, `GetClipboardOwner()` and
`GetForegroundWindow()` return the browser process handle. There is no
way for an OS-level DLP to distinguish:

- SharePoint tab (managed, T3 data OK) vs. ChatGPT tab (unmanaged, block)
- Salesforce (managed) vs. Personal Gmail (unmanaged)
- GitHub Enterprise (managed) vs. GitHub.com public (depends on policy)
- Internal Jira (managed) vs. Notion public workspace (unmanaged)

The decision has to happen **inside the browser**, with knowledge of
the active tab URL/origin and whether that origin is classified as
managed by enterprise policy.

This is exactly what Microsoft Purview, Forcepoint, Netskope, Zscaler,
Symantec Web Isolation, and Island Browser all solve — and it's a
must-have for enterprise DLP competitive parity. Without it, this DLP
will lose every procurement deal where browser exfiltration is the
stated threat model (which is most of them).

## When to Surface

**Trigger conditions** — this seed should be presented during
`/gsd-new-milestone` when ANY of these match:

1. SEED-001 is being executed and the team hits the "browser is opaque"
   wall (this is the most likely trigger — SEED-001 will naturally lead
   here)
2. A milestone explicitly scopes "browser integration" or
   "web DLP" or "SaaS data loss"
3. A pre-sales / enterprise evaluation flags "copy-paste into ChatGPT"
   or "copy-paste into Gmail" as a gating requirement
4. Microsoft Purview / Chrome Enterprise Connector compatibility is
   evaluated
5. A regulatory incident (HIPAA, GDPR, SOX) involves browser-based
   exfiltration and the customer demands a browser-level control
6. v0.4.0+ milestone planning begins — this is realistically a v0.4.0
   or later feature, not v0.3.0

## Scope Estimate

**LARGE** — this is a full milestone on its own, and is dependent on
SEED-001 being at least partially complete. It splits into two very
different delivery paths, and the team must choose:

### Path A: Build a native browser extension (control the stack)

Ship a DLP browser extension for Chrome (Manifest V3) and Edge that:

1. **Tracks active tab origin** via the `tabs` and `activeTab`
   permissions. Every time the tab changes, the extension knows the
   current URL.
2. **Intercepts clipboard events** via the `clipboardRead` /
   `clipboardWrite` permissions and the `document.oncopy` / `onpaste`
   DOM events. When a copy happens, tag the payload with the source
   origin. When a paste happens, check the target origin.
3. **Classifies source origin** — does it match a managed origin list
   from enterprise policy? Managed origins get a "protected" tag.
4. **On paste**, if source is protected AND destination origin is
   unmanaged, block the paste and show a toast; log the event.
5. **Communicates with the native agent** via Native Messaging
   (`chrome.runtime.connectNative`) to the dlp-agent. Agent receives
   the copy/paste events and emits audit events through the existing
   pipeline.
6. **Ships in Chrome Web Store + Edge Add-ons store**, plus a policy
   template for forced-install via Group Policy / Intune.

Estimated subsystems:
- New crate: `dlp-browser-ext-native-host` (native messaging host,
  registered in HKCU\Software\Google\Chrome\NativeMessagingHosts)
- New folder: `browser-extension/` (TypeScript + Manifest V3, built
  with esbuild or vite)
- Policy engine extension: `source_origin` and `destination_origin`
  attributes in AbacContext
- Managed-origins list storage in dlp-server DB (mirror Phase 3.1)
- Admin CLI screen for managing origins (same pattern as SIEM/alert config)
- Audit event enrichment: `source_origin`, `destination_origin`
  fields on AuditEvent (add to dlp-common)
- Agent-side Pipe 3 message type `BrowserClipboardAlert` alongside
  the existing `ClipboardAlert`
- Cross-browser testing (Chrome, Edge, Chromium forks — Brave, Arc, Vivaldi)
- Forced-install policy templates (Chrome JSON, Edge ADMX, Intune)

Rough effort: **6-10 phases, ~1 full milestone**. Requires browser
extension build toolchain (node/npm), extension signing keys for the
stores, and ongoing maintenance as Chrome Manifest V3 evolves.

### Path B: Integrate with Microsoft Purview / Chrome Enterprise Connectors

Instead of building our own extension, plug into existing browser-side
DLP APIs:

1. **Chrome Enterprise Connectors** — Chrome ships a DLP connector API
   (`https://chromeenterprise.google/policies/#OnFileAttachedEnterprise
   Connector`, `OnTextEnteredEnterpriseConnector`, etc.) that POSTs
   copy/paste events to a local or cloud endpoint for scanning. The
   endpoint is this DLP server. Chrome blocks until the endpoint
   responds. Paid / enterprise-managed Chrome only.
2. **Edge for Business DLP integration** — similar to Chrome Connectors,
   exposed via Microsoft Purview Information Protection and Endpoint
   DLP. Edge is already instrumented; we become a Purview policy
   provider or DLP event sink.
3. **Requires customers to be on Chrome Enterprise or Edge for Business**
   — not all customers are, so this is a complementary path, not a
   replacement for Path A.

Estimated subsystems:
- New module: `dlp-server/src/chrome_connector.rs` — HTTPS endpoint
  that matches the Chrome Enterprise Connector scanning protocol
  (OpenAPI schema published by Google)
- New module: `dlp-server/src/edge_connector.rs` — Purview integration
- Admin CLI config for enabling each connector and managing the
  policy rules Chrome/Edge will evaluate against
- Documentation and customer onboarding runbooks

Rough effort: **3-5 phases, ~1/3 milestone**. Much cheaper than Path A
but only works for subset of customers.

### Likely recommendation

Ship Path B first (low effort, immediate value for enterprise Edge/Chrome
customers), then ship Path A in a follow-up milestone for customers on
unmanaged browsers. Document the capability matrix so customers know what
they're getting with each browser deployment mode.

## Breadcrumbs

**Existing code that this seed would extend:**

- `dlp-common/src/audit.rs:147,151` — `AuditEvent` already has
  `application_path` + `application_hash` fields (from SEED-001
  breadcrumbs). This seed would add `source_origin: Option<String>`
  and `destination_origin: Option<String>` for browser-specific events.

- `dlp-common/src/abac.rs` — `AbacContext` would gain origin attributes
  so policy rules can express "IF source_origin matches managed list
  AND destination_origin NOT in managed list AND classification >= T2
  THEN DENY".

- `dlp-user-ui/src/clipboard_monitor.rs` — today only watches the OS
  clipboard via `AddClipboardFormatListener`. Browser-tab-aware events
  would come from a separate source (native messaging host or HTTP
  endpoint) and merge into the same audit flow.

- `dlp-user-ui/src/ipc/pipe3.rs` — Pipe 3 message types currently
  include `ClipboardAlert`. Browser-specific events might reuse this
  with new fields OR add a `BrowserClipboardAlert` variant.

- `dlp-agent/src/ipc/pipe3.rs:197-233` — agent-side ClipboardAlert
  handler. Would need to route browser alerts into the same audit
  emission path with additional context.

- `dlp-server/src/admin_api.rs` — the Phase 3.1 / Phase 4 pattern
  (DB-backed config + admin API + TUI screen) applies directly to
  managed-origin list management.

- `dlp-server/src/db.rs` — new table `managed_origins` listing which
  hostnames/domains count as "protected" for browser paste purposes.
  Might also need `browser_connector_config` for Path B.

- `docs/THREAT_MODEL.md` — THREAT-016 already discusses clipboard
  exfiltration. This seed specifically addresses the "browser is a
  single process with many security boundaries inside" variant that
  SEED-001 can't solve.

- `docs/ABAC_POLICIES.md` — example policy rules referencing origin
  attributes would go here.

- `scripts/` — a forced-install policy template directory would be
  added for Chrome/Edge enterprise deployment.

## Dependencies on other planned work

- **SEED-001 (application-aware DLP)** — STRONG PREREQUISITE. This seed
  only makes sense after the policy engine can express per-app rules.
  The "browser" as a whole needs to be distinguishable from other apps
  (SEED-001) before the browser's *internal* tabs can be distinguished
  (SEED-002). Think of SEED-002 as "SEED-001 drilling one level deeper
  for one specific app family."
- **Phase 7 (AD LDAP integration)** — managed-origin lists are likely
  tied to AD groups ("Sales team's managed origins include Salesforce
  but not Jira"). Benefits from LDAP being in place.
- **Phase 4 (alert router, IN PROGRESS)** — browser paste blocks should
  trigger alerts through the same router. The DB-backed alert config
  pattern is directly reusable.
- **Phase 9 (admin operation audit logging)** — changes to managed-origin
  lists must be audited.

## Risks and Open Questions

1. **Browser extension stores are political.** Chrome Web Store review
   takes days-weeks, can reject enterprise DLP extensions, and revokes
   publisher accounts that violate guidelines. Ship forced-install via
   enterprise policy instead of public store for most customers.

2. **Manifest V3 limits.** MV3 removed blocking web requests and
   background pages. The extension must use service workers and
   `declarativeNetRequest`. Clipboard interception is still possible
   but more constrained than MV2. Research required.

3. **Native messaging security.** The native messaging host registration
   is per-user (HKCU) or per-machine (HKLM). Machine-wide requires admin
   install, which we already have via the installer. Per-extension ID
   allowlisting prevents rogue extensions from talking to the host.

4. **User-owned browsers.** Personal Chrome installed by the user (not
   via enterprise policy) can't be forced to install our extension.
   Customers on BYOD may reject this entirely, or demand we block all
   non-managed browsers.

5. **Other Chromium forks.** Brave, Arc, Vivaldi, Opera all support
   Manifest V3 extensions but have their own stores. Maintenance burden.

6. **Firefox + Safari.** Outside Chromium entirely. Firefox has WebExtensions
   (similar API), Safari uses its own model. Scope carefully.

7. **The "copy once, paste many" problem.** A user copies from managed
   SharePoint, switches to a personal Gmail tab, and pastes. The
   extension sees the paste target but has already lost track of the
   source (because the source tab is now inactive). Solution: the
   extension tags the CLIPBOARD ITSELF at copy time with the source
   origin, and on paste checks the tag. This requires sidecar storage
   because Chrome's clipboard API doesn't expose user-data-on-item.

8. **Data URI / screenshot evasion.** Users copy an image of text
   instead of text. Defeats text-based classification entirely. Need
   OCR + image classification, which is a different rabbit hole.

9. **Generative AI websites specifically.** The arguments mention ChatGPT
   and similar. These are a high-priority subset of "unmanaged" with
   unique characteristics: very long inputs, commonly pasted code /
   documents, unclear data retention policies. A "GenAI-aware" mode
   might warrant its own explicit rule type.

## Notes

**Inferences made at planting time** (verify before surfacing):

- **Prerequisites**: I marked SEED-001 as a STRONG prerequisite because
  solving browser-level granularity without first solving app-level
  granularity is architecturally backwards. If you disagree (e.g., you
  want to ship a browser-only minimum slice as a customer demo), edit
  the dependencies section.

- **Two-path scope (Path A vs Path B)**: I offered both because they
  are fundamentally different engineering investments. The recommendation
  to do B first, then A, is based on cost/benefit and the typical
  enterprise customer mix. If your customer base is mostly unmanaged-
  browser small businesses, flip the order. If your customer base is
  mostly large enterprises already on Edge for Business / Chrome
  Enterprise, maybe you only ever need Path B.

- **Trigger conditions** — I deliberately included "SEED-001 execution
  team hits the browser wall" as a trigger because that is the most
  likely concrete event that will surface this seed. It's self-fulfilling:
  implementing SEED-001's browser detection WILL reveal the limitation.

- **Scope = large**: Path A alone is a full milestone. Path B is smaller
  but still ~3-5 phases. Scope is marked large to reflect the ambitious
  end state, not the minimum viable slice.

**Minimum viable slice** (if you want a phase-sized preview):

- Implement **Chrome Enterprise Connector** endpoint in dlp-server
  (`POST /browser/chrome-connector/scan`) that accepts Chrome's DLP
  scan payloads
- Hardcode a simple managed-domains list (Microsoft 365, SharePoint,
  Teams) and block paste events where the source domain is in the list
  and the destination isn't
- Document required Chrome policy for customers to forced-install the
  connector
- Generates audit events through existing pipeline
- No browser extension, no Edge integration, no admin CLI management
- One phase, ~5-7 days of work

This slice is Path B's smallest increment and proves the concept
without committing to the full Path A extension engineering investment.

**Relationship to SEED-001 summary:**

| Attribute | SEED-001 | SEED-002 |
|---|---|---|
| Scope | Distinguish apps by process identity | Distinguish origins inside a single app (browser) |
| Detection layer | OS (Win32 API) | Browser extension OR browser native DLP API |
| Primary customer type | Any Windows enterprise | Enterprise with managed browser deployment |
| Dependency | None (can ship alone) | SEED-001 (prerequisite) |
| Effort | ~1 milestone | ~1 milestone (Path A) OR ~3-5 phases (Path B) |
| Blast radius | All clipboard and file events | Only browser-mediated events |
| Competitive peer | Symantec DLP, Forcepoint | Microsoft Purview, Netskope, Zscaler, Island Browser |

The two seeds should ideally be planned together — SEED-001 first, then
SEED-002 in a subsequent milestone as a natural extension. Both are
planted now so neither gets lost.
