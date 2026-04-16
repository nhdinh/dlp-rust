# Feature Landscape — v0.4.0 Policy Authoring TUI

**Domain:** DLP admin TUI — policy lifecycle management (ratatui, Rust, single-admin)
**Researched:** 2026-04-16
**Scope:** Four feature areas: (1) Policy CRUD screens, (2) Conditions builder, (3) Simulate / dry-run, (4) Import / export

---

## Context: What Already Exists

The existing `dlp-admin-cli` TUI uses a flat Screen enum state machine with these established patterns:

- Navigation: `Up/Down` to move, `Enter` to confirm, `Esc` to go back. Wraps around at ends.
- Inline editing: two-mode cycle (nav mode / edit mode), `Enter` enters edit, `Esc` cancels edit, second `Enter` commits. The `buffer` field holds in-flight text.
- Bool toggles: `Enter` on a bool field flips the value directly (no edit mode needed).
- Confirmation dialogs: `Left/Right` selects Yes/No, `Enter` commits.
- Status bar: bottom 1-line strip, `StatusKind::{Info, Success, Error}`.
- All API calls: `app.rt.block_on(...)` — blocking async on a Tokio runtime kept in `App`. No threading needed.
- `PolicyCondition` is a tagged-union enum with five variants: `Classification`, `MemberOf`, `DeviceTrust`, `NetworkLocation`, `AccessContext`. Each variant has an `op: String` field plus a variant-specific value.
- Current policy CRUD: file-path based (type a JSON file path, submit). v0.4.0 replaces this with in-TUI forms.

---

## Feature Area 1: Policy List + Detail Screens

### Table Stakes

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Scrollable table: id, name, priority, action, enabled | Every mature DLP tool (Purview, Forcepoint, k9s) shows list with key columns at a glance | Low | Use `ratatui::widgets::Table` + `TableState`; `select_next()` / `select_previous()` already proven in codebase |
| Highlight selected row | Standard TUI list interaction; ratatui `TableState` does this automatically | Low | `highlight_style` + `highlight_symbol` (">" prefix) |
| `Enter` to drill into detail | Every admin UI opens a read-only detail view on selection | Low | Reuse existing `PolicyDetail` screen; upgrade from raw JSON dump to structured layout |
| `Esc` returns to Policy menu | Already the codebase convention | None | Consistent with all existing list screens |
| Empty-state message | Policy table with zero rows must explain why ("No policies found") | Low | Conditional render in draw function |
| Status bar: "Loaded N policies" | User needs confirmation that list is fresh | None | Already implemented via `set_status` |
| Inline action keys on list | From list screen: `n` to create, `e` to edit selected, `d` to delete selected, `r` to refresh | Low-Med | Eliminates need for separate PolicyMenu prompts; matches k9s UX (single-letter actions on list) |

### Differentiators

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Priority ordering visible | Policies evaluated lowest-priority-first; list sorted by priority clarifies enforcement order | Low | Sort `Vec<Policy>` by `priority` before rendering; show priority column |
| Enabled/disabled badge | Color-coded: green=enabled, red=disabled; matches enterprise DLP tools | Low | Use `Style::fg(Color::Green)` vs `Color::Red` on enabled column |
| Condition count in list | Shows "#Conditions" column so admin knows policy complexity at a glance | Low | Derive from `conditions.len()` |
| Last-modified / version column | `version: u64` already in Policy struct; useful for change tracking | Low | Show `v{version}` in a narrow column |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Pagination controls (page N of M) | Total policy count will be small (< 100 in enterprise); adds nav complexity for no gain | Rely on ratatui Table's built-in scroll offset, which moves the viewport |
| Column sorting | Out of scope for solo admin TUI; adds state complexity | Hard-code priority-ascending sort as the canonical order |
| Multi-select delete | Dangerous in a DLP admin context; accidental batch delete is catastrophic | Single-select delete with confirmation dialog (already implemented) |

### Dependencies

- Depends on existing `GET /admin/policies` API (already shipped).
- `Enter` from list into detail requires detail screen to support `e` key for transitioning to edit — new `PolicyEdit` screen must be reachable from `PolicyDetail`.

---

## Feature Area 2: Structured Conditions Builder

This is the most novel and complex feature in v0.4.0. There is no direct prior art in the existing TUI.

### Table Stakes

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Attribute picker (step 1) | Every DLP rule builder starts by picking "what attribute to match on" — Purview does this with a sidebar list | Low | Enum over 5 attributes: Classification, MemberOf, DeviceTrust, NetworkLocation, AccessContext |
| Operator picker (step 2) | After attribute, pick the comparison operator. Current `op: String` allows "eq", "ne" | Low | Predefined list per attribute variant; "eq" is the only sensible op for all current variants but show the picker for extensibility |
| Value picker (step 3) | Typed value entry based on attribute selected: enum variants for DeviceTrust/NetworkLocation/AccessContext/Classification; free-text SID for MemberOf | Medium | Enum variants rendered as a scrollable list; MemberOf gets a text input field |
| Conditions list with add/remove | Admin builds a list of conditions, can add more or remove existing ones | Medium | In-TUI list of built conditions; `a` to add, `d` to delete selected |
| Save / cancel | Must commit the full condition list or discard on Esc | Low | Standard confirm flow |

### Differentiators

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Inline preview of generated JSON condition | Show the serialized `PolicyCondition` JSON as the admin builds it, so they see exactly what will be stored | Low | One-line Paragraph widget below the picker |
| Validation: MemberOf SID format check | Silently saving a malformed SID (e.g., missing "S-1-5-") causes silent policy misfires | Low | Regex check `^S-\d-\d+(-\d+)+$` before committing |
| Condition summary labels | Instead of showing raw JSON in the conditions list, show human-readable labels: "Classification == T3", "MemberOf S-1-5-21-..." | Low | Derive from `PolicyCondition` variant in a `Display` impl |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Raw JSON condition text entry | PROJECT.md explicitly rules this out ("Raw JSON conditions editing — replaced by structured conditions builder") | Structured 3-step picker |
| AND/OR/NOT boolean logic between conditions | Current engine evaluates ALL conditions as implicit AND (first-match-wins, all conditions must match). Adding boolean logic requires engine changes not in scope for v0.4.0 | Defer to v0.5.0; document implicit AND in help text |
| Condition reordering | Conditions within one policy are AND-connected — order does not affect outcome | Skip; would add drag-like complexity with no benefit |

### UX Pattern: 3-Step Sequential Picker (ratatui)

The proven TUI pattern for attribute/operator/value pickers in terminal UIs (established by firewall config TUIs and system-config-firewall-tui) is a sequential modal flow:

```
Step 1 — Attribute:         Step 2 — Operator:        Step 3 — Value:
[ ] Classification          [ ] eq                    [ ] T1 (Public)
[*] MemberOf               [*] ne                    [ ] T2 (Internal)
[ ] DeviceTrust                                       [*] T3 (Confidential)
[ ] NetworkLocation                                   [ ] T4 (Restricted)
[ ] AccessContext

        Enter -> next step                  Enter -> add to conditions list
```

Implementation approach that fits the existing Screen enum state machine:

- Add a `ConditionBuilder` screen variant with a `step: ConditionBuilderStep` enum:
  `SelectAttribute | SelectOperator | SelectValue { attribute }`.
- Each step renders a scrollable `List` with the options for that step.
- `Enter` commits the step and advances; `Esc` goes back one step (or exits to PolicyEdit on step 1).
- No separate "wizard" framework needed — the existing `nav()` helper + `List` widget covers this.

### Typed Value Sets Per Attribute

| Attribute Variant | Value Type | Input Method |
|-------------------|------------|--------------|
| `Classification` | `Classification` enum: T1, T2, T3, T4 | Scrollable list (4 items) |
| `MemberOf` | `group_sid: String` | Text input field (existing `TextInput` screen) |
| `DeviceTrust` | `DeviceTrust` enum: Managed, Unmanaged, Compliant, Unknown | Scrollable list (4 items) |
| `NetworkLocation` | `NetworkLocation` enum: Corporate, CorporateVpn, Guest, Unknown | Scrollable list (4 items) |
| `AccessContext` | `AccessContext` enum: Local, Smb | Scrollable list (2 items) |

For `MemberOf`, redirect to the existing `TextInput` screen pattern rather than embedding a text field into the new picker screen.

### Dependencies

- Requires `PolicyEdit` screen (Feature Area 1) to embed the condition list and launch the builder.
- Uses existing `TextInput` screen for MemberOf SID entry.
- No API changes required — conditions serialize to `PolicyCondition` JSON which `POST /admin/policies` already accepts.

---

## Feature Area 3: Policy Simulate / Dry-Run

### Table Stakes

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| EvaluateRequest form: subject fields | Admin needs to fill `user_sid`, `user_name`, optional `groups` (comma-separated SIDs) | Medium | Multi-field form using the existing SiemConfig/AlertConfig row-navigation pattern (navigate rows, Enter to edit) |
| EvaluateRequest form: resource fields | `path` (text), `classification` (enum picker) | Low | |
| EvaluateRequest form: environment fields | `access_context` (enum toggle), `action` (enum picker: READ/WRITE/COPY/DELETE/MOVE/PASTE) | Low | |
| Submit and show result | Call `POST /evaluate`, display `decision`, `matched_policy_id`, `reason` | Low | Reuse `ResultView` screen or a dedicated `SimulateResult` screen |
| Decision color coding | ALLOW=green, DENY=red, ALLOW_WITH_LOG=yellow, DENY_WITH_ALERT=red bold | Low | `Style::fg(Color::*)` on the decision span |

### Differentiators

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Pre-fill from selected policy | If launched from `PolicyDetail`, pre-fill the form with conditions that would exercise that policy | Medium | Derive sensible defaults from the selected policy's conditions; reduces test data entry friction |
| "No match" reason clarity | When `matched_policy_id` is None and decision is DENY, show "Default deny — no matching policy" prominently | Low | Conditionally render extra explanation text |
| Editable history (last run) | Store last simulate inputs in `App` state so admin can re-run with minor tweaks | Low | Add `last_simulate: Option<EvaluateRequest>` to `App`; pre-fill form from this on launch |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Persistent simulation mode (Purview-style 15-day simulation) | Purview runs simulations asynchronously over real data. This system's simulate is a single-shot evaluation call against current policy set | Single-shot `POST /evaluate` response shown immediately |
| Batch simulate (multiple requests at once) | Admin use case is "does this specific request match?" — batch adds complexity with low value | Single evaluate at a time |
| Saving simulate scenarios | Low value for single-admin tool | Defer to post-v0.4.0; use `last_simulate` history as a lightweight substitute |

### UX Pattern: Multi-Field Form (ratatui)

Use the same row-nav + edit-mode pattern as `SiemConfig` and `AlertConfig` screens:

```
Simulate Policy Decision
------------------------
user_sid:           [S-1-5-21-...]
user_name:          [jsmith        ]
groups (comma SIDs):[              ]
device_trust:       [Managed       ] (toggle)
network_location:   [CorporateVpn  ] (toggle)
resource_path:      [C:\Data\...   ]
classification:     [T3            ] (toggle)
access_context:     [Local         ] (toggle)
action:             [COPY          ] (toggle)
                    [Simulate] [Back]
```

For enum fields, use toggle-on-Enter cycling through enum variants (same as bool toggles in AlertConfig, but cycling through N variants instead of 2).

### Dependencies

- Depends on existing `POST /evaluate` API (already shipped).
- `EvaluateRequest` and all sub-types already defined in `dlp-common::abac`.
- No API changes required.

---

## Feature Area 4: Policy Import / Export

### Table Stakes

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Export all policies to a file | Every enterprise policy tool (Check Point, Intune, Forcepoint) supports JSON export for backup/migration | Low | `GET /admin/policies` -> serialize `Vec<Policy>` to JSON or TOML; use `std::fs::write` |
| Import policies from a file | Companion to export; enables disaster recovery and policy migration between environments | Medium | `std::fs::read_to_string` -> deserialize `Vec<Policy>` -> POST each |
| File path prompt | Admin enters destination/source path | None | Reuse existing `TextInput` screen |
| Success/failure summary | "Exported 12 policies to /tmp/policies.json" or "Imported 8/10 policies (2 failed)" | Low | `ResultView` screen |

### Differentiators

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Conflict detection on import: ID collision | If an imported policy ID already exists in the DB, the admin must choose: skip, overwrite, or rename | Medium | For v0.4.0: skip-or-overwrite prompt. Show a summary: "3 conflicts found: overwrite all? [Yes] [No]" — if No, skip conflicting IDs |
| JSON format (not TOML for export) | `Policy` struct already has `Serialize/Deserialize`. JSON is directly round-trippable with the API. TOML would require `serde_toml` and needs array-of-tables format which is awkward for `Vec<Policy>` | Low | Use JSON as the canonical import/export format. TOML is out of scope for v0.4.0 (PROJECT.md lists "TOML or JSON" but JSON alone satisfies R-07/R-08) |
| Export path default suggestion | Default to a timestamped filename: `dlp-policies-YYYY-MM-DD.json` — less friction for admin | Low | `chrono::Utc::now().format(...)` |
| Per-policy import errors visible | If one policy in a batch fails (e.g., malformed condition), continue with others and show a result log | Medium | Collect `(policy_name, result)` tuples and render in `ResultView` |

### Anti-Features

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| TOML export in v0.4.0 | `Vec<Policy>` with nested `PolicyCondition` enum tags maps poorly to TOML's array-of-tables format; the tagged-union serde format (`attribute = "..."`) is not supported by TOML | JSON only; TOML may be added in v0.5.0 if needed |
| Schema versioning / migration | No schema changes planned for v0.4.0; import/export of current `Policy` struct is sufficient | Log the `version` field per policy as-is |
| Diff view (imported vs. existing) | Useful but high complexity — requires a side-by-side layout that ratatui supports poorly in a narrow terminal | Defer; skip-or-overwrite prompt is sufficient |

### Dependencies

- Depends on `GET /admin/policies` (list, for export) and `POST /admin/policies` (create, for import).
- Import conflict detection requires `GET /admin/policies` before import to build a set of existing IDs.
- No new API endpoints required.

---

## MVP Recommendation

**Include in v0.4.0 (POLICY-01 through POLICY-08):**

Priority order based on dependency chain and risk:

1. **Policy list screen with inline action keys** (POLICY-01) — foundation; everything else navigates from here. Low complexity.
2. **Structured conditions builder** (POLICY-05) — most complex; implement first before wrapping it in create/edit forms so it can be tested in isolation.
3. **Policy create form** (POLICY-02) — depends on conditions builder. Medium complexity.
4. **Policy edit form** (POLICY-03) — reuses create form with pre-populated fields. Low incremental complexity.
5. **Policy delete with confirmation** (POLICY-04) — already mostly done (`ConfirmPurpose::DeletePolicy` exists); upgrade to trigger from list screen. Low complexity.
6. **Policy simulate** (POLICY-06) — independent of CRUD; depends only on existing `/evaluate` API. Medium complexity.
7. **Policy export** (POLICY-07) — low complexity; JSON serialization of existing types.
8. **Policy import with conflict detection** (POLICY-08) — depends on export format being stable. Medium complexity.

**Defer (out of scope for v0.4.0):**

- Boolean logic (AND/OR/NOT) between conditions — engine change required.
- TOML export format — awkward serde-toml mapping.
- Batch simulate.
- Condition reordering within a policy.
- Diff view on import.

---

## Sources

- [Microsoft Purview DLP Policy Design](https://learn.microsoft.com/en-us/purview/dlp-policy-design) — MEDIUM confidence (official docs, April 2025)
- [Microsoft Purview DLP Simulation Mode](https://learn.microsoft.com/en-us/purview/dlp-simulation-mode-learn) — MEDIUM confidence (official docs, March 2024)
- [ratatui Table widget docs](https://docs.rs/ratatui/latest/ratatui/widgets/struct.Table.html) — HIGH confidence (official crate docs)
- [ratatui Table example with keyboard nav](https://ratatui.rs/examples/widgets/table/) — HIGH confidence (official ratatui site)
- [Check Point Harmony Endpoint policy import/export](https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Harmony-Endpoint-Admin-Guide/Topics-Common-for-HEP/Import-or-Export-Policies.htm) — MEDIUM confidence (vendor docs)
- [k9s Kubernetes TUI](https://k9scli.io/) — MEDIUM confidence (reference for list+action TUI patterns)
- [ratatui-form crate](https://github.com/DavidLiedle/ratatui-form) — LOW confidence (WebSearch only; not needed given existing pattern in dlp-admin-cli)
- [system-config-firewall-tui (CentOS)](https://jackstromberg.com/2014/04/tutorial-adding-firewall-rules-via-system-config-firewall-tui-on-centos-6/) — LOW confidence (legacy reference for sequential picker pattern)
- Existing `dlp-admin-cli` codebase (`app.rs`, `screens/dispatch.rs`) — HIGH confidence (direct code inspection)
- `dlp-common/src/abac.rs` — HIGH confidence (direct code inspection)
