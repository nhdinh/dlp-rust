# Phase 54: Admin TUI Protected Paths + Bypass Alerts Screens - Research

**Researched:** 2026-05-28
**Domain:** Rust TUI (ratatui 0.29 + crossterm 0.28), HTTP client patterns, Admin CLI screen architecture
**Confidence:** HIGH

## Summary

Phase 54 delivers two new admin TUI screens that let an operator fully manage Protected Paths and triage Bypass Alerts without touching SQLite, the registry, or any raw config file. This is pure TUI work on `dlp-admin-cli` with **no server changes needed** — Phases 52 and 53 already built the complete REST APIs.

The work follows the established three-file screen pattern: add enum variants to `app.rs`, add dispatch handlers to `screens/dispatch.rs`, add render functions to `screens/render.rs`, add client methods to `client.rs`, and wire menu entry points. Both new screens are list screens (not config forms), so they follow the `LabelList` / `ApprovalList` pattern: scrollable table with `TableState`, pagination, filter cycling, and inline actions.

**Primary recommendation:** Model `ProtectedPathList` after `LabelList` (CRUD + sync actions, filter cycling) and `BypassAlertList` after `ApprovalList` (list with actions, detail popup, ack flow). Both use client-side pagination with page size 20.

---

## User Constraints (from CONTEXT.md)

### Locked Decisions

| ID | Decision |
|----|----------|
| D-01 | Single scrollable list with source badge — `[A]` for auto (dim gray), `[M]` for manual (bright cyan). No separate tabs. |
| D-02 | Tier display as colored text — T3 in yellow, T4 in red. |
| D-03 | Path validation happens server-side via `GetFullPathNameW`. TUI sends raw path string; server returns 400. TUI surfaces as toast. |
| D-04 | Add path via `TextInput` screen with `InputPurpose::AddProtectedPath`. |
| D-05 | Delete requires confirmation via `ConfirmPurpose::DeleteProtectedPath`. Only `manual` entries can be deleted. |
| D-06 | Sync action (`s` key) calls `POST /admin/protected-paths/sync`. Idempotent, preserves manual entries. Shows success toast with count. |
| D-07 | Bypass Alerts compact list view: severity badge, relative timestamp, image_path (truncated), file_path (truncated), correlation_reason. Enter opens detail popup. |
| D-08 | Detail popup shows all `BypassAlertRow` fields. SHA-256 truncated to first 16 chars. `file_object` displayed as hex pointer. |
| D-09 | Only `ack` action exists — `POST /admin/bypass-alerts/{id}/ack`. No dismiss/delete. Acknowledged alerts visually dimmed and filterable. |
| D-10 | Severity filter cycles: All → Crit → Warn → Info → All (bound to `f` key). Maps to `severity` query param. |
| D-11 | Acknowledged toggle (bound to `h` key for "hide ack'd") — cycles between unacknowledged-only and all. Maps to `acknowledged=false` or no filter. |
| D-12 | Manual refresh via `r` key — no auto-refresh timer. |
| D-13 | Protected Paths keys: `a`=add, `d`=delete (manual only), `s`=sync, `r`=refresh, Esc=back to SystemMenu. |
| D-14 | Bypass Alerts keys: `a`=ack, `f`=cycle severity filter, `h`=toggle hide-acknowledged, `r`=refresh, Enter=detail, Esc=back to SystemMenu. |
| D-15 | Navigation keys: Up/Down follow `nav()` helper; PageUp/PageDown for pagination. |
| D-16 | Both screens live in `SystemMenu` — indices 10 and 11, pushing "Back" to index 12. |
| D-17 | Client-side pagination with fixed page size of 20. Server supports `limit`/`offset`. Status bar shows "Page 1/3 (45 total)". |

### Claude's Discretion
- Protected Paths list sorted by path alphabetically (server-side `ORDER BY path`).
- Bypass Alerts list sorted by `created_at DESC` (newest first, server-side).
- Optimistic UI on ack: mark row as acknowledged locally immediately, show success toast. Revert + error toast on server failure.
- Error toasts use `StatusKind::Error` (red), success toasts use `StatusKind::Success` (green), neutral uses `StatusKind::Info` (white).
- `file_object` field displayed as hex (e.g., `0x00007FF6...`).

### Deferred Ideas (OUT OF SCOPE)
- Bulk add/remove for protected paths
- Bulk ack for bypass alerts
- Real-time auto-refresh feed for bypass alerts
- Graphical path browser dialog
- Bypass alert dismissal separate from ack
- Email/webhook notification on new bypass alert
- Copy SHA-256 or path to clipboard from detail view

---

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| UX-01 | Protected Paths screen: scrollable list with source badge, add/remove/sync actions, pagination | `LabelList` pattern in dispatch.rs (lines 5682-5773) and render.rs (lines 2665-2770) |
| UX-02 | Bypass Alerts screen: paginated event feed with detail popup, ack action, severity/acknowledged filters | `ApprovalList` pattern in dispatch.rs (lines 5300-5480) and render.rs (lines 3470-3601) |

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| TUI rendering | Client (ratatui) | — | All rendering happens in dlp-admin-cli terminal |
| HTTP API calls | Client (reqwest) | — | EngineClient makes blocking async calls via tokio runtime |
| Path validation | API / Backend | — | Server-side `GetFullPathNameW` (Phase 52) |
| Data persistence | API / Backend | — | SQLite via server repositories (Phases 52/53) |
| Pagination logic | Client | API | Client tracks page state; server provides limit/offset |
| Filter state | Client | — | Filter enums cycle client-side; sent as query params |

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| ratatui | 0.29 | Terminal UI widgets (Table, List, Paragraph, Block) | Project standard; all existing screens use it [VERIFIED: STACK.md] |
| crossterm | 0.28 | Cross-platform terminal event handling | Paired with ratatui; KeyCode, KeyEvent patterns [VERIFIED: STACK.md] |
| reqwest | 0.12 | HTTP client for EngineClient | Project standard; async with blocking wrapper [VERIFIED: STACK.md] |
| serde_json | 1.x | JSON deserialization of API responses | All TUI screens use `serde_json::Value` for API data [VERIFIED: codebase] |
| tokio | 1.x | Async runtime for blocking HTTP calls | `app.rt.block_on()` pattern throughout [VERIFIED: codebase] |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| urlencoding | 2.x | Query parameter encoding | Filter values in client query strings [VERIFIED: client.rs] |
| chrono | 0.4 | Relative timestamp formatting | "2m ago" display for bypass alerts [VERIFIED: Cargo.toml] |

**No new external dependencies required.** All needed crates are already in `dlp-admin-cli/Cargo.toml`.

---

## Package Legitimacy Audit

No new external packages are installed in this phase. All dependencies are already present in the workspace.

---

## Architecture Patterns

### System Architecture Diagram

```
Operator Keyboard
       |
       v
+---------------+     +------------------+     +------------------+
|  dlp-admin-cli | --> |  EngineClient    | --> |  dlp-server      |
|  (ratatui TUI) |     |  (reqwest 0.12)  |     |  (axum 0.8)      |
|                |     |                  |     |                  |
|  Screen enum   |     |  get/post/put/   |     |  /admin/protected|
|  dispatch.rs   |     |  delete helpers  |     |  -paths          |
|  render.rs     |     |                  |     |  /admin/bypass-  |
+---------------+     +------------------+     |  alerts          |
       ^                                       +------------------+
       |                                               |
       +-----------------------------------------------+
                    JSON responses (serde_json::Value)
```

### Recommended Project Structure (no changes needed)

```
dlp-admin-cli/src/
├── app.rs              # Screen enum, filter enums, purpose enums, App struct
├── client.rs           # EngineClient + new methods
├── screens/
│   ├── dispatch.rs     # Event handlers for new screen variants
│   ├── render.rs       # Draw functions for new screen variants
│   ├── labels.rs       # Constants pattern (model new constants files after this)
│   └── approvals.rs    # Constants pattern (model new constants files after this)
```

### Pattern 1: Screen Lifecycle (List Screen)
**What:** Every list screen follows the same lifecycle: enum variant → dispatch handler → render function → client method → menu entry.
**When to use:** Both `ProtectedPathList` and `BypassAlertList` are list screens.
**Example (from LabelList):**
```rust
// 1. Enum variant in app.rs
pub enum Screen {
    LabelList {
        labels: Vec<serde_json::Value>,
        selected: usize,
        filter: LabelFilter,
        page: usize,
        page_size: usize,
        total: usize,
    },
}

// 2. Dispatch routing in dispatch.rs handle_event()
Screen::LabelList { .. } => handle_label_list(app, key),

// 3. Render routing in render.rs draw_screen()
Screen::LabelList { labels, selected, filter, page, page_size, total } => {
    draw_label_list(frame, area, labels, *selected, *filter, *page, *page_size, *total);
}

// 4. Client method in client.rs
pub async fn list_labels(&self, ...) -> Result<PaginatedLabelsResponse> { ... }

// 5. Menu entry in handle_system_menu()
8 => action_load_label_review_queue(app),
```

### Pattern 2: Two-Phase Borrow in Dispatch Handlers
**What:** Read scalar fields with a shared borrow first, then re-borrow mutably for modifications. This avoids Rust borrow checker conflicts.
**When to use:** All dispatch handlers that need to read state before mutating.
**Example (from handle_label_list, dispatch.rs:5683-5693):**
```rust
fn handle_label_list(app: &mut App, key: KeyEvent) {
    let (labels, selected, filter, page, page_size, total) = match &mut app.screen {
        Screen::LabelList { labels, selected, filter, page, page_size, total } =>
            (labels.clone(), selected, *filter, *page, *page_size, *total),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if !labels.is_empty() { nav(selected, labels.len(), key.code); }
        }
        // ... other keys
    }
}
```

### Pattern 3: Filter Enum with Cycling
**What:** An enum representing filter state with `next()` for cycling and `as_str()` / `label()` for wire format.
**When to use:** Both new screens need filter enums.
**Example (from ApprovalFilter, app.rs:443-479):**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApprovalFilter {
    #[default]
    All,
    Pending,
    Approved,
    // ...
}

impl ApprovalFilter {
    pub fn next(self) -> Self { /* cycle through variants */ }
    pub fn as_str(self) -> Option<&'static str> { /* wire format */ }
}
```

### Pattern 4: Action Functions (Async Blocking)
**What:** Functions that clone data from screen state, call `app.rt.block_on(app.client.xxx())`, handle Ok/Err with `app.set_status()`, and transition screen on success.
**When to use:** All CRUD operations that need server round-trips.
**Example (from action_load_approval_list, dispatch.rs:5622-5665):**
```rust
fn action_load_approval_list(app: &mut App, filter: ApprovalFilter, page: u32) {
    let per_page = 50u32;
    let status_filter = filter.as_str();
    match app.rt.block_on(app.client.list_approvals(status_filter, page, per_page)) {
        Ok(response) => {
            let approvals = response.get("approvals").and_then(|a| a.as_array()).cloned().unwrap_or_default();
            let total = response.get("total").and_then(|t| t.as_i64()).unwrap_or(0);
            app.set_status(format!("Loaded {} approvals", approvals.len()), StatusKind::Success);
            app.screen = Screen::ApprovalList { approvals, selected: 0, filter, page, per_page, total, status_message: String::new() };
        }
        Err(e) => app.set_status(format!("Error loading approvals: {e}"), StatusKind::Error),
    }
}
```

### Pattern 5: Table-Based List with TableState
**What:** ratatui `Table` widget with `TableState` for row selection highlighting.
**When to use:** All list screens (LabelList, ApprovalList, DeviceList, etc.).
**Example (from draw_label_list, render.rs:2665-2770):**
```rust
let header = Row::new(vec!["Path", "Type", "Tier", "State", "Owner"])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(1);

let rows: Vec<Row> = labels.iter().map(|l| {
    Row::new(vec![
        l["path"].as_str().unwrap_or("-").to_string(),
        // ... other columns
    ])
}).collect();

let table = Table::new(rows, widths)
    .header(header)
    .block(Block::default().title("Label Management").borders(Borders::ALL))
    .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD))
    .highlight_symbol("> ");

let mut state = ratatui::widgets::TableState::default();
state.select(Some(selected));
frame.render_stateful_widget(table, area, &mut state);
```

### Pattern 6: Constants File for Hints
**What:** A dedicated module (e.g., `screens/labels.rs`, `screens/approvals.rs`) containing only string constants shared between dispatch and render.
**When to use:** Both new screens should have their own constants files.
**Example (from screens/labels.rs):**
```rust
pub const LABEL_LIST_HINTS: &str = "[n] New  [e] Edit  [d] Delete  [v] View  [f] Filter  [x] Expire  [PgUp/PgDn] Page  [Esc] Back";
pub const LABEL_LIST_EMPTY: &str = "No labels found. Press [n] to create one.";
```

### Anti-Patterns to Avoid
- **Do NOT add strongly-typed structs for API responses in the TUI.** The existing pattern uses `serde_json::Value` everywhere. Deviating introduces deserialization risk and inconsistency.
- **Do NOT use `unwrap()` in production code paths.** Use `if let Some()` or `and_then` chains with fallback defaults (e.g., `unwrap_or("-")`).
- **Do NOT mutate `app.screen` while holding a borrow of its fields.** Use the two-phase read-then-mutate pattern.
- **Do NOT forget to update `handle_system_menu` item count.** Adding two menu items changes `nav(selected, 12, key.code)` to `nav(selected, 14, key.code)`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Table rendering with selection | Custom row highlighting | `ratatui::widgets::Table` + `TableState` | Already used by 6+ screens; handles scrolling, styling, headers |
| Pagination math | Manual page calculations | `total.div_ceil(page_size)` | Used by LabelList; standard Rust pattern |
| HTTP query string building | String concatenation | `urlencoding::encode` + `format!` | Used by client.rs list methods; prevents encoding bugs |
| Relative time display | Custom duration formatter | `chrono` humanize or simple minute/hour/day buckets | chrono already in dependency tree |
| Confirmation dialog | Inline yes/no in list handler | Reuse `Screen::Confirm` + `ConfirmPurpose` | Already handles Esc, Enter, Left/Right, y/n keys |
| Text input for path entry | Custom input widget | Reuse `Screen::TextInput` + `InputPurpose` | Already handles typing, backspace, Enter, Esc |

---

## Runtime State Inventory

Phase 54 is a greenfield TUI feature addition. No rename, refactor, or migration is involved. No runtime state inventory needed.

---

## Common Pitfalls

### Pitfall 1: Borrow Checker Conflicts in Dispatch Handlers
**What goes wrong:** Attempting to read fields from `app.screen` while also needing to mutate `app.screen` or call methods on `app` causes compile-time borrow errors.
**Why it happens:** `app.screen` is a single field; borrowing it exclusively prevents borrowing `app` for method calls.
**How to avoid:** Use the two-phase pattern: (1) clone/extract needed fields with a match on `&mut app.screen`, (2) use the cloned values in logic, (3) re-borrow `&mut app.screen` only for mutations. See `handle_label_list` and `handle_approval_list` for canonical examples.
**Warning signs:** Compiler error "cannot borrow `app` as mutable more than once at a time" in dispatch handlers.

### Pitfall 2: Menu Index Drift
**What goes wrong:** Adding new menu items without updating the item count in `nav()` or the Enter match arms causes wrong selection behavior or panics.
**Why it happens:** `SystemMenu` currently has 12 items (indices 0-11). Adding two items makes it 14 (indices 0-13), pushing "Back" from index 11 to 13.
**How to avoid:** Update `nav(selected, 14, key.code)` in `handle_system_menu`, add two new match arms, and update the Esc return routing for any screens that navigate back to SystemMenu.
**Warning signs:** "Back" menu item is no longer selectable, or selecting an item opens the wrong screen.

### Pitfall 3: Forgetting to Add Screen Variant to handle_event Match
**What goes wrong:** New `Screen` enum variants compile fine but key events are silently ignored because `handle_event` doesn't route them.
**Why it happens:** The match in `handle_event` (dispatch.rs:44-86) must have an arm for every non-read-only screen variant.
**How to avoid:** Add routing arms for `ProtectedPathList`, `BypassAlertList`, and `BypassAlertDetail` in `handle_event`. Follow the existing pattern.
**Warning signs:** Screen renders but keyboard is unresponsive.

### Pitfall 4: Filter Enum Wire Format Mismatch
**What goes wrong:** The filter enum's `as_str()` returns values that don't match the server's query parameter expectations.
**Why it happens:** Server expects `"crit"`, `"warn"`, `"info"` for severity; client might send different casing.
**How to avoid:** Match the server's `BypassAlertQuery.severity` field exactly. The server splits on commas and trims, so single values are fine.
**Warning signs:** Filter changes but list contents don't change; server logs show unrecognized query params.

### Pitfall 5: Pagination Off-by-One
**What goes wrong:** Page numbers are inconsistent between client (0-based or 1-based) and server.
**Why it happens:** `LabelList` uses 0-based pages; `ApprovalList` uses 1-based pages. The server APIs differ.
**How to avoid:** For Protected Paths (no existing server-side pagination), use 0-based `limit`/`offset` consistently. For Bypass Alerts, check the server's response format — the existing `list_bypass_alerts_handler` returns `total` but no explicit page number; client tracks its own offset.
**Warning signs:** PageUp/PageDown navigate incorrectly; "Page 1 of 3" shows wrong data.

### Pitfall 6: Optimistic UI Revert on Error
**What goes wrong:** On ack failure, the local optimistic state is not reverted, leaving the UI out of sync with the server.
**Why it happens:** The ack handler needs to both update local state AND handle the async error case.
**How to avoid:** Set local `acknowledged = true` immediately, then call `ack_bypass_alert()`. On `Err(e)`, set it back to `false` and show error toast. On `Ok(())`, show success toast.
**Warning signs:** Alert appears acked in TUI but reappears on refresh.

---

## Code Examples

### Adding a New Screen Variant
```rust
// In app.rs, add to Screen enum:
/// Protected path management list screen.
/// Pattern: LabelList — scrollable table with CRUD actions and sync.
ProtectedPathList {
    paths: Vec<serde_json::Value>,
    selected: usize,
    page: usize,
    page_size: usize,
    total: usize,
},

/// Bypass alert triage list screen.
/// Pattern: ApprovalList — scrollable table with ack action and filters.
BypassAlertList {
    alerts: Vec<serde_json::Value>,
    selected: usize,
    filter: BypassAlertSeverityFilter,
    hide_acknowledged: bool,
    page: usize,
    page_size: usize,
    total: usize,
    status_message: String,
},

/// Bypass alert detail popup (read-only).
BypassAlertDetail {
    alert: serde_json::Value,
},
```

### Adding a Filter Enum
```rust
// In app.rs:
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BypassAlertSeverityFilter {
    #[default]
    All,
    Crit,
    Warn,
    Info,
}

impl BypassAlertSeverityFilter {
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Crit,
            Self::Crit => Self::Warn,
            Self::Warn => Self::Info,
            Self::Info => Self::All,
        }
    }

    pub fn as_str(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::Crit => Some("crit"),
            Self::Warn => Some("warn"),
            Self::Info => Some("info"),
        }
    }
}
```

### Adding EngineClient Methods
```rust
// In client.rs:
/// Calls GET /admin/protected-paths.
pub async fn list_protected_paths(&self) -> Result<Vec<serde_json::Value>> {
    self.get("admin/protected-paths").await
}

/// Calls POST /admin/protected-paths.
pub async fn create_protected_path(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
    self.post("admin/protected-paths", body).await
}

/// Calls PUT /admin/protected-paths/{id}.
pub async fn update_protected_path(&self, id: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    self.put(&format!("admin/protected-paths/{id}"), body).await
}

/// Calls DELETE /admin/protected-paths/{id}.
pub async fn delete_protected_path(&self, id: &str) -> Result<()> {
    self.delete(&format!("admin/protected-paths/{id}")).await
}

/// Calls POST /admin/protected-paths/sync.
pub async fn sync_protected_paths(&self) -> Result<serde_json::Value> {
    self.post("admin/protected-paths/sync", &serde_json::json!({})).await
}

/// Calls GET /admin/bypass-alerts with optional filters.
pub async fn list_bypass_alerts(
    &self,
    severity: Option<&str>,
    acknowledged: Option<bool>,
    limit: usize,
    offset: usize,
) -> Result<serde_json::Value> {
    let mut path = format!("admin/bypass-alerts?limit={limit}&offset={offset}");
    if let Some(s) = severity {
        path.push_str(&format!("&severity={}", urlencoding::encode(s)));
    }
    if let Some(a) = acknowledged {
        path.push_str(&format!("&acknowledged={a}"));
    }
    self.get(&path).await
}

/// Calls POST /admin/bypass-alerts/{id}/ack.
pub async fn ack_bypass_alert(&self, id: i64) -> Result<()> {
    let url = self.build_url(&format!("admin/bypass-alerts/{id}/ack"));
    let resp = self.apply_auth(self.inner.post(&url)).send().await
        .with_context(|| format!("POST {url} failed"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST {url} returned {status}: {body}");
    }
    Ok(())
}
```

### Dispatch Handler Pattern (ProtectedPathList)
```rust
fn handle_protected_path_list(app: &mut App, key: KeyEvent) {
    let (paths, selected, page, page_size, total) = match &mut app.screen {
        Screen::ProtectedPathList { paths, selected, page, page_size, total } =>
            (paths.clone(), selected, *page, *page_size, *total),
        _ => return,
    };
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if !paths.is_empty() { nav(selected, paths.len(), key.code); }
        }
        KeyCode::Char('a') => {
            app.screen = Screen::TextInput {
                prompt: "Protected path (e.g., C:\\Sensitive)".to_string(),
                input: String::new(),
                purpose: InputPurpose::AddProtectedPath,
            };
        }
        KeyCode::Char('d') => {
            if let Some(path) = paths.get(*selected) {
                let source = path["source"].as_str().unwrap_or("");
                if source == "manual" {
                    let id = path["id"].as_str().unwrap_or_default().to_string();
                    let path_str = path["path"].as_str().unwrap_or("<unnamed>").to_string();
                    app.screen = Screen::Confirm {
                        message: format!("Delete protected path '{path_str}'?"),
                        yes_selected: false,
                        purpose: ConfirmPurpose::DeleteProtectedPath { id },
                    };
                } else {
                    app.set_status("Only manual entries can be deleted", StatusKind::Error);
                }
            }
        }
        KeyCode::Char('s') => action_sync_protected_paths(app),
        KeyCode::Char('r') => action_load_protected_path_list(app, page),
        KeyCode::PageUp => {
            if page > 0 { action_load_protected_path_list(app, page - 1); }
        }
        KeyCode::PageDown => {
            if (page + 1) * page_size < total { action_load_protected_path_list(app, page + 1); }
        }
        KeyCode::Esc => app.screen = Screen::SystemMenu { selected: 10 },
        _ => {}
    }
}
```

### Render Function Pattern (BypassAlertList)
```rust
fn draw_bypass_alert_list(
    frame: &mut Frame,
    area: Rect,
    alerts: &[serde_json::Value],
    selected: usize,
    filter: BypassAlertSeverityFilter,
    hide_acknowledged: bool,
    page: usize,
    page_size: usize,
    total: usize,
) {
    if alerts.is_empty() {
        let paragraph = Paragraph::new(BYPASS_ALERT_LIST_EMPTY)
            .block(Block::default().title("Bypass Alerts (0)").borders(Borders::ALL))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(paragraph, area);
        draw_hints(frame, area, BYPASS_ALERT_LIST_HINTS);
        return;
    }

    let filter_suffix = if filter != BypassAlertSeverityFilter::All {
        format!(" [Severity: {}]", filter.as_str().unwrap_or(""))
    } else {
        String::new()
    };
    let ack_suffix = if hide_acknowledged { " [Hide Ack'd]" } else { "" };

    let total_pages = total.div_ceil(page_size).max(1);
    let page_info = format!("Page {} of {} | {} per page", page + 1, total_pages, page_size);

    let header = Row::new(vec!["Severity", "Time", "Image", "File", "Reason"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = alerts.iter().map(|a| {
        let severity = a["severity"].as_str().unwrap_or("-");
        let acked = a["ack_by"].is_string();
        let severity_style = match severity {
            "crit" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            "warn" => Style::default().fg(Color::Yellow),
            "info" => Style::default().fg(Color::Blue),
            _ => Style::default(),
        };
        let time = a["created_at"].as_str().unwrap_or("-");
        let image = a["image_path"].as_str().unwrap_or("-");
        let file = a["file_path"].as_str().unwrap_or("-");
        let reason = a["correlation_reason"].as_str().unwrap_or("-");

        Row::new(vec![
            Cell::from(severity.to_string()).style(severity_style),
            Cell::from(time.to_string()),
            Cell::from(if image.len() > 25 { format!("{}...", &image[..22]) } else { image.to_string() }),
            Cell::from(if file.len() > 25 { format!("{}...", &file[..22]) } else { file.to_string() }),
            Cell::from(reason.to_string()),
        ])
    }).collect();

    let widths = [
        Constraint::Percentage(10),
        Constraint::Percentage(15),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .title(format!(" Bypass Alerts ({}){}{} ", alerts.len(), filter_suffix, ack_suffix))
            .borders(Borders::ALL))
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    let mut state = ratatui::widgets::TableState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(table, area, &mut state);

    let hint_text = format!("{BYPASS_ALERT_LIST_HINTS}  |  {page_info}");
    draw_hints(frame, area, &hint_text);
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `LabelList` used 0-based page numbers | `ApprovalList` uses 1-based page numbers | Phase 61 | Inconsistent pagination base across screens; new screens should pick one and document it |
| Direct `app.client.get()` calls in dispatch | `action_*` helper functions | Phase 38+ | Cleaner separation; all new screens should use action helpers |

**Deprecated/outdated:**
- None identified for this phase.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The server returns `ProtectedPathResponse` JSON with fields: `id`, `path`, `source`, `is_override`, `tier`, `label_id`, `created_at`, `updated_at` | Server API Summary | Client would fail to parse or display fields; verify with Phase 52 artifacts |
| A2 | The server `list_bypass_alerts` endpoint returns JSON with `total` and `alerts` array, where each alert has all `BypassAlertRow` fields | Server API Summary | Client deserialization would fail; verify with Phase 53 artifacts |
| A3 | `ack_bypass_alert` returns 200 on success and 404 if alert not found | Server API Summary | Error handling would be wrong; verify with admin_api.rs tests |
| A4 | No new crates need to be added to `dlp-admin-cli/Cargo.toml` | Standard Stack | If chrono humanize or similar is needed, dependency must be added |

---

## Open Questions

1. **Protected Paths server pagination:** Does `GET /admin/protected-paths` support `limit`/`offset` query params, or does it return the full list?
   - What we know: `list_all()` in repository orders by `path ASC` with no limit.
   - What's unclear: Whether the handler accepts pagination params.
   - Recommendation: Check Phase 52 artifacts. If no pagination, fetch full list and paginate client-side (simpler). If pagination exists, follow the `LabelList` pattern.

2. **Bypass alert relative timestamp formatting:** Should the TUI compute "2m ago" client-side from `created_at`, or does the server provide it?
   - What we know: `created_at` is ISO-8601 string.
   - What's unclear: Whether to use a simple bucket approach ("<1m", "5m", "1h", "1d") or chrono's relative formatting.
   - Recommendation: Use simple bucket approach to avoid adding new dependencies.

3. **Bypass alert detail popup — should it be a modal overlay or a full screen?**
   - What we know: `ApprovalDetail` is a full screen that returns to the list on Enter/Esc.
   - What's unclear: Whether BypassAlertDetail should follow the same pattern or use a modal overlay like `ConditionsBuilder`.
   - Recommendation: Follow `ApprovalDetail` pattern (full screen) for consistency.

---

## Environment Availability

Phase 54 is pure code changes within `dlp-admin-cli`. No external dependencies beyond the existing Rust toolchain and workspace crates.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | Compilation | Yes | 1.75+ | — |
| cargo | Build/test | Yes | — | — |
| ratatui 0.29 | TUI rendering | Yes (in Cargo.lock) | 0.29 | — |
| crossterm 0.28 | Event handling | Yes (in Cargo.lock) | 0.28 | — |
| reqwest 0.12 | HTTP client | Yes (in Cargo.lock) | 0.12 | — |

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Built-in `#[test]` + `ratatui::backend::TestBackend` |
| Config file | None — inline `#[cfg(test)]` modules |
| Quick run command | `cargo test -p dlp-admin-cli` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| UX-01 | ProtectedPathList renders table with paths | unit (render) | `cargo test -p dlp-admin-cli draw_protected_path_list` | No — new tests needed |
| UX-01 | ProtectedPathList handles 'a' key → TextInput | unit (dispatch) | `cargo test -p dlp-admin-cli handle_protected_path_list` | No — new tests needed |
| UX-01 | ProtectedPathList handles 'd' key on manual → Confirm | unit (dispatch) | `cargo test -p dlp-admin-cli handle_protected_path_list_delete` | No — new tests needed |
| UX-01 | ProtectedPathList handles 's' key → sync | unit (dispatch) | `cargo test -p dlp-admin-cli action_sync_protected_paths` | No — new tests needed |
| UX-02 | BypassAlertList renders table with severity badges | unit (render) | `cargo test -p dlp-admin-cli draw_bypass_alert_list` | No — new tests needed |
| UX-02 | BypassAlertList handles 'a' key → optimistic ack | unit (dispatch) | `cargo test -p dlp-admin-cli handle_bypass_alert_list_ack` | No — new tests needed |
| UX-02 | BypassAlertList handles 'f' key → cycle severity filter | unit (dispatch) | `cargo test -p dlp-admin-cli bypass_alert_severity_filter_next` | No — new tests needed |
| UX-02 | BypassAlertDetail renders all fields | unit (render) | `cargo test -p dlp-admin-cli draw_bypass_alert_detail` | No — new tests needed |

### Sampling Rate
- **Per task commit:** `cargo test -p dlp-admin-cli`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `dlp-admin-cli/src/screens/render.rs` — render tests for new draw functions
- [ ] `dlp-admin-cli/src/screens/dispatch.rs` — dispatch tests for new handlers
- [ ] `dlp-admin-cli/src/client.rs` — client method tests (can use `EngineClient::for_test()`)
- [ ] `dlp-admin-cli/src/app.rs` — enum variant tests (follow existing pattern)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | JWT already handled by EngineClient |
| V3 Session Management | No | Token managed by EngineClient |
| V4 Access Control | Yes | Only admin JWT can access these endpoints; server enforces |
| V5 Input Validation | Yes | Path validation server-side (`GetFullPathNameW`); TUI sends raw input |
| V6 Cryptography | No | No crypto in TUI layer |
| V7 Error Handling | Yes | Error toasts must NOT leak sensitive path data |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Path traversal in user input | Tampering | Server validates with `GetFullPathNameW`; TUI does not pre-validate |
| Information disclosure in error messages | Information Disclosure | Error toasts show server error body; ensure server doesn't leak internal paths |
| Unauthorized deletion of auto-derived paths | Elevation of Privilege | TUI checks `source == "manual"` before allowing delete; server also enforces |

---

## Sources

### Primary (HIGH confidence)
- `dlp-admin-cli/src/app.rs` — Screen enum, filter enums, App struct, StatusKind
- `dlp-admin-cli/src/client.rs` — EngineClient generic helpers and existing typed methods
- `dlp-admin-cli/src/screens/dispatch.rs` — handle_event routing, handle_label_list, handle_approval_list, action helpers
- `dlp-admin-cli/src/screens/render.rs` — draw_screen routing, draw_label_list, draw_approval_list, draw_hints
- `dlp-admin-cli/src/screens/labels.rs` — Constants file pattern
- `dlp-admin-cli/src/screens/approvals.rs` — Constants file pattern
- `dlp-server/src/admin_api.rs` — Protected paths handlers (lines ~4845-5030), Bypass alerts handlers (lines ~5235-5298)
- `dlp-server/src/db/repositories/protected_paths.rs` — ProtectedPathRow schema, list_all() orders by path ASC
- `dlp-server/src/db/repositories/bypass_alerts.rs` — BypassAlertRow schema, BypassAlertFilter, list_by_filters() orders by created_at DESC

### Secondary (MEDIUM confidence)
- `.planning/phases/52-dacl-tripwire-repair-watcher-protected-paths-dpapi-recovery-doc/52-06-SUMMARY.md` — Protected Paths Admin API (referenced in CONTEXT.md)
- `.planning/phases/53-etw-kernel-file-consumer-bypass-correlator-hook-journal-ring/53-05-SUMMARY.md` — Bypass Alert Storage (referenced in CONTEXT.md)
- `.planning/codebase/STACK.md` — Dependency versions
- `.planning/codebase/CONVENTIONS.md` — Rust coding standards

### Tertiary (LOW confidence)
- None — all claims verified against source code.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all versions verified in STACK.md and Cargo.lock
- Architecture: HIGH — all patterns verified in existing source code
- Pitfalls: HIGH — all identified from actual code review and compiler behavior

**Research date:** 2026-05-28
**Valid until:** 2026-06-28 (stable stack, low churn expected)

---

## Integration Points — Exact Files and Line Ranges

### Files to Modify

| File | Lines to Modify | Change Type |
|------|----------------|-------------|
| `dlp-admin-cli/src/app.rs` | After line 1074 (before closing `}` of Screen enum) | Add 3 Screen variants + 1 filter enum + 2 purpose variants |
| `dlp-admin-cli/src/app.rs` | After line 126 (ConfirmPurpose enum) | Add `DeleteProtectedPath { id: String }` |
| `dlp-admin-cli/src/app.rs` | After line 62 (InputPurpose enum) | Add `AddProtectedPath` |
| `dlp-admin-cli/src/client.rs` | After line 519 (end of impl EngineClient) | Add 7 new methods |
| `dlp-admin-cli/src/screens/dispatch.rs` | Line 44-86 (handle_event match) | Add 3 routing arms |
| `dlp-admin-cli/src/screens/dispatch.rs` | Line 231-260 (handle_system_menu) | Expand to 14 items, add entries at indices 10, 11 |
| `dlp-admin-cli/src/screens/dispatch.rs` | After line 6110 (end of handle_label_form) | Add handle_protected_path_list, handle_bypass_alert_list, handle_bypass_alert_detail |
| `dlp-admin-cli/src/screens/dispatch.rs` | After line 5665 (action_load_approval_list) | Add action_load_protected_path_list, action_sync_protected_paths, action_load_bypass_alert_list, action_ack_bypass_alert |
| `dlp-admin-cli/src/screens/render.rs` | Line 48-441 (draw_screen match) | Add 3 rendering arms |
| `dlp-admin-cli/src/screens/render.rs` | After line 3770 (end of draw_approval_grant) | Add draw_protected_path_list, draw_bypass_alert_list, draw_bypass_alert_detail |
| `dlp-admin-cli/src/screens/render.rs` | After line 2871 (end of draw_label_review_queue) | Add new draw functions |

### New Files to Create

| File | Purpose |
|------|---------|
| `dlp-admin-cli/src/screens/protected_paths.rs` | Constants: `PROTECTED_PATH_LIST_HINTS`, `PROTECTED_PATH_LIST_EMPTY` |
| `dlp-admin-cli/src/screens/bypass_alerts.rs` | Constants: `BYPASS_ALERT_LIST_HINTS`, `BYPASS_ALERT_LIST_EMPTY`, `BYPASS_ALERT_DETAIL_HINTS` |

### Enum Variants to Add

**Screen enum (app.rs):**
```rust
ProtectedPathList {
    paths: Vec<serde_json::Value>,
    selected: usize,
    page: usize,
    page_size: usize,
    total: usize,
},
BypassAlertList {
    alerts: Vec<serde_json::Value>,
    selected: usize,
    filter: BypassAlertSeverityFilter,
    hide_acknowledged: bool,
    page: usize,
    page_size: usize,
    total: usize,
    status_message: String,
},
BypassAlertDetail {
    alert: serde_json::Value,
},
```

**Filter enum (app.rs):**
```rust
pub enum BypassAlertSeverityFilter { All, Crit, Warn, Info }
```

**ConfirmPurpose enum (app.rs):**
```rust
DeleteProtectedPath { id: String },
```

**InputPurpose enum (app.rs):**
```rust
AddProtectedPath,
```

---

## Pattern Mapping

| New Screen | Closest Existing Analog | Key Differences |
|------------|------------------------|-----------------|
| `ProtectedPathList` | `LabelList` | No filter enum (no filtering needed), adds `s` key for sync action, delete restricted to `manual` entries, source badge coloring |
| `BypassAlertList` | `ApprovalList` | Two filter dimensions (severity + acknowledged) instead of one, `a` key does ack (not grant), optimistic UI on ack, no revoke action |
| `BypassAlertDetail` | `ApprovalDetail` | Different field set (SHA-256, file_object, correlation_reason, qpc_timestamp), no T4 canonical message |
| `ProtectedPathList` add flow | `LabelList` new flow via `TextInput` | Single field (path) instead of multi-step form; server validates path |
| `ProtectedPathList` delete flow | `LabelList` delete flow via `Confirm` | Extra check for `source == "manual"` before showing confirm |

---

*End of Research Document*
