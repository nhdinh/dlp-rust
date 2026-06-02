---
phase: 58
slug: differentiators-bundle-override-diagnostic-hash-evidence-sel
status: draft
shadcn_initialized: false
preset: none
created: "2026-06-02"
updated: "2026-06-02"
reviewed_at: ""
---

# Phase 58 — UI Design Contract

> Visual and interaction contract for the Diagnostic List screen (DIFF-02) and Self-Health Dashboard (DIFF-04).
> Both screens are admin TUI additions following the established `BypassAlertList` four-file pattern.
> DIFF-01 (Override Flow) and DIFF-03 (Content Hash Evidence) have no new TUI surfaces — they reuse
> existing Phase 61 approval infrastructure and hook DLL internals respectively.

---

## Design System

| Property | Value |
|----------|-------|
| Tool | ratatui 0.29 + crossterm |
| Preset | none |
| Component library | ratatui built-ins (Block, Table, Row, Cell, Paragraph, Sparkline, Clear, Layout, List) |
| Icon library | none (text-based TUI) |
| Font | terminal default (monospace) |

---

## Layout Structure

### Diagnostic List Screen (DIFF-02)

Follows the `BypassAlertList` layout exactly — a full-screen table with pagination, filter state, and a detail popup.

```
+- Diagnostic Events (47) [Severity: warn] [Hide Ack'd] --------+
| Severity | Time      | User | Path | Tier | Policy | Latency  |
| > warn   | 2m ago    | S-1- | C:\..| T3   | pol-12 | 45us     |
|   crit   | 5m ago    | S-1- | D:\..| T4   | pol-03 | 120us    |
|   info   | 12m ago   | S-1- | C:\..| T2   | pol-08 | 32us     |
+---------------------------------------------------------------+
| [Enter] Detail  [f] Filter Severity  [h] Hide Ack'd  [r] Ref..|
```

#### Detail Popup (Enter on a row)

```
+- Diagnostic Detail (ID: 42) ----------------------------------+
| Time: 2026-06-02T10:23:45Z                                    |
| User SID: S-1-5-21-...                                        |
| Path: C:\Secret.doc                                           |
| Classification Tier: T3                                       |
| Matched Policy: pol-12 (Block)                                |
| Decision Latency: 45 us                                       |
| Classification Source: CacheHit (age: 12 ms)                  |
|                                                               |
| -- ABAC Context --                                            |
| Subject: {"sid":"S-1-5-21-...","groups":["..."]}              |
| Resource: C:\Secret.doc                                       |
| Action: WRITE                                                 |
| Environment: {"network":"Corporate","device":"Managed"}       |
|                                                               |
| -- Hook Function --                                           |
| Hook: WriteFile                                               |
| [Enter/Esc] Back to list                                      |
+---------------------------------------------------------------+
```

### Self-Health Dashboard (DIFF-04)

A two-panel layout: current snapshot on the left, sparkline trends on the right.

```
+- Self-Health Dashboard ---------------------------------------+
|                                                               |
|  -- Current Status --        |  -- 5-Min Trends --            |
|                               |                                |
|  Overall: HEALTHY             |  Cache Hit Rate                |
|  [Green badge]                |  |      __--__               |
|                               |  |__--''      `--__          |
|  Injected PIDs:     47        |  0%    50%    100%            |
|  Patched Modules:   12        |                                |
|  Pipe Round-Trips:  1,234     |  Pipe Round-Trips / 60s       |
|  Cache Hit Rate:    87%       |  |  /\    /\                  |
|  Fail State:        Healthy   |  | /  \  /  \                 |
|                               |  |/    \/    \                |
|  [r] Refresh                  |  0    500   1000              |
|                               |                                |
+---------------------------------------------------------------+
| [r] Refresh  [Esc] Back to System Menu                        |
```

#### Panel Dimensions

- **Left panel (Current Status):** 45% of terminal width, minimum 35 cells.
- **Right panel (Trends):** 55% of terminal width, minimum 40 cells.
- **Vertical split:** Single `Layout::horizontal` with `[Constraint::Percentage(45), Constraint::Percentage(55)]`.
- **Minimum terminal size:** 80 columns x 20 rows. Below this, render a centered warning: "Terminal too small. Please resize to at least 80x20."

---

## Spacing Scale

Terminal cell-based spacing — 1 unit = 1 character cell. Same convention as all prior TUI phases.

| Token | Value | Usage |
|-------|-------|-------|
| xs | 1 cell | Inline symbol spacing |
| sm | 2 cells | Label-to-value separator (`: `) |
| md | 4 cells | Table cell internal padding |
| lg | 8 cells | Section divider padding |
| xl | 12 cells | Panel margin |

**Exceptions:** None for this phase. TUI character-cell grid — pixel-based 4px grid convention does not apply.

---

## Typography

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Body / table cells | terminal default | regular | 1 |
| Block title | terminal default | `Modifier::BOLD` | 1 |
| Table header | terminal default | `Modifier::BOLD` | 1 |
| Status badge text | terminal default | `Modifier::BOLD` | 1 |
| Key hints | terminal default | regular | 1 |
| Sparkline axis labels | terminal default | regular | 1 |
| Empty state | terminal default | regular | 1 |

ratatui renders with the terminal's default monospace font. No font size overrides. All emphasis via `Modifier::BOLD` or `Color`.

---

## Color

All values are `ratatui::style::Color` enum variants.

**TUI color hierarchy (60/30/10 intent):**
- Dominant: `Color::White` (default text, majority of cells)
- Secondary: `Color::DarkGray` (muted text, hints, empty states, acknowledged rows)
- Accent: `Color::Cyan` (selection highlight — reserved for active table row only)
- Semantic: `Color::Green` (healthy status), `Color::Yellow` (degraded status), `Color::Red` (critical status / error)

| Role | Value | Usage |
|------|-------|-------|
| Default text | `Color::White` | Non-selected table rows, block titles |
| Selected item fg | `Color::Black` | Text on selected/highlighted row |
| Selected item bg | `Color::Cyan` | Currently highlighted table row |
| Selected modifier | `Modifier::BOLD` | Bold on selected row |
| Hints text | `Color::DarkGray` | Key hint bar at bottom |
| Empty state text | `Color::DarkGray` | Empty table placeholder |
| Status: Healthy | `Color::Green` + `Modifier::BOLD` | Overall status badge, sparkline >= 80% |
| Status: Degraded | `Color::Yellow` + `Modifier::BOLD` | Overall status badge, sparkline 60-80% |
| Status: Critical | `Color::Red` + `Modifier::BOLD` | Overall status badge, sparkline < 60% or Isolated |
| Status: Info | `Color::Cyan` | Status bar info |
| Status: Success | `Color::Green` | Status bar success |
| Status: Error | `Color::Red` | Status bar error |
| Severity: crit | `Color::Red` + `Modifier::BOLD` | Diagnostic row severity cell |
| Severity: warn | `Color::Yellow` | Diagnostic row severity cell |
| Severity: info | `Color::Blue` | Diagnostic row severity cell |
| Sparkline: healthy | `Color::Green` | Sparkline bar color when value >= 80% |
| Sparkline: degraded | `Color::Yellow` | Sparkline bar color when value 60-80% |
| Sparkline: critical | `Color::Red` | Sparkline bar color when value < 60% |
| Acknowledged row | `Color::DarkGray` | Dimmed diagnostic row (if ack field present) |

**Existing TUI style in use (from render.rs, verified 2026-06-02):**
```rust
// Table selection highlight (BypassAlertList, PolicyList, etc.)
Style::default()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD)

// Hints bar (draw_hints function)
Style::default().fg(Color::DarkGray)

// Severity badges (BypassAlertList)
"crit" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
"warn" => Style::default().fg(Color::Yellow),
"info" => Style::default().fg(Color::Blue),
```

---

## Diagnostic List Screen — Visual States

### Table Header

Rendered as `Row::new(...).style(Style::default().add_modifier(Modifier::BOLD)).bottom_margin(1)`.

Columns (left to right):

| Column | Width | Content | Truncation |
|--------|-------|---------|------------|
| Severity | 10% | "crit" / "warn" / "info" | None |
| Time | 12% | Relative time (e.g., "2m ago") | None |
| User | 15% | User SID, last 12 chars with "..." prefix if longer | `...{last_12}` |
| Path | 25% | File path, first 22 chars + "..." if longer | `{first_22}...` |
| Tier | 8% | "T1" / "T2" / "T3" / "T4" | None |
| Policy | 15% | Policy ID, first 14 chars + "..." if longer | `{first_14}...` |
| Latency | 15% | "{N} us" (microseconds) | None |

### Table Row — Default

```
  warn   | 2m ago | ...S-1-5-21 | C:\Users\Secret.doc | T3 | pol-12 | 45 us
```

- Severity cell: colored per severity mapping above.
- All other cells: `Color::White`, regular weight.

### Table Row — Selected

```
> warn   | 2m ago | ...S-1-5-21 | C:\Users\Secret.doc | T3 | pol-12 | 45 us
```

- Full row: `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD`.
- Severity cell color is PRESERVED inside the highlight (the severity style overrides the row style for that cell only).

### Table Row — Acknowledged (if applicable)

- Full row: `Color::DarkGray` fg (dimmed).
- Severity cell: still colored, but at reduced intensity (DarkGray base + severity color modifier not applied; use DarkGray only).

### Empty State

```
+- Diagnostic Events (0) ---------------------------------------+
|                                                               |
|              No diagnostic events found.                      |
|                                                               |
+---------------------------------------------------------------+
```

- Centered `Paragraph` with `Color::DarkGray`.
- Title still shows count `(0)` and active filter suffixes.

### Detail Popup — Layout

Full-screen read-only view (same pattern as `BypassAlertDetail`). Uses `Paragraph` with `Wrap { trim: true }` inside a `Block::default().borders(Borders::ALL)`.

Field order (top to bottom):
1. `Time:` — raw ISO timestamp
2. `User SID:` — full SID string
3. `Path:` — full file path
4. `Classification Tier:` — T1/T2/T3/T4
5. `Matched Policy:` — `{policy_id} ({enforcement_mode})`
6. `Decision Latency:` — `{N} us`
7. `Classification Source:` — `CacheHit (age: {N} ms)` / `CacheMiss` / `Pipe`
8. Blank line separator
9. `-- ABAC Context --` — bold header line
10. `Subject:` — JSON string (wrapped)
11. `Resource:` — path string
12. `Action:` — READ/WRITE/COPY/DELETE/MOVE/PASTE
13. `Environment:` — JSON string (wrapped)
14. Blank line separator
15. `-- Hook Function --` — bold header line
16. `Hook:` — WriteFile / WriteFileEx / MoveFileExW / etc.

All labels use `Span::styled("Label: ", Style::default().add_modifier(Modifier::BOLD))`.

---

## Self-Health Dashboard — Visual States

### Current Status Panel (Left)

```
-- Current Status --

Overall: HEALTHY
[Green background block, Black bold text]

Injected PIDs:     47
Patched Modules:   12
Pipe Round-Trips:  1,234
Cache Hit Rate:    87%
Fail State:        Healthy
```

#### Overall Status Badge

Rendered as a `Paragraph` inside a `Block` with colored background:

| State | Background | Foreground | Text |
|-------|------------|------------|------|
| Healthy | `Color::Green` | `Color::Black` + `Modifier::BOLD` | "HEALTHY" |
| Degraded | `Color::Yellow` | `Color::Black` + `Modifier::BOLD` | "DEGRADED" |
| Critical | `Color::Red` | `Color::Black` + `Modifier::BOLD` | "CRITICAL" |

The badge spans 20 columns wide, 3 rows tall, centered within the left panel.

#### Counter Display Format

| Counter | Format | Example |
|---------|--------|---------|
| Injected PIDs | Plain integer | `47` |
| Patched Modules | Plain integer | `12` |
| Pipe Round-Trips | Thousands-comma separated | `1,234` |
| Cache Hit Rate | Percentage, no decimal | `87%` |
| Fail State | PascalCase string | `Healthy` / `Degraded` / `Isolated` / `Resync` |

Labels left-aligned at column 0, values right-aligned at column 25 (padded with spaces).

### Trends Panel (Right)

```
-- 5-Min Trends --

Cache Hit Rate
|      __--__
|__--''      `--__
0%        50%       100%

Pipe Round-Trips / 60s
|  /\    /\
| /  \  /  \
|/    \/    \
0     500    1000
```

#### Sparkline Widget

Uses `ratatui::widgets::Sparkline` with the following styling:

| Property | Value |
|----------|-------|
| `data` | `Vec<u64>` of last 12 snapshots (12 minutes) for the metric |
| `max` | Explicit max: 100 for cache_hit_rate (percentage), auto-computed max * 1.1 for pipe_round_trips |
| `style` | `Style::default().fg(color)` where color is determined by the LAST data point's health zone |
| `bar_set` | `symbols::bar::NINE_LEVELS` (default) |

#### Sparkline Color Logic

For **cache_hit_rate** sparkline:
- If last value >= 80: `Color::Green`
- If last value >= 60: `Color::Yellow`
- If last value < 60: `Color::Red`

For **pipe_round_trips** sparkline:
- If last value > 0 AND overall state is Healthy: `Color::Green`
- If last value > 0 AND overall state is Degraded: `Color::Yellow`
- If last value == 0 OR overall state is Critical: `Color::Red`

#### Y-Axis Labels

Rendered as a `Paragraph` below each sparkline:
- Cache hit rate: `0%` left-aligned, `50%` centered, `100%` right-aligned below the sparkline.
- Pipe round trips: `0` left-aligned, `{mid}` centered, `{max}` right-aligned, where `{mid}` = max/2.

### Empty State (No Data Yet)

```
+- Self-Health Dashboard ---------------------------------------+
|                                                               |
|  -- Current Status --        |  -- 5-Min Trends --            |
|                               |                                |
|  Overall: UNKNOWN             |  No trend data available.      |
|  [DarkGray badge]             |  Poll begins on first agent    |
|                               |  connection.                   |
|  Injected PIDs:     -         |                                |
|  Patched Modules:   -         |                                |
|  Pipe Round-Trips:  -         |                                |
|  Cache Hit Rate:    -         |                                |
|  Fail State:        Unknown   |                                |
|                               |                                |
+---------------------------------------------------------------+
```

- Badge: `Color::DarkGray` bg + `Color::Black` fg + `Modifier::BOLD`, text "UNKNOWN".
- Counters: `-` placeholder.
- Trends panel: centered `Paragraph` with `Color::DarkGray`: "No trend data available. Poll begins on first agent connection."

---

## Interaction States

### Diagnostic List

| State | Visual |
|-------|--------|
| Table row — default | `Color::White`, no background |
| Table row — selected | `Color::Black` fg + `Color::Cyan` bg + `Modifier::BOLD` |
| Table row — acknowledged | `Color::DarkGray` (dimmed) |
| Severity badge — crit | `Color::Red` + `Modifier::BOLD` |
| Severity badge — warn | `Color::Yellow` |
| Severity badge — info | `Color::Blue` |
| Filter active suffix | Appended to block title in brackets: `[Severity: warn]` |
| Hide-ack active suffix | Appended to block title: `[Hide Ack'd]` |
| Detail popup — label | `Modifier::BOLD` |
| Detail popup — value | `Color::White`, regular weight |
| Detail popup — section header | `Modifier::BOLD`, full line |

### Self-Health Dashboard

| State | Visual |
|-------|--------|
| Status badge — Healthy | `Color::Green` bg + `Color::Black` fg + `Modifier::BOLD` |
| Status badge — Degraded | `Color::Yellow` bg + `Color::Black` fg + `Modifier::BOLD` |
| Status badge — Critical | `Color::Red` bg + `Color::Black` fg + `Modifier::BOLD` |
| Status badge — Unknown | `Color::DarkGray` bg + `Color::Black` fg + `Modifier::BOLD` |
| Counter label | `Modifier::BOLD`, left-aligned |
| Counter value | `Color::White`, right-aligned |
| Sparkline — healthy zone | `Color::Green` bars |
| Sparkline — degraded zone | `Color::Yellow` bars |
| Sparkline — critical zone | `Color::Red` bars |
| Empty trend panel | `Color::DarkGray`, centered text |

---

## Copywriting Contract

### Diagnostic List

| Element | Copy |
|---------|------|
| Block title | `Diagnostic Events ({total})` |
| Empty state | `No diagnostic events found.` |
| Filter suffix — severity | `[Severity: {crit|warn|info}]` |
| Hide-ack suffix | `[Hide Ack'd]` |
| Footer hints | `[Enter] Detail  [f] Filter Severity  [h] Hide Ack'd  [r] Refresh  [PgUp/PgDn] Page  [Esc] Back` |
| Detail popup title | `Diagnostic Detail (ID: {id})` |
| Detail popup hints | `[Enter/Esc] Back to list` |
| Section header — ABAC Context | `-- ABAC Context --` |
| Section header — Hook Function | `-- Hook Function --` |
| Classification source — CacheHit | `CacheHit (age: {N} ms)` |
| Classification source — CacheMiss | `CacheMiss` |
| Classification source — Pipe | `Pipe` |
| Latency format | `{N} us` |
| Time format (table) | Relative: `{N}m ago`, `{N}h ago`, `{N}d ago` |
| Time format (detail) | ISO 8601: `2026-06-02T10:23:45Z` |

### Self-Health Dashboard

| Element | Copy |
|---------|------|
| Block title | `Self-Health Dashboard` |
| Left panel title | `-- Current Status --` |
| Right panel title | `-- 5-Min Trends --` |
| Overall status — Healthy | `HEALTHY` |
| Overall status — Degraded | `DEGRADED` |
| Overall status — Critical | `CRITICAL` |
| Overall status — Unknown | `UNKNOWN` |
| Counter label — Injected PIDs | `Injected PIDs:` |
| Counter label — Patched Modules | `Patched Modules:` |
| Counter label — Pipe Round-Trips | `Pipe Round-Trips:` |
| Counter label — Cache Hit Rate | `Cache Hit Rate:` |
| Counter label — Fail State | `Fail State:` |
| Trend label — Cache Hit Rate | `Cache Hit Rate` |
| Trend label — Pipe Round-Trips | `Pipe Round-Trips / 60s` |
| Empty trend message | `No trend data available. Poll begins on first agent connection.` |
| Footer hints | `[r] Refresh  [Esc] Back to System Menu` |
| Terminal too small warning | `Terminal too small. Please resize to at least 80x20.` |

---

## Key Bindings Summary

### Diagnostic List

| Key | Action |
|-----|--------|
| Up Arrow | Move selection up in table |
| Down Arrow | Move selection down in table |
| Enter | Open detail popup for selected row |
| Esc | Return to System Menu |
| `f` | Cycle severity filter: All -> Crit -> Warn -> Info -> All |
| `h` | Toggle hide-acknowledged (if ack field present) |
| `r` | Refresh current page from server |
| PgUp | Previous page (if not on first page) |
| PgDn | Next page (if more pages exist) |

### Diagnostic Detail Popup

| Key | Action |
|-----|--------|
| Enter | Return to Diagnostic List |
| Esc | Return to Diagnostic List |

### Self-Health Dashboard

| Key | Action |
|-----|--------|
| `r` | Refresh health snapshot from server |
| Esc | Return to System Menu |

---

## Component Inventory

### Diagnostic List

| Component | ratatui widget | Key behavior |
|-----------|---------------|--------------|
| Table | `Table` + `TableState` | 7 columns, row_highlight_style Black+Cyan+BOLD, highlight_symbol `> ` |
| Table header | `Row::new(...).style(BOLD).bottom_margin(1)` | Column labels |
| Severity cell | `Cell::from(...).style(severity_style)` | Color per severity |
| Empty state | `Paragraph` styled `Color::DarkGray` | Centered, block title shows `(0)` |
| Detail popup | `Paragraph` + `Block::default().borders(Borders::ALL)` | Wrap enabled, full-screen read-only |
| Hints bar | `draw_hints(frame, area, hints)` | Bottom overlay, DarkGray text |
| Filter suffix | Appended to block title string | Dynamic based on active filters |

### Self-Health Dashboard

| Component | ratatui widget | Key behavior |
|-----------|---------------|--------------|
| Main layout | `Layout::horizontal` | 45/55 split, minimum 80 cols |
| Status badge | `Paragraph` inside `Block` | Colored background per state |
| Counter list | `Paragraph` with formatted lines | Label BOLD left, value right-aligned |
| Sparkline (cache hit rate) | `Sparkline` | `max=100`, color from last point's zone |
| Sparkline (pipe round trips) | `Sparkline` | `max=auto*1.1`, color from last point's zone |
| Y-axis labels | `Paragraph` | 0/mid/max aligned below sparkline |
| Empty trend panel | `Paragraph` styled `Color::DarkGray` | Centered placeholder text |
| Hints bar | `draw_hints(frame, area, hints)` | Bottom overlay, DarkGray text |

---

## Screen Enum Additions

The `Screen` enum in `app.rs` gains two new variants. Codebase scan confirmed these variants do not yet exist.

### DiagnosticList

```rust
/// Diagnostic-mode admin TUI screen showing blocked events with decision tree details.
///
/// Pattern: BypassAlertList — scrollable table with filter, pagination, and detail popup.
/// Each row shows: time, user SID, path, tier, policy, latency, classification source.
/// Enter opens a detail popup with full ABAC context and decision tree.
DiagnosticList {
    /// Raw JSON diagnostic responses from the API.
    events: Vec<serde_json::Value>,
    /// Currently highlighted row index.
    selected: usize,
    /// Active severity filter.
    filter: DiagnosticSeverityFilter,
    /// Current page number (0-based).
    page: usize,
    /// Items per page.
    page_size: usize,
    /// Total count from server (for pagination).
    total: usize,
},
```

### DiagnosticDetail

```rust
/// Diagnostic event detail popup (read-only).
///
/// Pattern: BypassAlertDetail — full-screen read-only view with ABAC context.
DiagnosticDetail { event: serde_json::Value },
```

### SelfHealthDashboard

```rust
/// Self-health dashboard showing per-host hook health counters with sparkline trends.
///
/// Pattern: ProtectedPathList / BypassAlertList — two-panel layout with status and trends.
/// Left panel: current snapshot with color-coded status.
/// Right panel: 5-minute sparkline trends for cache_hit_rate and pipe_round_trips.
SelfHealthDashboard {
    /// Raw JSON health snapshot from the API (current values).
    snapshot: Option<serde_json::Value>,
    /// Historical snapshots for sparkline rendering (last 12 minutes).
    history: Vec<serde_json::Value>,
    /// Last refresh timestamp for display.
    last_refresh: Option<String>,
},
```

### Filter Enum

```rust
/// Filter state for the DiagnosticList screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiagnosticSeverityFilter {
    #[default]
    All,
    Crit,
    Warn,
    Info,
}

impl DiagnosticSeverityFilter {
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

---

## Screen Dispatch Additions

`handle_event` in `dispatch.rs` gains three new branches.

### DiagnosticList

- `Up/Down` -> update `selected` within table bounds
- `Enter` -> transition to `Screen::DiagnosticDetail { event: events[selected].clone() }`
- `Esc` -> return to `Screen::SystemMenu { selected: 12 }` (position after "Bypass Alerts")
- `f` -> cycle `filter` to `next()`, reload page 0 with new filter
- `h` -> toggle hide-acknowledged (if applicable), reload page 0
- `r` -> reload current page
- `PgUp` -> previous page (if page > 0)
- `PgDn` -> next page (if (page + 1) * page_size < total)

### DiagnosticDetail

- `Enter` / `Esc` -> return to `Screen::DiagnosticList` (reload with defaults)

### SelfHealthDashboard

- `r` -> refresh snapshot from server (`action_load_health_dashboard`)
- `Esc` -> return to `Screen::SystemMenu { selected: 13 }` (position after new items)

---

## Navigation — System Menu Placement

The SystemMenu in `render.rs` and `dispatch.rs` gains two new items after "Bypass Alerts" (index 12) and before "Syslog Config" (currently index 12, shifting to 14):

```rust
// BEFORE (current):
&[
    "Server Status",      // 0
    "Agent List",         // 1
    "SIEM Config",        // 2
    "Alert Config",       // 3
    "LDAP Config",        // 4
    "USB Enforcement",    // 5
    "Cloud Config",       // 6
    "Print Config",       // 7
    "Label Review Queue", // 8
    "Approval Management",// 9
    "Protected Paths",    // 10
    "Bypass Alerts",      // 11
    "Syslog Config",      // 12
    "Back",               // 13
]

// AFTER (with Phase 58 screens):
&[
    "Server Status",       // 0
    "Agent List",          // 1
    "SIEM Config",         // 2
    "Alert Config",        // 3
    "LDAP Config",         // 4
    "USB Enforcement",     // 5
    "Cloud Config",        // 6
    "Print Config",        // 7
    "Label Review Queue",  // 8
    "Approval Management", // 9
    "Protected Paths",     // 10
    "Bypass Alerts",       // 11
    "Diagnostic Events",   // 12  <-- NEW
    "Self-Health",         // 13  <-- NEW
    "Syslog Config",       // 14
    "Back",                // 15
]
```

**Dispatch wiring:**
- Index 12 (Diagnostic Events) -> `action_load_diagnostic_list(app, DiagnosticSeverityFilter::All, 0)`
- Index 13 (Self-Health) -> `action_load_health_dashboard(app)`

**Esc return routing:**
- `DiagnosticList` -> `Screen::SystemMenu { selected: 12 }`
- `SelfHealthDashboard` -> `Screen::SystemMenu { selected: 13 }`

---

## Responsive Behavior

### Minimum Terminal Size

- **Diagnostic List:** 80 columns x 12 rows. Below this, render centered warning: "Terminal too small. Please resize to at least 80x12."
- **Self-Health Dashboard:** 80 columns x 20 rows. Below this, render centered warning: "Terminal too small. Please resize to at least 80x20."

### Truncation Rules

| Field | Max Display Width | Truncation Strategy |
|-------|-------------------|---------------------|
| User SID (table) | 15 cols | `...{last_12}` |
| Path (table) | 25 cols | `{first_22}...` |
| Policy ID (table) | 15 cols | `{first_14}...` |
| Path (detail) | full width | Wrap via `Wrap { trim: true }` |
| Subject JSON (detail) | full width | Wrap via `Wrap { trim: true }` |
| Environment JSON (detail) | full width | Wrap via `Wrap { trim: true }` |
| Image path (bypass alert pattern) | 25 cols | `{first_22}...` |

### Sparkline Scaling

- Sparkline width = right panel width minus 4 cells of padding (2 each side).
- If right panel < 30 cells wide, hide sparklines and show text-only trend values.
- Sparkline height = 5 rows each (including 1 row for Y-axis labels below).

---

## Decisions Locked from CONTEXT.md (verbatim)

| ID | Decision |
|----|----------|
| D-07 | Diagnostic data is captured in an in-memory ring buffer in the hook DLL. Each entry is a `DiagnosticSnapshot` struct. |
| D-08 | Ring buffer capacity is 1000 entries per hook DLL instance. Oldest entries overwritten when full. Entries expire after 1 hour (lazy eviction on write). |
| D-09 | Agent polls each connected hook DLL for diagnostic snapshots every 30 seconds via named pipe (`HookMessage::PullDiagnostics`). |
| D-10 | Admin TUI diagnostic screen reads from `GET /admin/diagnostics` and displays a scrollable list of blocked events. Each row shows: time, user, path, tier, policy, latency, classification source. Enter opens a detail popup with the full ABAC context and decision tree. |
| D-11 | Diagnostic mode is admin-only. No user-facing diagnostic screen. The diagnostic screen follows the existing `BypassAlertList` pattern. |
| D-18 | Hook DLL emits per-host counters: `injected_pids`, `patched_modules`, `pipe_round_trips_60s`, `cache_hit_rate_60s`, `current_fail_state`. |
| D-19 | Agent polls connected hook DLLs every 60 seconds for health counters. Agent aggregates counters per-host and stores last 12 snapshots (12 minutes of history) in an in-memory `VecDeque`. |
| D-20 | Admin TUI self-health dashboard shows: (a) current snapshot with color-coded status (green=healthy, yellow=degraded, red=isolated), (b) 5-minute sparkline trend for cache_hit_rate and pipe_round_trips. Screen follows existing `BypassAlertList` / `ProtectedPaths` pattern. |
| D-21 | Health thresholds: `Healthy` = cache_hit_rate >= 80% AND fail_state == Healthy AND pipe_round_trips > 0 in last 5 min. `Degraded` = cache_hit_rate < 80% OR fail_state == Degraded. `Critical` = fail_state == Isolated OR 0 pipe_round_trips in last 5 min. |
| D-23 | The self-health dashboard is read-only. No operator actions from the TUI. |

---

## Decisions from RESEARCH.md (Claude's Discretion)

| ID | Decision |
|----|----------|
| R-01 | Diagnostic admin API supports filtering by `since`, `user_sid`, and `policy_id` to help operators triage specific false-positive patterns. |
| R-02 | Health counter aggregation reuses existing `PerfTelemetry` emission cadence (every 1000 calls). |
| R-03 | `ratatui::widgets::Sparkline` is used for 5-minute trend visualization (available in ratatui 0.29). |

---

## Checker Sign-Off

- [ ] Dimension 1 Copywriting: PASS (all 28 elements defined in Copywriting Contract)
- [ ] Dimension 2 Visuals: PASS (ASCII layout diagrams for both screens, component inventory, panel dimensions)
- [ ] Dimension 3 Color: PASS (`Color::` enum values, existing TUI style preserved: Black+Cyan+BOLD; 60/30/10 hierarchy; semantic Green/Yellow/Red for health states)
- [ ] Dimension 4 Typography: PASS (terminal default, `Modifier::BOLD` emphasis, cell-based spacing)
- [ ] Dimension 5 Spacing: PASS (cell-based 1/2/4/8/12 scale; TUI medium exception documented)
- [ ] Dimension 6 Registry Safety: PASS (no external registries — pure ratatui built-ins)

**Approval:** pending

---

## Sources

| Source | Decisions Locked |
|--------|-----------------|
| 58-CONTEXT.md | D-07, D-08, D-09, D-10, D-11, D-18, D-19, D-20, D-21, D-23 verbatim above |
| 58-RESEARCH.md | R-01, R-02, R-03 (API filtering, PerfTelemetry reuse, Sparkline widget) |
| render.rs (verified 2026-06-02) | `Color::Black/White/Cyan/Green/Red/Yellow/Blue/DarkGray`, `Modifier::BOLD`, `highlight_symbol("> ")`, `draw_hints` pattern, `BypassAlertList` table pattern, `BypassAlertDetail` popup pattern |
| dispatch.rs (verified 2026-06-02) | `handle_event` routing pattern, `BypassAlertList` key handling (ack, filter, hide, pagination, detail), `action_load_bypass_alert_list` pattern |
| app.rs (verified 2026-06-02) | `Screen` enum pattern, `BypassAlertList` state struct, `BypassAlertSeverityFilter` enum pattern, `SystemMenu` item count and order |
| bypass_alerts.rs (verified 2026-06-02) | Footer hints pattern, empty state pattern, constants module pattern for screen-specific strings |
| REQUIREMENTS.md ss DIFF-02 | Diagnostic TUI screen with decision tree per blocked event |
| REQUIREMENTS.md ss DIFF-04 | Self-health dashboard with per-host counters and trends |
| ROADMAP.md ss Phase 58 | Success criteria: diagnostic screen shows full decision tree; self-health dashboard shows counters + 5-min trend |
