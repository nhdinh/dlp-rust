# Phase 16: Policy List + Simulate — PATTERNS

**Phase:** 16-policy-list-simulate
**Date:** 2026-04-17

---

## 1. Files Created or Modified

| File | Role | Change |
|------|------|--------|
| `dlp-admin-cli/src/app.rs` | State definition | Add `SimulateFormState`, `SimulateOutcome`, `SimulateCaller`; extend `Screen` with `PolicySimulate` |
| `dlp-admin-cli/src/screens/dispatch.rs` | Event handling | Add `Char('n')` branch; inject sort; extend menu nav counts; add simulate handlers |
| `dlp-admin-cli/src/screens/render.rs` | Rendering | Rewrite `draw_policy_list` columns/widths/hints; add `draw_policy_simulate`; extend menu arrays |
| `dlp-admin-cli/Cargo.toml` | Dependencies | Add `chrono = "0.4"` |

---

## 2. Pattern A — Policy List Polish

### A-1. `draw_policy_list` column rewrite (render.rs §1137–1192)

**Analog:** existing `draw_policy_list` (render.rs lines 1137–1192)

**What changes:**
- `header` row: `["Priority", "Name", "Action", "Enabled"]` (drop `ID`, `Version`)
- `widths`: `[15%, 45%, 20%, 20%]`
- Row builder: `p["priority"].as_u64()` → u32 (malformed = u32::MAX); `p["enabled"].as_bool()` → `"Yes"`/`"No"`; `action` = raw string from `p["action"]`
- Hints: `"n: new | e: edit | d: delete | Enter: view | Esc: back"`

**Excerpt (from analog — replace only the differing parts):**

```rust
// CURRENT (drop this header):
let header = Row::new(vec!["ID", "Name", "Priority", "Enabled", "Version"])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(1);

// REPLACE WITH:
let header = Row::new(vec!["Priority", "Name", "Action", "Enabled"])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(1);

// CURRENT widths (drop):
let widths = [
    Constraint::Percentage(20),  // ID
    Constraint::Percentage(30),  // Name
    Constraint::Percentage(15),  // Priority
    Constraint::Percentage(15),  // Enabled
    Constraint::Percentage(20),  // Version
];

// REPLACE WITH:
let widths = [
    Constraint::Percentage(15),  // Priority
    Constraint::Percentage(45),  // Name
    Constraint::Percentage(20),  // Action
    Constraint::Percentage(20),  // Enabled
];

// CURRENT row builder (replace):
let rows: Vec<Row> = policies
    .iter()
    .map(|p| {
        Row::new(vec![
            p["id"].as_str().unwrap_or("-").to_string(),
            p["name"].as_str().unwrap_or("-").to_string(),
            p["priority"].to_string(),
            p["enabled"].to_string(),
            p["version"].to_string(),
        ])
    })
    .collect();

// REPLACE WITH:
let rows: Vec<Row> = policies.iter().map(|p| {
    let priority = p["priority"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(u32::MAX);
    let action = p["action"].as_str().unwrap_or("-");
    let enabled = if p["enabled"].as_bool().unwrap_or(false) { "Yes" } else { "No" };
    Row::new(vec![
        priority.to_string(),
        p["name"].as_str().unwrap_or("-").to_string(),
        action.to_string(),
        enabled.to_string(),
    ])
}).collect();

// CURRENT hints (replace):
draw_hints(frame, area, "e: edit | d: delete | Enter: view | Esc: back");

// REPLACE WITH:
draw_hints(frame, area, "n: new | e: edit | d: delete | Enter: view | Esc: back");
```

### A-2. `handle_policy_list` — add `Char('n')` branch (dispatch.rs §393–434)

**Analog:** `KeyCode::Char('e')` branch at dispatch.rs lines 414–419

**Change:** insert `KeyCode::Char('n')` branch before the `_ => {}` arm.

```rust
// REPLACE the catch-all arm in handle_policy_list match block:
// CURRENT:
KeyCode::Char('d') => { /* ... */ }
_ => {}  // <-- insert Char('n') before this

// WITH:
KeyCode::Char('d') => { /* existing */ }
KeyCode::Char('n') => {
    app.screen = Screen::PolicyCreate {
        form: PolicyFormState::default(),
        selected: 0,
        editing: false,
        buffer: String::new(),
        validation_error: None,
    };
}
_ => {}
```

**Exact insertion point:** after the `KeyCode::Char('d')` branch (line 430 in current file), before `_ => {}` (line 432).

### A-3. `action_list_policies` — inject sort (dispatch.rs §458–475)

**Analog:** current `action_list_policies` at dispatch.rs lines 458–475

**Change:** after `Ok(policies)` deserializes, sort the `Vec` before assigning to `Screen::PolicyList`.

```rust
// CURRENT:
fn action_list_policies(app: &mut App) {
    match app.rt.block_on(app.client.get::<Vec<serde_json::Value>>("policies")) {
        Ok(policies) => {
            app.set_status(format!("Loaded {} policies", policies.len()), StatusKind::Success);
            app.screen = Screen::PolicyList { policies, selected: 0 };
        }
        Err(e) => app.set_status(format!("Failed: {e}"), StatusKind::Error),
    }
}

// REPLACE body with:
Ok(policies) => {
    app.set_status(
        format!("Loaded {} policies", policies.len()),
        StatusKind::Success,
    );
    let mut sorted = policies;
    // Primary: priority ascending (u32::MAX for malformed = sinks to bottom).
    // Secondary: name case-insensitive ascending for stable tiebreak.
    sorted.sort_by(|a, b| {
        let pa = a["priority"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(u32::MAX);
        let pb = b["priority"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(u32::MAX);
        pa.cmp(&pb)
            .then_with(|| {
                let na = a["name"].as_str().unwrap_or("").to_lowercase();
                let nb = b["name"].as_str().unwrap_or("").to_lowercase();
                na.cmp(&nb)
            })
    });
    app.screen = Screen::PolicyList { policies: sorted, selected: 0 };
}
```

**Notes:**
- `use std::cmp::Ordering;` is not needed — `sort_by` uses `Ord` on `u32` directly.
- The `to_lowercase()` call requires `use std::ascii::AsciiExt;` at the top of `dispatch.rs` (already imported via prelude) or `.to_ascii_lowercase()` on `&str` via `AsciiExt` trait. Confirm `use std::ascii::AsciiExt;` is present in the file — if not, add it.

### A-4. `draw_main_menu` — add Simulate Policy row (render.rs §28–36)

**Analog:** existing `draw_main_menu` call at render.rs lines 28–35

**Change:** add `"Simulate Policy"` as index 4. `handle_main_menu` nav count changes from 4 to 5. `handle_main_menu` Enter branch adds `4 => action_open_simulate(app, SimulateCaller::MainMenu)`.

```rust
// CURRENT draw_main_menu call:
draw_menu(
    frame, area, "dlp-admin-cli",
    &["Password Management", "Policy Management", "System", "Exit"],
    *selected,
);

// REPLACE WITH:
draw_menu(
    frame, area, "dlp-admin-cli",
    &["Password Management", "Policy Management", "System", "Simulate Policy", "Exit"],
    *selected,
);
```

### A-5. `handle_main_menu` nav count + Enter branch (dispatch.rs §61–78)

**Change:** `nav(selected, 4, ...)` → `nav(selected, 5, ...)`; Enter branch adds `4 => action_open_simulate(app, SimulateCaller::MainMenu)`.

```rust
// CURRENT nav call:
KeyCode::Up | KeyCode::Down => nav(selected, 4, key.code),
// REPLACE WITH:
KeyCode::Up | KeyCode::Down => nav(selected, 5, key.code),

// CURRENT Enter branch:
KeyCode::Enter => match *selected {
    0 => app.screen = Screen::PasswordMenu { selected: 0 },
    1 => app.screen = Screen::PolicyMenu { selected: 0 },
    2 => app.screen = Screen::SystemMenu { selected: 0 },
    3 => app.should_quit = true,
    _ => {}
},

// REPLACE WITH:
KeyCode::Enter => match *selected {
    0 => app.screen = Screen::PasswordMenu { selected: 0 },
    1 => app.screen = Screen::PolicyMenu { selected: 0 },
    2 => app.screen = Screen::SystemMenu { selected: 0 },
    3 => action_open_simulate(app, SimulateCaller::MainMenu),
    4 => app.should_quit = true,
    _ => {}
},
```

### A-6. `draw_policy_menu` — add Simulate Policy row (render.rs §51–65)

**Analog:** existing `draw_policy_menu` call at render.rs lines 51–65

**Change:** add `"Simulate Policy"` as index 5 (before `"Back"` at index 6). `handle_policy_menu` nav count changes from 6 to 7.

```rust
// CURRENT draw_policy_menu call:
&[
    "List Policies",
    "Get Policy",
    "Create Policy",
    "Update Policy",
    "Delete Policy",
    "Back",
],

// REPLACE WITH:
&[
    "List Policies",
    "Get Policy",
    "Create Policy",
    "Update Policy",
    "Delete Policy",
    "Simulate Policy",
    "Back",
],
```

### A-7. `handle_policy_menu` nav count + Enter branch (dispatch.rs §125–169)

**Change:** `nav(selected, 6, ...)` → `nav(selected, 7, ...)`; Enter branch: insert `5 => action_open_simulate(app, SimulateCaller::PolicyMenu)`, renumber `5 => MainMenu` to `6 => MainMenu`.

```rust
// CURRENT nav:
KeyCode::Up | KeyCode::Down => nav(selected, 6, key.code),

// REPLACE WITH:
KeyCode::Up | KeyCode::Down => nav(selected, 7, key.code),

// CURRENT Enter branch:
0 => action_list_policies(app),
1 => { /* GetPolicy TextInput */ },
2 => { /* PolicyCreate */ },
3 => { /* UpdatePolicy TextInput */ },
4 => { /* DeletePolicy TextInput */ },
5 => app.screen = Screen::MainMenu { selected: 1 },

// REPLACE WITH:
0 => action_list_policies(app),
1 => { /* GetPolicy TextInput — unchanged */ },
2 => { /* PolicyCreate — unchanged */ },
3 => { /* UpdatePolicy TextInput — unchanged */ },
4 => { /* DeletePolicy TextInput — unchanged */ },
5 => action_open_simulate(app, SimulateCaller::PolicyMenu),
6 => app.screen = Screen::MainMenu { selected: 1 },
```

---

## 3. Pattern B — Policy Simulate Screen

### B-1. New types in `app.rs` (alongside `PolicyFormState`, before `Screen` enum)

**Analog:** `PolicyFormState` struct (app.rs lines 123–140)

**Placement:** after `CallerScreen` enum, before `PolicyFormState`.

```rust
/// Identifies which menu opened the simulate screen — used to route Esc correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulateCaller {
    MainMenu,
    PolicyMenu,
}

/// The outcome of a simulate submission: no result yet, a successful evaluation,
/// or an error (network or server).
#[derive(Debug, Clone)]
pub enum SimulateOutcome {
    /// No submission made yet, or result was cleared.
    None,
    /// Server returned a decision successfully.
    Success(dlp_common::abac::EvaluateResponse),
    /// Network or server error; message is already prefixed.
    Error(String),
}

/// All form field values for the Policy Simulate screen.
///
/// `groups_raw` stores the comma-separated text buffer; it is split into
/// `Vec<String>` on submit. Other fields store select indices or string values.
#[derive(Debug, Clone, Default)]
pub struct SimulateFormState {
    /// Raw comma-separated SID input (not parsed until submit).
    pub groups_raw: String,
    /// Subject fields.
    pub user_sid: String,
    pub user_name: String,
    /// Select indices for DeviceTrust, NetworkLocation, Classification, Action,
    /// AccessContext. Defaults chosen per D-18.
    pub device_trust: usize,       // index into DeviceTrustOptions — default 1 (Unmanaged)
    pub network_location: usize,  // index into NetworkLocationOptions — default 3 (Unknown)
    /// Resource fields.
    pub path: String,
    pub classification: usize,    // index into ClassificationOptions — default 0 (T1)
    /// Environment / action fields.
    pub action: usize,           // index into ActionOptions — default 0 (READ)
    pub access_context: usize,   // index into AccessContextOptions — default 0 (Local)
}

/// Fixed select options for the simulate form (shared with Phase 13/14 conditions builder).
pub const SIMULATE_DEVICE_TRUST_OPTIONS: [&str; 4] = ["Managed", "Unmanaged", "Compliant", "Unknown"];
pub const SIMULATE_NETWORK_LOCATION_OPTIONS: [&str; 4] = ["Corporate", "CorporateVpn", "Guest", "Unknown"];
pub const SIMULATE_CLASSIFICATION_OPTIONS: [&str; 4] = ["T1", "T2", "T3", "T4"];
pub const SIMULATE_ACTION_OPTIONS: [&str; 6] = ["READ", "WRITE", "COPY", "DELETE", "MOVE", "PASTE"];
pub const SIMULATE_ACCESS_CONTEXT_OPTIONS: [&str; 2] = ["Local", "Smb"];

/// Total editable row count for the simulate form (0..=9).
pub const SIMULATE_ROW_COUNT: usize = 10;
/// Index of the [Simulate] submit row.
pub const SIMULATE_SUBMIT_ROW: usize = 9;
```

### B-2. `Screen::PolicySimulate` variant (app.rs inside `Screen` enum)

**Analog:** `Screen::PolicyCreate` (app.rs lines 265–287)

**Placement:** after `Screen::PolicyEdit` closing brace (line 314).

```rust
/// Policy simulation form.
///
/// Renders a Subject / Resource / Environment multi-field form, submits to
/// `POST /evaluate` (unauthenticated), and renders the `EvaluateResponse`
/// inline below the submit row. Reachable from both MainMenu and PolicyMenu.
///
/// Row layout (editable index → render row, with section headers skipped):
///   0: User SID            (text)
///   1: User Name           (text)
///   2: Groups (comma-SIDs)(text)
///   3: Device Trust        (select: cycles on Enter)
///   4: Network Location    (select: cycles on Enter)
///   --- Subject ---
///   5: Path                (text)
///   6: Classification     (select: cycles on Enter)
///   --- Resource ---
///   7: Action              (select: cycles on Enter)
///   8: Access Context      (select: cycles on Enter)
///   --- Environment ---
///   9: [Simulate]
///   --- Submit ---
PolicySimulate {
    /// All form field values and select indices.
    form: SimulateFormState,
    /// Index of the currently highlighted editable row (0..=9).
    selected: usize,
    /// Whether the selected text field is in edit mode.
    editing: bool,
    /// Text buffer while editing a field (User SID, User Name, Groups, Path).
    buffer: String,
    /// Inline result block or error.
    result: SimulateOutcome,
    /// Which menu opened this screen (for Esc return destination).
    caller: SimulateCaller,
},
```

### B-3. `handle_event` dispatch — add `PolicySimulate` arm (dispatch.rs §18–37)

**Analog:** `Screen::PolicyCreate { .. } => handle_policy_create(app, key)` (dispatch.rs line 31)

**Change:** add before the read-only views arm.

```rust
// INSERT before: Screen::PolicyDetail { .. } | Screen::ServerStatus { .. } | Screen::ResultView { .. } => {
Screen::PolicySimulate { .. } => handle_policy_simulate(app, key),
```

### B-4. `handle_policy_simulate` — entrypoint (dispatch.rs)

**Analog:** `handle_policy_create` (dispatch.rs lines 1076–1091)

**Template:**

```rust
/// Routes key events for the Policy Simulate screen.
fn handle_policy_simulate(app: &mut App, key: KeyEvent) {
    // Phase 1: read scalar flags with a shared borrow (avoids borrow conflicts).
    let (selected, editing) = match &app.screen {
        Screen::PolicySimulate {
            selected, editing, ..
        } => (*selected, *editing),
        _ => return,
    };
    if editing {
        handle_simulate_editing(app, key, selected);
    } else {
        handle_simulate_nav(app, key, selected);
    }
}
```

### B-5. `handle_simulate_editing` (dispatch.rs)

**Analog:** `handle_policy_create_editing` (dispatch.rs lines 1093–1147)

**Key insight:** Text field rows are 0 (user_sid), 1 (user_name), 2 (groups_raw), 5 (path). Buffer commits to the correct field based on `selected`.

```rust
/// Handles key events while editing a text field in the Policy Simulate form.
///
/// Text rows: 0 = user_sid, 1 = user_name, 2 = groups_raw, 5 = path.
fn handle_simulate_editing(app: &mut App, key: KeyEvent, _selected: usize) {
    match key.code {
        KeyCode::Char(c) => {
            if let Screen::PolicySimulate { buffer, .. } = &mut app.screen {
                buffer.push(c);
            }
        }
        KeyCode::Backspace => {
            if let Screen::PolicySimulate { buffer, .. } = &mut app.screen {
                buffer.pop();
            }
        }
        KeyCode::Enter => {
            // Commit buffer to the appropriate field.
            let (selected, buf) = match &app.screen {
                Screen::PolicySimulate { selected, buffer, .. } => {
                    (*selected, buffer.clone())
                }
                _ => return,
            };
            if let Screen::PolicySimulate {
                form, buffer, editing, ..
            } = &mut app.screen
            {
                match selected {
                    0 => form.user_sid = buf.trim().to_string(),
                    1 => form.user_name = buf.trim().to_string(),
                    2 => form.groups_raw = buf.clone(), // preserve formatting
                    5 => form.path = buf.trim().to_string(),
                    _ => {}
                }
                buffer.clear();
                *editing = false;
            }
        }
        KeyCode::Esc => {
            // Cancel edit; restore field to pre-edit value (do NOT discard result).
            if let Screen::PolicySimulate { buffer, editing, .. } = &mut app.screen {
                buffer.clear();
                *editing = false;
            }
        }
        _ => {}
    }
}
```

### B-6. `handle_simulate_nav` (dispatch.rs)

**Analog:** `handle_policy_create_nav` (dispatch.rs lines 1149–1238)

**Critical behavior:** `selected` is the editable row index (0..=9). Section header rows are skipped by the render function. Navigation via `nav(sel, SIMULATE_ROW_COUNT, key.code)` works directly because `selected` already indexes only editable rows — no skip-map required (Option B from 16-RESEARCH.md §U1).

Select rows: 3 (device_trust), 4 (network_location), 6 (classification), 7 (action), 8 (access_context). Enter cycles to next option.

```rust
/// Handles key events while navigating the Policy Simulate form (not editing).
fn handle_simulate_nav(app: &mut App, key: KeyEvent, selected: usize) {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if let Screen::PolicySimulate { selected: sel, .. } = &mut app.screen {
                nav(sel, SIMULATE_ROW_COUNT, key.code);
            }
        }
        KeyCode::Enter => match selected {
            // Text field rows: enter edit mode pre-filled.
            0 | 1 | 5 => {
                // Rows with free-text input (user_sid, user_name, path).
                if let Screen::PolicySimulate {
                    form,
                    editing,
                    buffer,
                    ..
                } = &mut app.screen
                {
                    let pre_fill = match selected {
                        0 => form.user_sid.clone(),
                        1 => form.user_name.clone(),
                        5 => form.path.clone(),
                        _ => return,
                    };
                    *buffer = pre_fill;
                    *editing = true;
                }
            }
            // Groups: text field, enter edit mode pre-filled.
            2 => {
                if let Screen::PolicySimulate {
                    form, editing, buffer, ..
                } = &mut app.screen
                {
                    *buffer = form.groups_raw.clone();
                    *editing = true;
                }
            }
            // Select rows: cycle to next option on Enter.
            3 => {
                // DeviceTrust select.
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.device_trust = (form.device_trust + 1) % SIMULATE_DEVICE_TRUST_OPTIONS.len();
                }
            }
            4 => {
                // NetworkLocation select.
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.network_location =
                        (form.network_location + 1) % SIMULATE_NETWORK_LOCATION_OPTIONS.len();
                }
            }
            6 => {
                // Classification select.
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.classification =
                        (form.classification + 1) % SIMULATE_CLASSIFICATION_OPTIONS.len();
                }
            }
            7 => {
                // Action select.
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.action = (form.action + 1) % SIMULATE_ACTION_OPTIONS.len();
                }
            }
            8 => {
                // AccessContext select.
                if let Screen::PolicySimulate { form, .. } = &mut app.screen {
                    form.access_context =
                        (form.access_context + 1) % SIMULATE_ACCESS_CONTEXT_OPTIONS.len();
                }
            }
            // [Simulate] submit row.
            SIMULATE_SUBMIT_ROW => {
                action_submit_simulate(app);
            }
            _ => {}
        },
        KeyCode::Esc | KeyCode::Char('q') => {
            // Return to the caller screen.
            let caller = match &app.screen {
                Screen::PolicySimulate { caller, .. } => *caller,
                _ => return,
            };
            match caller {
                SimulateCaller::MainMenu => {
                    // Return to MainMenu with Simulate Policy row selected.
                    app.screen = Screen::MainMenu { selected: 3 };
                }
                SimulateCaller::PolicyMenu => {
                    app.screen = Screen::PolicyMenu { selected: 5 };
                }
            }
        }
        _ => {}
    }
}
```

### B-7. `action_open_simulate` (dispatch.rs)

**Analog:** `action_load_siem_config` (dispatch.rs lines 674–688) — the pattern of loading state then switching screens.

```rust
/// Opens the Policy Simulate screen with a fresh `SimulateFormState::default()`
/// and the appropriate caller enum value.
fn action_open_simulate(app: &mut App, caller: SimulateCaller) {
    app.screen = Screen::PolicySimulate {
        form: SimulateFormState::default(),
        selected: 0,
        editing: false,
        buffer: String::new(),
        result: SimulateOutcome::None,
        caller,
    };
}
```

**Placement:** in dispatch.rs, after `action_server_status` (line 624) or in the simulate section at the end of the file.

### B-8. `action_submit_simulate` (dispatch.rs)

**Analog:** `action_save_siem_config` (dispatch.rs lines 692–707) — `block_on` pattern for async calls.

**Key implementation details:**
- Build `EvaluateRequest` from `SimulateFormState`:
  - `groups`: split `groups_raw` by `,`, `trim()` each, drop empty segments.
  - Map select indices to typed enums via index access on option arrays.
  - `environment.timestamp = chrono::Utc::now()`, `environment.session_id = 0`, `agent = None`.
- Call `app.rt.block_on(app.client.post::<EvaluateResponse>("evaluate", &req))`.
- Prefix network errors (reqwest) with `"Network error: "`, all others with `"Server error: "`.
- On success: set `result = SimulateOutcome::Success(response)`.
- On error: `result = SimulateOutcome::Error(prefixed_msg)`.

```rust
/// Builds an EvaluateRequest from the current form state, POSTs to /evaluate,
/// and stores the outcome in the screen's result field.
fn action_submit_simulate(app: &mut App) {
    // Extract form state (two-phase borrow).
    let form = match &app.screen {
        Screen::PolicySimulate { form, .. } => form.clone(),
        _ => return,
    };

    // Build groups Vec<String> from comma-separated input.
    let groups: Vec<String> = form
        .groups_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Map select indices to typed enums.
    use dlp_common::abac::{DeviceTrust, NetworkLocation, Subject, Resource, Environment,
                            Action, AccessContext, EvaluateRequest};
    use dlp_common::Classification;

    let device_trust_vals: [DeviceTrust; 4] = [
        DeviceTrust::Managed, DeviceTrust::Unmanaged,
        DeviceTrust::Compliant, DeviceTrust::Unknown,
    ];
    let network_location_vals: [NetworkLocation; 4] = [
        NetworkLocation::Corporate, NetworkLocation::CorporateVpn,
        NetworkLocation::Guest, NetworkLocation::Unknown,
    ];
    let classification_vals: [Classification; 4] = [
        Classification::T1, Classification::T2, Classification::T3, Classification::T4,
    ];
    let action_vals: [Action; 6] = [
        Action::READ, Action::WRITE, Action::COPY,
        Action::DELETE, Action::MOVE, Action::PASTE,
    ];
    let access_context_vals: [AccessContext; 2] = [
        AccessContext::Local, AccessContext::Smb,
    ];

    let req = EvaluateRequest {
        subject: Subject {
            user_sid: form.user_sid.clone(),
            user_name: form.user_name.clone(),
            groups,
            device_trust: device_trust_vals
                .get(form.device_trust)
                .copied()
                .unwrap_or(DeviceTrust::Unmanaged),
            network_location: network_location_vals
                .get(form.network_location)
                .copied()
                .unwrap_or(NetworkLocation::Unknown),
        },
        resource: Resource {
            path: form.path.clone(),
            classification: classification_vals
                .get(form.classification)
                .copied()
                .unwrap_or(Classification::T1),
        },
        environment: Environment {
            timestamp: chrono::Utc::now(),
            session_id: 0,
            access_context: access_context_vals
                .get(form.access_context)
                .copied()
                .unwrap_or(AccessContext::Local),
        },
        action: action_vals
            .get(form.action)
            .copied()
            .unwrap_or(Action::READ),
        agent: None,
    };

    // POST to /evaluate.
    let result = app.rt.block_on(app.client.post::<dlp_common::abac::EvaluateResponse>("evaluate", &req));

    // Store outcome in screen result field.
    if let Screen::PolicySimulate { result: out_result, .. } = &mut app.screen {
        match result {
            Ok(resp) => *out_result = SimulateOutcome::Success(resp),
            Err(e) => {
                // Detect reqwest network errors for accurate prefix.
                let prefix = if e.downcast_ref::<reqwest::Error>().is_some() {
                    "Network error: "
                } else {
                    "Server error: "
                };
                *out_result = SimulateOutcome::Error(format!("{prefix}{e}"));
            }
        }
    }
}
```

### B-9. `draw_policy_simulate` (render.rs)

**Analog:** `draw_policy_create` (render.rs lines 751–901) — multi-row form with inline error region.

**Structure:**
- Build 13 render rows (4 section headers + 9 editable rows). Render the selected editable row with cyan highlight.
- Section headers: rendered as dim, bold `ListItem`s using `Span::styled(...)` with `Color::DarkGray`.
- Editable rows: show label + current value; selected text row shows `[buffer_]` cursor.
- Inline result block: positioned below the form, inside the same `area`. Success renders 3-line paragraph with colored Decision; Error renders single red paragraph.
- Hints bar: `"Up/Down: navigate | Enter: select/cycle | Esc: back"`.

```rust
/// Row definitions for the simulate form (editable index -> label).
/// Section header rows are inserted at specific positions in the render list.
const SIMULATE_FIELD_LABELS: [&str; 10] = [
    "User SID",
    "User Name",
    "Groups (comma-separated SIDs)",
    "Device Trust",
    "Network Location",
    "Path",
    "Classification",
    "Action",
    "Access Context",
    "[Simulate]",
];

/// Section header positions in the full render list (non-editable rows).
const SIMULATE_SECTION_HEADERS: [(usize, &'static str); 4] = [
    (4, "--- Subject ---"),
    (6, "--- Resource ---"),
    (8, "--- Environment ---"),
    (10, "--- Submit ---"),
];

/// Builds the full render list including section-header rows.
///
/// Returns a `Vec<(render_row_index, ListItem)>` so the caller can map
/// `selected` (editable index 0..=9) → render position for ListState selection.
fn build_simulate_items(form: &SimulateFormState, selected: usize, editing: bool, buffer: &str) -> Vec<(usize, ListItem<'static>)> {
    let mut items = Vec::with_capacity(14);
    let mut render_idx = 0usize;

    // Helper to push a header row.
    let push_header = |items: &mut Vec<_>, render_idx: &mut usize, label: &'static str| {
        let line = Line::styled(
            format!("  {label}"),
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
        items.push((*render_idx, ListItem::new(line)));
        *render_idx += 1;
    };

    // Row 0: User SID
    let line = if editing && selected == 0 {
        Line::from(format!("User SID:               [{buffer}_]"))
    } else if form.user_sid.is_empty() {
        Line::from(vec![
            Span::raw("User SID:               "),
            Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(format!("User SID:               {}", form.user_sid))
    };
    items.push((render_idx, ListItem::new(line)));
    render_idx += 1;

    // Row 1: User Name
    let line = if editing && selected == 1 {
        Line::from(format!("User Name:              [{buffer}_]"))
    } else if form.user_name.is_empty() {
        Line::from(vec![
            Span::raw("User Name:              "),
            Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(format!("User Name:              {}", form.user_name))
    };
    items.push((render_idx, ListItem::new(line)));
    render_idx += 1;

    // Row 2: Groups
    let line = if editing && selected == 2 {
        Line::from(format!("Groups (comma-SIDs):    [{buffer}_]"))
    } else if form.groups_raw.is_empty() {
        Line::from(vec![
            Span::raw("Groups (comma-SIDs):    "),
            Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(format!("Groups (comma-SIDs):    {}", form.groups_raw))
    };
    items.push((render_idx, ListItem::new(line)));
    render_idx += 1;

    // Row 3: Device Trust
    push_header(items, &mut render_idx, "Subject ---");
    let dt_label = SIMULATE_DEVICE_TRUST_OPTIONS[form.device_trust.min(SIMULATE_DEVICE_TRUST_OPTIONS.len() - 1)];
    items.push((render_idx, ListItem::new(Line::from(format!("Device Trust:           {dt_label}")))));
    render_idx += 1;

    // Row 4: Network Location
    let nl_label = SIMULATE_NETWORK_LOCATION_OPTIONS[form.network_location.min(SIMULATE_NETWORK_LOCATION_OPTIONS.len() - 1)];
    items.push((render_idx, ListItem::new(Line::from(format!("Network Location:       {nl_label}")))));
    render_idx += 1;

    // Row 5: Path
    push_header(items, &mut render_idx, "Resource ---");
    let line = if editing && selected == 5 {
        Line::from(format!("Path:                   [{buffer}_]"))
    } else if form.path.is_empty() {
        Line::from(vec![
            Span::raw("Path:                   "),
            Span::styled("(empty)", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(format!("Path:                   {}", form.path))
    };
    items.push((render_idx, ListItem::new(line)));
    render_idx += 1;

    // Row 6: Classification
    let cl_label = SIMULATE_CLASSIFICATION_OPTIONS[form.classification.min(SIMULATE_CLASSIFICATION_OPTIONS.len() - 1)];
    items.push((render_idx, ListItem::new(Line::from(format!("Classification:         {cl_label}")))));
    render_idx += 1;

    // Row 7: Action
    push_header(items, &mut render_idx, "Environment ---");
    let ac_label = SIMULATE_ACTION_OPTIONS[form.action.min(SIMULATE_ACTION_OPTIONS.len() - 1)];
    items.push((render_idx, ListItem::new(Line::from(format!("Action:                {ac_label}")))));
    render_idx += 1;

    // Row 8: Access Context
    let cx_label = SIMULATE_ACCESS_CONTEXT_OPTIONS[form.access_context.min(SIMULATE_ACCESS_CONTEXT_OPTIONS.len() - 1)];
    items.push((render_idx, ListItem::new(Line::from(format!("Access Context:        {cx_label}")))));
    render_idx += 1;

    // Row 9: [Simulate] submit
    push_header(items, &mut render_idx, "Submit ---");
    items.push((render_idx, ListItem::new(Line::from("  [Simulate]"))));
    // render_idx += 1; // not needed after last row

    items
}

/// Maps an editable `selected` index (0..=9) to the render list position.
fn simulate_editable_to_render(selected: usize) -> usize {
    // Matches the build order in build_simulate_items above.
    // section header at 4 → insert before index 4
    // section header at 6 → insert before index 6
    // section header at 8 → insert before index 8
    // section header at 10 → insert before index 10
    const EDITO_TO_RENDER: [usize; 10] = [
        0, 1, 2,       // user_sid, user_name, groups (no header)
        4, 5,          // device_trust, network_location (after "Subject" header at 4)
        7, 8,          // path, classification (after "Resource" header at 7)
        10, 11,        // action, access_context (after "Environment" header at 10)
        13,            // [Simulate] (after "Submit" header at 13)
    ];
    EDITO_TO_RENDER.get(selected).copied().unwrap_or(0)
}

/// Draws the Policy Simulate multi-field form with inline result block.
fn draw_policy_simulate(
    frame: &mut Frame,
    area: Rect,
    form: &SimulateFormState,
    selected: usize,
    editing: bool,
    buffer: &str,
    result: &SimulateOutcome,
) {
    let items = build_simulate_items(form, selected, editing, buffer);
    let render_selected = simulate_editable_to_render(selected);

    // Render list items without block (block wraps the whole form including result).
    let list_items: Vec<ListItem> = items.iter().map(|(_, item)| item.clone()).collect();

    let list = List::new(list_items)
        .block(Block::default().title(" Policy Simulate ").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = ListState::default();
    state.select(Some(render_selected));
    frame.render_stateful_widget(list, area, &mut state);

    // Inline result block below the form.
    let result_height = 4u16;
    if area.height > result_height + 3 {
        let result_area = Rect {
            x: area.x + 2,
            y: area.y + area.height - result_height - 1,
            width: area.width.saturating_sub(4),
            height: result_height,
        };

        match result {
            SimulateOutcome::None => {
                // No result block rendered.
            }
            SimulateOutcome::Success(resp) => {
                // Build 3-line paragraph: Matched policy / Decision (colored) / Reason.
                let decision_color = if resp.decision.is_denied() {
                    Color::Red
                } else {
                    Color::Green
                };
                let matched = resp.matched_policy_id
                    .as_deref()
                    .unwrap_or("none");
                let lines = vec![
                    Line::from(format!("Matched policy:  {matched}")),
                    Line::from(vec![
                        Span::raw("Decision:        "),
                        Span::styled(format!("{:?}", resp.decision), Style::default().fg(decision_color)),
                    ]),
                    Line::from(format!("Reason:          {}", resp.reason)),
                ];
                let block = Block::default()
                    .title(" Result ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green));
                frame.render_widget(
                    Paragraph::new(lines).block(block),
                    result_area,
                );
            }
            SimulateOutcome::Error(msg) => {
                let block = Block::default()
                    .title(" Error ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red));
                frame.render_widget(
                    Paragraph::new(msg.as_str()).style(Style::default().fg(Color::Red)).block(block),
                    result_area,
                );
            }
        }
    }

    let hints = if editing {
        "Type to edit | Enter: commit | Esc: cancel"
    } else {
        "Up/Down: navigate | Enter: select/cycle | Esc: back"
    };
    draw_hints(frame, area, hints);
}
```

### B-10. `draw_screen` arm — add `PolicySimulate` match arm (render.rs §26–187)

**Analog:** `Screen::PolicyCreate { form, selected, editing, buffer, validation_error }` arm (render.rs lines 151–167)

**Placement:** after `Screen::PolicyEdit` arm, before the closing `}` of `draw_screen`.

```rust
Screen::PolicySimulate {
    form,
    selected,
    editing,
    buffer,
    result,
    ..
} => {
    draw_policy_simulate(
        frame,
        area,
        form,
        *selected,
        *editing,
        buffer,
        result,
    );
}
```

---

## 4. Pattern C — `chrono` Dependency

### C-1. `Cargo.toml` — add `chrono = "0.4"`

**File:** `dlp-admin-cli/Cargo.toml`

**Placement:** in `[dependencies]` section, alphabetically after `bcrypt`.

```toml
# Date/time for evaluate request timestamp
chrono = "0.4"
```

**Verification:** `chrono` is used transitively via `dlp-common` (dependency of `dlp-common`), but adding it as a direct dependency ensures `chrono::Utc::now()` compiles reliably. The `chrono` feature flags needed are `std` and `serde` (both default for `"0.4"`). No explicit features needed.

---

## 5. Wiring Checklist

| # | Change | Location | Status |
|---|--------|----------|--------|
| 1 | Add `chrono = "0.4"` to `Cargo.toml` | `dlp-admin-cli/Cargo.toml` | Add |
| 2 | Add `SimulateCaller`, `SimulateOutcome`, `SimulateFormState` types | `app.rs` before `Screen` enum | Add |
| 3 | Add `PolicySimulate` variant to `Screen` enum | `app.rs` inside enum | Add |
| 4 | Add `PolicySimulate` arm in `handle_event` | `dispatch.rs` line ~36 | Add |
| 5 | Add `Char('n')` branch in `handle_policy_list` | `dispatch.rs` after `Char('d')` branch | Add |
| 6 | Inject sort in `action_list_policies` | `dispatch.rs` inside `Ok(policies)` block | Modify |
| 7 | Extend MainMenu menu array + nav count + Enter branch | `render.rs` + `dispatch.rs` | Modify |
| 8 | Extend PolicyMenu menu array + nav count + Enter branch | `render.rs` + `dispatch.rs` | Modify |
| 9 | Rewrite `draw_policy_list` columns/widths/hints | `render.rs` lines 1137–1192 | Modify |
| 10 | Add `draw_policy_simulate` function | `render.rs` new function | Add |
| 11 | Add `PolicySimulate` arm in `draw_screen` | `render.rs` inside `draw_screen` | Add |
| 12 | Add `action_open_simulate`, `handle_policy_simulate`, `handle_simulate_editing`, `handle_simulate_nav`, `action_submit_simulate` | `dispatch.rs` new functions | Add |
| 13 | Add `SIMULATE_*` option arrays and `SIMULATE_ROW_COUNT`, `SIMULATE_SUBMIT_ROW` constants | `dispatch.rs` (or `app.rs`) | Add |

---

## 6. Serde Contracts (Authoritative)

These are confirmed from `dlp-common/src/abac.rs` and `dlp-common/src/classification.rs`:

| Type | Wire string | Notes |
|------|-------------|-------|
| `DeviceTrust::Managed` | `"Managed"` | `#[serde(rename_all = "PascalCase")]` |
| `DeviceTrust::Unmanaged` | `"Unmanaged"` | |
| `DeviceTrust::Compliant` | `"Compliant"` | |
| `DeviceTrust::Unknown` | `"Unknown"` | default |
| `NetworkLocation::Corporate` | `"Corporate"` | `#[serde(rename_all = "PascalCase")]` |
| `NetworkLocation::CorporateVpn` | `"CorporateVpn"` | |
| `NetworkLocation::Guest` | `"Guest"` | |
| `NetworkLocation::Unknown` | `"Unknown"` | default |
| `AccessContext::Local` | `"local"` | `#[serde(rename_all = "lowercase")]` |
| `AccessContext::Smb` | `"smb"` | |
| `Classification::T1` | `"t1"` | `#[serde(rename_all = "lowercase")]` |
| `Classification::T2` | `"t2"` | |
| `Classification::T3` | `"t3"` | |
| `Classification::T4` | `"t4"` | |
| `Action::READ` | `"READ"` | no rename attribute |
| `Action::WRITE` | `"WRITE"` | |
| `Action::COPY` | `"COPY"` | |
| `Action::DELETE` | `"DELETE"` | |
| `Action::MOVE` | `"MOVE"` | |
| `Action::PASTE` | `"PASTE"` | |
| `Decision::is_denied()` | returns `true` for `DENY`, `DenyWithAlert` | used for red/green coloring |

`Environment.timestamp` serializes as ISO 8601 / RFC 3339 string. `serde_json` handles this automatically with chrono serde (default for `"0.4"`).

---

## 7. Existing Codebase Reference Points

| Pattern | Source location | Usage in Phase 16 |
|---------|----------------|-------------------|
| Table rendering with `Table` widget | `render.rs` lines 1137–1192 | Replace columns in `draw_policy_list` |
| Footer hints via `draw_hints` | `render.rs` line 1187 | Update hint string |
| `nav` helper for wrap-around Up/Down | `dispatch.rs` lines 45–55 | Reuse for simulate row nav |
| `handle_policy_list` match structure | `dispatch.rs` lines 393–434 | Add `Char('n')` branch |
| `action_list_policies` HTTP pattern | `dispatch.rs` lines 458–475 | Add sort before assignment |
| `handle_main_menu` / `handle_policy_menu` | `dispatch.rs` lines 61–169 | Extend nav counts + Enter branches |
| `draw_main_menu` / `draw_policy_menu` arrays | `render.rs` lines 28–80 | Extend item arrays |
| `draw_policy_create` multi-row form | `render.rs` lines 751–901 | Template for `draw_policy_simulate` |
| `handle_policy_create_nav` select cycling | `dispatch.rs` lines 1149–1238 | Template for `handle_simulate_nav` select rows |
| `handle_siem_config_editing` text pattern | `dispatch.rs` lines 728–764 | Template for `handle_simulate_editing` |
| `action_save_siem_config` block_on pattern | `dispatch.rs` lines 692–707 | Template for `action_submit_simulate` |
| `EngineClient::post` generic | `client.rs` lines 221–243 | Reuse for `POST /evaluate` |
| `PolicyFormState` struct shape | `app.rs` lines 123–140 | Template for `SimulateFormState` |
| `ConditionsBuilder` caller pattern | `app.rs` lines 106–116 | Template for `SimulateCaller` |
| `SimulateOutcome` as inline result enum | `render.rs` lines 880–892 (validation_error region) | Extend to `SimulateOutcome` enum |