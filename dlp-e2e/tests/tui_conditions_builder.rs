//! Headless TUI integration test for the Conditions Builder modal (app-identity).
//!
//! Automates the deferred Phase 28 UAT item for App-Identity Conditions Builder
//! verification.  Exercises the 3-step flow (Attribute -> Operator -> Value) for
//! both SourceApplication and DestinationApplication attributes, covering all three
//! AppField variants (Publisher, ImagePath, TrustTier) and both text-input and
//! picker-based Step 3 paths.
//!
//! All tests are gated with `#[cfg(windows)]` because the `dlp-admin-cli` crate
//! depends on Win32 APIs that do not compile on non-Windows targets.

#![cfg(windows)]

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dlp_admin_cli::app::{App, ConditionAttribute, Screen};
use dlp_common::abac::{AppField, PolicyCondition};
use dlp_admin_cli::event::AppEvent;
use dlp_admin_cli::screens::handle_event;
use dlp_e2e::helpers;
use ratatui::buffer::Buffer;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawns a real mock axum server on an ephemeral port and builds a TUI
/// `App` wired to it.
///
/// Returns `(app, pool, socket_addr)` so callers can verify DB state directly.
fn setup_test_app() -> (App, std::sync::Arc<dlp_server::db::Pool>, std::net::SocketAddr) {
    let (router, pool) = helpers::server::build_test_app();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create local runtime");

    let addr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP listener");
        let addr = listener.local_addr().expect("get local addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("mock server serve");
        });
        addr
    });

    let app = helpers::tui::build_test_app_with_mock_client(format!("http://{addr}"));
    (app, pool, addr)
}

/// Convenience: inject a single key event into the app.
fn inject(app: &mut App, key: KeyEvent) {
    handle_event(app, AppEvent::Key(key));
}

/// Type a string into the active text input buffer, character by character.
fn type_text(app: &mut App, text: &str) {
    for ch in text.chars() {
        inject(app, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
    }
}

/// Navigate from MainMenu to PolicyCreate and open the ConditionsBuilder modal.
///
/// On entry, the app is at MainMenu.  This helper:
/// 1. Navigates to PolicyMenu (Down, Enter).
/// 2. Navigates to Create Policy (Down x2, Enter).
/// 3. Navigates to row 5 ([Add Conditions]) and presses Enter.
///
/// After return, `app.screen` is `Screen::ConditionsBuilder { step: 1, .. }`.
fn open_conditions_builder(app: &mut App) {
    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    // MainMenu -> PolicyMenu (index 1).
    inject(app, down);
    inject(app, enter);
    assert!(
        matches!(app.screen, Screen::PolicyMenu { selected: 0 }),
        "expected PolicyMenu after Down + Enter"
    );

    // PolicyMenu -> PolicyCreate (index 2).
    // PolicyMenu starts at selected:0 (List Policies). Down x2 -> Create Policy.
    inject(app, down);
    inject(app, down);
    inject(app, enter);
    assert!(
        matches!(app.screen, Screen::PolicyCreate { .. }),
        "expected PolicyCreate after Down x2 + Enter"
    );

    // Navigate to row 6 ([Add Conditions]) and open ConditionsBuilder.
    // PolicyCreate rows: 0=Name, 1=Desc, 2=Priority, 3=Action, 4=Enabled, 5=Mode, 6=Add Conditions.
    // We start at selected:0. Down x6 reaches row 6.
    for _ in 0..6 {
        inject(app, down);
    }
    inject(app, enter);

    assert!(
        matches!(app.screen, Screen::ConditionsBuilder { step: 1, .. }),
        "expected ConditionsBuilder at step 1 after opening from PolicyCreate"
    );
}

/// Extract the pending conditions list from a ConditionsBuilder screen.
fn pending_conditions(app: &App) -> Vec<PolicyCondition> {
    match &app.screen {
        Screen::ConditionsBuilder { pending, .. } => pending.clone(),
        _ => panic!("expected ConditionsBuilder screen"),
    }
}

// ---------------------------------------------------------------------------
// Test 1: SourceApplication Publisher eq (text-input Step 3)
// ---------------------------------------------------------------------------

/// Verifies the full SourceApplication -> Publisher -> eq -> text value flow.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_source_application_publisher_eq() {
    let (mut app, _pool, _addr) = setup_test_app();
    open_conditions_builder(&mut app);

    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    // Step 1: navigate to SourceApplication (index 5 from Classification at 0).
    for _ in 0..5 {
        inject(&mut app, down);
    }
    inject(&mut app, enter);

    // App-identity attribute selected but field not yet chosen: still step 1.
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 1,
                selected_attribute: Some(ConditionAttribute::SourceApplication),
                selected_field: None,
                ..
            }
        ),
        "expected Step 1 with SourceApplication selected and no field yet"
    );

    // AppField sub-step: Enter on publisher (index 0) -> advances to Step 2.
    inject(&mut app, enter);
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 2,
                selected_field: Some(AppField::Publisher),
                ..
            }
        ),
        "expected Step 2 with Publisher field selected"
    );

    // Step 2: Enter on "eq" (index 0 for Publisher) -> advances to Step 3.
    inject(&mut app, enter);
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 3,
                selected_operator: Some(op),
                ..
            } if op == "eq"
        ),
        "expected Step 3 with eq operator selected"
    );

    // Step 3: type value and confirm.
    type_text(&mut app, "Microsoft Corporation");
    inject(&mut app, enter);

    // Condition added; back to Step 1 with pending list populated.
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 1,
                pending,
                ..
            } if pending.len() == 1
        ),
        "expected Step 1 with 1 pending condition"
    );

    // Verify the exact condition structure.
    let pending = pending_conditions(&app);
    assert!(
        matches!(
            &pending[0],
            PolicyCondition::SourceApplication {
                field: AppField::Publisher,
                op,
                value,
            } if op == "eq" && value == "Microsoft Corporation"
        ),
        "expected SourceApplication Publisher eq 'Microsoft Corporation', got {:?}",
        pending[0]
    );

    // Esc closes modal and returns to PolicyCreate with conditions populated.
    let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
    inject(&mut app, esc);

    assert!(
        matches!(
            &app.screen,
            Screen::PolicyCreate { form, .. } if form.conditions.len() == 1
        ),
        "expected PolicyCreate with 1 condition after closing modal"
    );

    // Render assertion: buffer must contain "SourceApplication".
    let buffer = helpers::tui::render_to_buffer(&app, 80, 24);
    let buf: &Buffer = buffer.buffer();
    let text: String = buf.content.iter().map(|c| c.symbol()).collect();
    assert!(
        text.contains("SourceApplication"),
        "rendered buffer should contain 'SourceApplication': {text}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: DestinationApplication ImagePath contains (text-input Step 3)
// ---------------------------------------------------------------------------

/// Verifies the DestinationApplication -> ImagePath -> contains -> text value flow.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_destination_application_imagepath_contains() {
    let (mut app, _pool, _addr) = setup_test_app();
    open_conditions_builder(&mut app);

    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    // Step 1: navigate to DestinationApplication (index 6 from Classification at 0).
    for _ in 0..6 {
        inject(&mut app, down);
    }
    inject(&mut app, enter);

    // App-identity attribute selected but field not yet chosen: still step 1.
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 1,
                selected_attribute: Some(ConditionAttribute::DestinationApplication),
                selected_field: None,
                ..
            }
        ),
        "expected Step 1 with DestinationApplication selected"
    );

    // AppField sub-step: Down to ImagePath (index 1), Enter -> advances to Step 2.
    inject(&mut app, down);
    inject(&mut app, enter);
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 2,
                selected_field: Some(AppField::ImagePath),
                ..
            }
        ),
        "expected Step 2 with ImagePath field selected"
    );

    // Step 2: Down x2 to "contains" (index 2 for ImagePath), Enter -> Step 3.
    inject(&mut app, down);
    inject(&mut app, down);
    inject(&mut app, enter);
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 3,
                selected_operator: Some(op),
                ..
            } if op == "contains"
        ),
        "expected Step 3 with contains operator selected"
    );

    // Step 3: type value and confirm.
    type_text(&mut app, "chrome.exe");
    inject(&mut app, enter);

    let pending = pending_conditions(&app);
    assert_eq!(pending.len(), 1, "expected exactly 1 pending condition");
    assert!(
        matches!(
            &pending[0],
            PolicyCondition::DestinationApplication {
                field: AppField::ImagePath,
                op,
                value,
            } if op == "contains" && value == "chrome.exe"
        ),
        "expected DestinationApplication ImagePath contains 'chrome.exe', got {:?}",
        pending[0]
    );

    // Close modal and verify PolicyCreate state.
    let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
    inject(&mut app, esc);

    assert!(
        matches!(
            &app.screen,
            Screen::PolicyCreate { form, .. } if form.conditions.len() == 1
        ),
        "expected PolicyCreate with 1 condition"
    );

    // Render assertion: buffer must contain "DestinationApplication".
    let buffer = helpers::tui::render_to_buffer(&app, 80, 24);
    let buf: &Buffer = buffer.buffer();
    let text: String = buf.content.iter().map(|c| c.symbol()).collect();
    assert!(
        text.contains("DestinationApplication"),
        "rendered buffer should contain 'DestinationApplication': {text}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: SourceApplication TrustTier eq (picker-based Step 3)
// ---------------------------------------------------------------------------

/// Verifies the SourceApplication -> TrustTier -> eq -> picker value flow.
/// Step 3 uses a list picker (not free-text input) for TrustTier.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_source_application_trusttier_eq_picker() {
    let (mut app, _pool, _addr) = setup_test_app();
    open_conditions_builder(&mut app);

    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    // Step 1: navigate to SourceApplication (index 5).
    for _ in 0..5 {
        inject(&mut app, down);
    }
    inject(&mut app, enter);

    // AppField sub-step: Down x2 to TrustTier (index 2), Enter -> Step 2.
    inject(&mut app, down);
    inject(&mut app, down);
    inject(&mut app, enter);
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 2,
                selected_field: Some(AppField::TrustTier),
                ..
            }
        ),
        "expected Step 2 with TrustTier field selected"
    );

    // Step 2: Enter on "eq" (index 0 for TrustTier — only eq/ne available).
    inject(&mut app, enter);
    assert!(
        matches!(
            &app.screen,
            Screen::ConditionsBuilder {
                step: 3,
                selected_operator: Some(op),
                ..
            } if op == "eq"
        ),
        "expected Step 3 with eq operator selected"
    );

    // Step 3 is a picker: Down to "untrusted" (index 1), Enter.
    // Note: TrustTier picker values are ["trusted"(0), "untrusted"(1), "unknown"(2)].
    inject(&mut app, down);
    inject(&mut app, enter);

    let pending = pending_conditions(&app);
    assert_eq!(pending.len(), 1, "expected exactly 1 pending condition");
    assert!(
        matches!(
            &pending[0],
            PolicyCondition::SourceApplication {
                field: AppField::TrustTier,
                op,
                value,
            } if op == "eq" && value == "untrusted"
        ),
        "expected SourceApplication TrustTier eq 'untrusted', got {:?}",
        pending[0]
    );

    // Close modal and verify PolicyCreate state.
    let esc = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
    inject(&mut app, esc);

    assert!(
        matches!(
            &app.screen,
            Screen::PolicyCreate { form, .. } if form.conditions.len() == 1
        ),
        "expected PolicyCreate with 1 condition"
    );

    // Render assertion: buffer must contain "SourceApplication".
    let buffer = helpers::tui::render_to_buffer(&app, 80, 24);
    let buf: &Buffer = buffer.buffer();
    let text: String = buf.content.iter().map(|c| c.symbol()).collect();
    assert!(
        text.contains("SourceApplication"),
        "rendered buffer should contain 'SourceApplication': {text}"
    );
}
