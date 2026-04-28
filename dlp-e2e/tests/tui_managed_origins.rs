//! Headless TUI integration test for the Managed Origins screen flow.
//!
//! Automates the deferred Phase 28 UAT item for Managed Origins TUI screen
//! verification.  Injects `KeyEvent` sequences into the `App` state machine
//! via `TestBackend` and asserts on both internal state transitions and
//! rendered output.
//!
//! All tests are gated with `#[cfg(windows)]` because the `dlp-admin-cli`
//! crate depends on Win32 APIs that do not compile on non-Windows targets.

#![cfg(windows)]

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dlp_admin_cli::app::{App, Screen};
use dlp_admin_cli::event::AppEvent;
use dlp_admin_cli::screens::handle_event;
use dlp_e2e::helpers::{server, tui};
use ratatui::buffer::Buffer;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawns a real mock axum server on an ephemeral port and builds a TUI
/// `App` wired to it.
///
/// Returns `(app, pool, socket_addr, _rt)` so callers can verify DB state
/// directly. The runtime must be kept alive for the server task to continue
/// serving requests.
fn setup_test_app() -> (
    App,
    std::sync::Arc<dlp_server::db::Pool>,
    std::net::SocketAddr,
    tokio::runtime::Runtime,
) {
    let (router, pool) = server::build_test_app();

    // Use a multi-threaded runtime for the mock server so that spawned
    // server tasks continue executing even after block_on returns.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("create multi-threaded runtime");

    let addr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP listener");
        let addr = listener.local_addr().expect("get local addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("mock server serve");
        });
        // Brief pause to let the server start accepting connections.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        addr
    });

    let app = tui::build_test_app_with_mock_client(format!("http://{addr}"));
    (app, pool, addr, rt)
}

/// Convenience: inject a single key event into the app.
fn inject(app: &mut App, key: KeyEvent) {
    handle_event(app, AppEvent::Key(key));
}

// ---------------------------------------------------------------------------
// Test 1: Navigation from MainMenu -> DevicesMenu -> ManagedOriginList
// ---------------------------------------------------------------------------

/// Verifies that the correct key sequence navigates from the main menu
/// through the Devices & Origins submenu to the Managed Origins list.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_navigate_to_managed_origins() {
    let (mut app, _pool, _addr, _rt) = setup_test_app();

    // Initial state: MainMenu.
    assert!(
        matches!(app.screen, Screen::MainMenu { selected: 0 }),
        "expected MainMenu at start"
    );

    // MainMenu -> DevicesMenu: Down x3, Enter.
    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    for _ in 0..3 {
        inject(&mut app, down);
    }
    inject(&mut app, enter);

    assert!(
        matches!(app.screen, Screen::DevicesMenu { selected: 0 }),
        "expected DevicesMenu after Down x3 + Enter"
    );

    // DevicesMenu -> ManagedOriginList: Down x1, Enter.
    inject(&mut app, down);
    inject(&mut app, enter);

    // The API call is synchronous (block_on) so the screen transition is
    // immediate when running on a non-tokio-test thread.
    assert!(
        matches!(app.screen, Screen::ManagedOriginList { .. }),
        "expected ManagedOriginList after navigating from DevicesMenu"
    );

    // Render assertion: buffer must contain "Managed Origins" header text.
    let buffer = tui::render_to_buffer(&app, 80, 24);
    let buf: &Buffer = buffer.buffer();
    let text: String = buf.content.iter().map(|c| c.symbol()).collect();
    assert!(
        text.contains("Managed Origins"),
        "rendered buffer should contain 'Managed Origins': {text}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Add a managed origin
// ---------------------------------------------------------------------------

/// Verifies the full add-origin flow: navigate to ManagedOriginList,
/// press 'a', type an origin URL, confirm, and assert the list reloads
/// with the new entry.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_add_managed_origin() {
    let (mut app, _pool, _addr, _rt) = setup_test_app();

    // Navigate to ManagedOriginList.
    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    for _ in 0..3 {
        inject(&mut app, down);
    }
    inject(&mut app, enter);
    inject(&mut app, down);
    inject(&mut app, enter);

    // Press 'a' to open the text input for adding an origin.
    let char_a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
    inject(&mut app, char_a);

    assert!(
        matches!(app.screen, Screen::TextInput { ref prompt, .. } if prompt.contains("Origin URL pattern")),
        "expected TextInput with origin URL prompt after pressing 'a'"
    );

    // Type the origin URL character by character.
    let origin_url = "https://company.sharepoint.com/*";
    for ch in origin_url.chars() {
        inject(&mut app, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
    }
    // Confirm with Enter.
    inject(&mut app, enter);

    // The POST and reload are synchronous (block_on) so we can assert immediately.
    assert!(
        matches!(app.screen, Screen::ManagedOriginList { .. }),
        "expected ManagedOriginList after adding origin"
    );

    // Verify the origin data.
    if let Screen::ManagedOriginList { ref origins, .. } = app.screen {
        assert_eq!(
            origins.len(),
            1,
            "expected exactly 1 origin after add, got {origins:?}"
        );
        assert_eq!(
            origins[0]["origin"].as_str(),
            Some("https://company.sharepoint.com/*"),
            "origin URL should match"
        );
    } else {
        panic!("expected ManagedOriginList screen");
    }

    // Render assertion: buffer must show the origin URL.
    let buffer = tui::render_to_buffer(&app, 80, 24);
    let buf: &Buffer = buffer.buffer();
    let text: String = buf.content.iter().map(|c| c.symbol()).collect();
    assert!(
        text.contains("company.sharepoint.com"),
        "rendered buffer should show origin URL: {text}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Remove a managed origin
// ---------------------------------------------------------------------------

/// Verifies the remove-origin flow: from a list with one origin, press 'd',
/// confirm the delete dialog, and assert the list reloads empty.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_remove_managed_origin() {
    let (mut app, _pool, _addr, _rt) = setup_test_app();

    // Navigate to ManagedOriginList.
    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    for _ in 0..3 {
        inject(&mut app, down);
    }
    inject(&mut app, enter);
    inject(&mut app, down);
    inject(&mut app, enter);

    // Add an origin first so we have something to delete.
    let origin_url = "https://company.sharepoint.com/*";
    let char_a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
    inject(&mut app, char_a);

    for ch in origin_url.chars() {
        inject(&mut app, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
    }
    inject(&mut app, enter);

    // Verify origin was added.
    let origin_id = if let Screen::ManagedOriginList { ref origins, .. } = app.screen {
        assert_eq!(origins.len(), 1, "expected 1 origin after add");
        origins[0]["id"]
            .as_str()
            .expect("origin must have id")
            .to_string()
    } else {
        panic!("expected ManagedOriginList after add");
    };
    assert!(!origin_id.is_empty(), "expected non-empty origin id");

    // Press 'd' to open delete confirmation.
    let char_d = KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE);
    inject(&mut app, char_d);

    assert!(
        matches!(
            app.screen,
            Screen::Confirm {
                ref message,
                yes_selected: true,
                purpose: dlp_admin_cli::app::ConfirmPurpose::DeleteManagedOrigin { .. },
                ..
            } if message.contains("company.sharepoint.com")
        ),
        "expected Confirm dialog with origin URL in message"
    );

    // Confirm deletion with Enter (yes_selected defaults to true).
    inject(&mut app, enter);

    // The DELETE and reload are synchronous (block_on) so we can assert immediately.
    assert!(
        matches!(app.screen, Screen::ManagedOriginList { .. }),
        "expected ManagedOriginList after deletion"
    );

    if let Screen::ManagedOriginList { ref origins, .. } = app.screen {
        assert!(
            origins.is_empty(),
            "expected empty origin list after deletion, got {origins:?}"
        );
    } else {
        panic!("expected ManagedOriginList screen after delete");
    }
}
