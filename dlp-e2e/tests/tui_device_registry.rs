//! Headless TUI integration test for the Device Registry screen flow.
//!
//! Automates the deferred Phase 28 UAT item for Device Registry TUI screen
//! verification.  Injects `KeyEvent` sequences into the `App` state machine
//! via `TestBackend` and asserts on both internal state transitions and
//! rendered output.
//!
//! All tests are gated with `#[cfg(windows)]` because the `dlp-admin-cli`
//! crate depends on Win32 APIs that do not compile on non-Windows targets.

#![cfg(windows)]

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dlp_admin_cli::app::{App, ConfirmPurpose, Screen};
use dlp_admin_cli::event::AppEvent;
use dlp_admin_cli::screens::handle_event;
use dlp_e2e::helpers::{server, tui};
use ratatui::buffer::{Buffer, Cell};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawns a real mock axum server on an ephemeral port and builds a TUI
/// `App` wired to it.
///
/// Returns `(app, pool, socket_addr, rt)` so callers can verify DB state
/// directly. The runtime must be kept alive for the server task to continue
/// serving requests throughout the test.
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
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TCP listener");
        let addr = listener.local_addr().expect("get local addr");
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock server serve");
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

/// Navigate from the initial `MainMenu` state to `DeviceList`.
///
/// Key sequence:
/// - Down x3, Enter  -> `DevicesMenu`
/// - Enter           -> `DeviceList` (selects "Device Registry" at index 0)
fn navigate_to_device_list(app: &mut App) {
    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    // MainMenu: Down x3 to select "Devices & Origins" (index 3).
    for _ in 0..3 {
        inject(app, down);
    }
    inject(app, enter);

    assert!(
        matches!(app.screen, Screen::DevicesMenu { selected: 0 }),
        "expected DevicesMenu after Down x3 + Enter"
    );

    // DevicesMenu: Enter on index 0 ("Device Registry") -> DeviceList.
    inject(app, enter);

    assert!(
        matches!(app.screen, Screen::DeviceList { .. }),
        "expected DeviceList after Enter from DevicesMenu"
    );
}

/// Register a device via the TUI text-input chain and DeviceTierPicker.
///
/// Starting from `DeviceList`, injects 'r', types VID / PID / serial /
/// description, then selects the blocked tier (index 0) and confirms.
/// After return the app is at `DeviceList` with the new device loaded.
fn register_blocked_device(app: &mut App) {
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    // 'r' opens the VID text input.
    inject(app, KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));

    assert!(
        matches!(
            app.screen,
            Screen::TextInput { ref prompt, .. } if prompt.contains("VID")
        ),
        "expected TextInput with VID prompt after pressing 'r'"
    );

    // Type VID "0951", confirm.
    type_text(app, "0951");
    inject(app, enter);

    assert!(
        matches!(
            app.screen,
            Screen::TextInput { ref prompt, .. } if prompt.contains("PID")
        ),
        "expected TextInput with PID prompt after entering VID"
    );

    // Type PID "1666", confirm.
    type_text(app, "1666");
    inject(app, enter);

    assert!(
        matches!(
            app.screen,
            Screen::TextInput { ref prompt, .. } if prompt.contains("serial") || prompt.contains("Serial")
        ),
        "expected TextInput with serial prompt after entering PID"
    );

    // Type serial "SN001", confirm.
    type_text(app, "SN001");
    inject(app, enter);

    assert!(
        matches!(
            app.screen,
            Screen::TextInput { ref prompt, .. } if prompt.contains("escription")
        ),
        "expected TextInput with description prompt after entering serial"
    );

    // Type description "Test USB", confirm.
    type_text(app, "Test USB");
    inject(app, enter);

    // Now at DeviceTierPicker with selected == 0 (blocked).
    assert!(
        matches!(
            app.screen,
            Screen::DeviceTierPicker { selected: 0, .. }
        ),
        "expected DeviceTierPicker at index 0 (blocked) after entering description"
    );

    // Enter confirms the blocked tier and POSTs to the server; DeviceList reloads.
    inject(app, enter);

    assert!(
        matches!(app.screen, Screen::DeviceList { .. }),
        "expected DeviceList after confirming tier in DeviceTierPicker"
    );
}

/// Type a string character by character into the active text input buffer.
fn type_text(app: &mut App, text: &str) {
    for ch in text.chars() {
        inject(app, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
    }
}

// ---------------------------------------------------------------------------
// Test 1: Navigation from MainMenu -> DevicesMenu -> DeviceList
// ---------------------------------------------------------------------------

/// Verifies that the correct key sequence navigates from the main menu
/// through the Devices & Origins submenu to the Device Registry list.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_navigate_to_device_list() {
    let (mut app, _pool, _addr, _rt) = setup_test_app();

    // Initial state: MainMenu.
    assert!(
        matches!(app.screen, Screen::MainMenu { selected: 0 }),
        "expected MainMenu at start"
    );

    navigate_to_device_list(&mut app);

    // DeviceList with zero pre-seeded entries.
    assert!(
        matches!(app.screen, Screen::DeviceList { .. }),
        "expected DeviceList screen after navigation"
    );

    // Render assertion: buffer must contain "Device Registry" header text.
    let buffer = tui::render_to_buffer(&app, 80, 24);
    let buf: &Buffer = buffer.buffer();
    let text: String = buf.content.iter().map(|c: &Cell| c.symbol()).collect();
    assert!(
        text.contains("Device Registry"),
        "rendered buffer should contain 'Device Registry': {text}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Register a new device and verify [BLOCKED] tag in render
// ---------------------------------------------------------------------------

/// Verifies the full device registration flow: navigate to DeviceList,
/// register a device via the text-input chain and DeviceTierPicker, then
/// assert the list reloads with the new blocked-tier entry and that the
/// rendered buffer shows the `[BLOCKED]` tag.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_register_device() {
    let (mut app, _pool, _addr, _rt) = setup_test_app();

    navigate_to_device_list(&mut app);

    // Verify the list starts empty.
    if let Screen::DeviceList { ref devices, .. } = app.screen {
        assert!(
            devices.is_empty(),
            "expected empty device list before registration"
        );
    } else {
        panic!("expected DeviceList screen before registration");
    }

    register_blocked_device(&mut app);

    // Assert: DeviceList reloaded with exactly one device.
    let device = if let Screen::DeviceList { ref devices, .. } = app.screen {
        assert_eq!(
            devices.len(),
            1,
            "expected exactly 1 device after registration, got {devices:?}"
        );
        devices[0].clone()
    } else {
        panic!("expected DeviceList after registration");
    };

    // Assert trust tier is "blocked".
    assert_eq!(
        device["trust_tier"].as_str(),
        Some("blocked"),
        "registered device should have trust_tier 'blocked', got {:?}",
        device["trust_tier"]
    );

    // Render assertion: buffer must show [BLOCKED] tag.
    let buffer = tui::render_to_buffer(&app, 80, 24);
    let buf: &Buffer = buffer.buffer();
    let text: String = buf.content.iter().map(|c: &Cell| c.symbol()).collect();
    assert!(
        text.contains("[BLOCKED]"),
        "rendered buffer should show [BLOCKED] tag for blocked-tier device: {text}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Delete the registered device
// ---------------------------------------------------------------------------

/// Verifies the device deletion flow: from a DeviceList with one registered
/// device, press 'd' to open the confirmation dialog, confirm with Enter, and
/// assert the list reloads empty.
#[test]
#[cfg_attr(not(windows), ignore)]
fn test_delete_device() {
    let (mut app, _pool, _addr, _rt) = setup_test_app();

    navigate_to_device_list(&mut app);
    register_blocked_device(&mut app);

    // Extract the device id before pressing 'd'.
    let device_id = if let Screen::DeviceList { ref devices, .. } = app.screen {
        assert_eq!(devices.len(), 1, "expected 1 device before delete test");
        devices[0]["id"]
            .as_str()
            .expect("device must have an id")
            .to_string()
    } else {
        panic!("expected DeviceList before delete");
    };
    assert!(!device_id.is_empty(), "device id must be non-empty");

    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    // 'd' opens the delete confirmation dialog.
    inject(
        &mut app,
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
    );

    assert!(
        matches!(
            app.screen,
            Screen::Confirm {
                yes_selected: true,
                purpose: ConfirmPurpose::DeleteDevice { .. },
                ..
            }
        ),
        "expected Confirm dialog with yes_selected after pressing 'd'"
    );

    // Verify the confirmation message contains the device id.
    if let Screen::Confirm { ref message, .. } = app.screen {
        assert!(
            message.contains(&device_id),
            "confirmation message should contain device id '{device_id}': {message}"
        );
    }

    // Confirm with Enter (yes_selected defaults to true).
    inject(&mut app, enter);

    // DELETE + reload is synchronous (block_on) — screen transitions immediately.
    assert!(
        matches!(app.screen, Screen::DeviceList { .. }),
        "expected DeviceList after deletion"
    );

    if let Screen::DeviceList { ref devices, .. } = app.screen {
        assert!(
            devices.is_empty(),
            "expected empty device list after deletion, got {devices:?}"
        );
    } else {
        panic!("expected DeviceList screen after delete");
    }
}
