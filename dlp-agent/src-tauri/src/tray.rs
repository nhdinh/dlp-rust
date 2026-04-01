//! System tray icon and context menu (T-46).
//!
//! Shows a tray icon with status, and a context menu:
//! - "Show Portal" → opens the DLP admin portal URL
//! - "Agent Status: Running" (disabled, non-interactive label)
//! - Separator
//! - "Exit" → closes the UI

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, Runtime,
};
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Lazily-constructed null-terminated wide strings for ShellExecuteW.
static PORTAL_URL: std::sync::LazyLock<Vec<u16>> =
    std::sync::LazyLock::new(|| "https://dlp-admin.local\0".encode_utf16().collect());
static OP_OPEN: std::sync::LazyLock<Vec<u16>> =
    std::sync::LazyLock::new(|| "open\0".encode_utf16().collect());

/// Builds and installs the system tray icon.
pub fn init<R: Runtime>(app: &tauri::App<R>) -> tauri::Result<()> {
    let show_portal = MenuItem::with_id(app, "show_portal", "Show Portal", true, None::<&str>)?;
    // Disabled item used as a static status label (non-interactive).
    let agent_status = MenuItem::with_id(
        app,
        "agent_status",
        "Agent Status: Running",
        false,
        None::<&str>,
    )?;
    let separator = PredefinedMenuItem::separator(app)?;
    let exit = MenuItem::with_id(app, "exit", "Exit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show_portal, &agent_status, &separator, &exit])?;

    let _tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().cloned().expect("no default icon"))
        .menu(&menu)
        .tooltip("DLP Agent UI")
        .on_menu_event(move |app, event| {
            let id = event.id.as_ref();
            match id {
                "show_portal" => {
                    // TODO (Phase 5): open DLP admin portal URL.
                    tracing::info!("Show Portal clicked — Phase 5 target");
                    let _ = unsafe {
                        ShellExecuteW(
                            None,
                            PCWSTR::from_raw(OP_OPEN.as_ptr()),
                            PCWSTR::from_raw(PORTAL_URL.as_ptr()),
                            None,
                            None,
                            SW_SHOWNORMAL,
                        )
                    };
                }
                "exit" => {
                    tracing::info!("Exit clicked — closing UI");
                    app.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                // Left-click: show/focus the main window.
                if let Some(window) = tray.app_handle().get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}
