//! System tray icon and context menu (T-46).
//!
//! Shows a tray icon with status, and a context menu:
//! - "Show Portal" -- opens the dlp-admin-cli admin interface URL (Phase 5: dlp-server REST API)
//! - "Agent Status: Running" (disabled, non-interactive label)
//! - Separator
//! - "Exit" -- closes the UI

use anyhow::Result;
use muda::{Menu, MenuItem, PredefinedMenuItem};
use tray_icon::TrayIconBuilder;
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Lazily-constructed null-terminated wide strings for ShellExecuteW.
static PORTAL_URL: std::sync::LazyLock<Vec<u16>> =
    std::sync::LazyLock::new(|| "https://dlp-admin.local\0".encode_utf16().collect());
static OP_OPEN: std::sync::LazyLock<Vec<u16>> =
    std::sync::LazyLock::new(|| "open\0".encode_utf16().collect());

/// Pending status update from the agent (set by Pipe 2, consumed by the
/// main iced tick loop).  `MenuItem` is not `Send` so it cannot be stored
/// in a cross-thread static.  Instead the Pipe 2 handler writes the new
/// status string here, and the iced subscription tick applies it to the
/// menu item on the main thread.
static PENDING_STATUS: parking_lot::Mutex<Option<String>> = parking_lot::Mutex::new(None);

/// Pending tooltip text queued from any thread; applied on the main thread
/// by [`apply_pending_tooltip`].  `TrayIcon` is not `Send`, so we stage the
/// string here and perform the actual `set_tooltip` call from the Tick arm.
static PENDING_TOOLTIP: parking_lot::Mutex<Option<String>> = parking_lot::Mutex::new(None);

// Handle to the "Agent Status" menu item.  Only accessed from the main
// thread (iced event loop).  Stored in a thread_local because MenuItem
// is not Send.
std::thread_local! {
    static STATUS_ITEM: std::cell::RefCell<Option<MenuItem>> = const {
        std::cell::RefCell::new(None)
    };
}

// Handle to the TrayIcon.  Only accessed from the main thread (iced event
// loop).  Stored in a thread_local because TrayIcon is not Send.
// Previously the icon was kept alive via `std::mem::forget`; storing it
// here allows us to call `set_tooltip` on it later.
std::thread_local! {
    static TRAY_ICON: std::cell::RefCell<Option<tray_icon::TrayIcon>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Builds and installs the system tray icon.
///
/// # Errors
///
/// Returns an error if the tray icon or menu cannot be created.
pub fn init() -> Result<()> {
    let show_portal = MenuItem::with_id(
        "show_portal",
        "Show Portal",
        true,
        None::<muda::accelerator::Accelerator>,
    );
    let agent_status = MenuItem::with_id(
        "agent_status",
        "Agent Status: Running",
        false,
        None::<muda::accelerator::Accelerator>,
    );
    let separator = PredefinedMenuItem::separator();
    let exit = MenuItem::with_id("exit", "Exit", true, None::<muda::accelerator::Accelerator>);

    let menu = Menu::with_items(&[&show_portal, &agent_status, &separator, &exit])
        .map_err(|e| anyhow::anyhow!("failed to create tray menu: {e}"))?;

    // Store the status item handle in the thread-local (main thread only).
    STATUS_ITEM.with(|cell| {
        *cell.borrow_mut() = Some(agent_status);
    });

    let icon = load_default_icon();

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("DLP Agent UI")
        .with_icon(icon)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build tray icon: {e}"))?;

    // Store the TrayIcon in thread-local so we can update the tooltip later.
    // Previously this was std::mem::forget(tray), which kept it alive but
    // prevented any subsequent calls (e.g. set_tooltip).  Thread-local storage
    // achieves the same lifetime guarantee while allowing mutation.
    TRAY_ICON.with(|cell| {
        *cell.borrow_mut() = Some(tray);
    });

    Ok(())
}

/// Queues a tray status update from any thread.
///
/// Called by the Pipe 2 listener when a `StatusUpdate` message arrives
/// from the agent.  The actual menu item update is applied on the main
/// thread by [`apply_pending_status`] (called from the iced tick loop).
pub fn update_status(status: &str) {
    *PENDING_STATUS.lock() = Some(status.to_string());
    tracing::debug!(status, "tray status update queued");
}

/// Applies any pending status update to the tray menu item.
///
/// Must be called from the main (iced) thread because `MenuItem` is not
/// `Send`.  Called from the iced subscription tick (every 100 ms).
pub fn apply_pending_status() {
    let pending = PENDING_STATUS.lock().take();
    if let Some(status) = pending {
        STATUS_ITEM.with(|cell| {
            if let Some(item) = cell.borrow().as_ref() {
                let label = format!("Agent Status: {status}");
                item.set_text(label);
                tracing::info!(status, "tray status applied");
            }
        });
    }
}

/// Queues a tooltip string for application on the next Tick.
///
/// Thread-safe: can be called from any thread.  The actual `set_tooltip`
/// call happens on the main thread via [`apply_pending_tooltip`].
///
/// # Arguments
///
/// * `text` - The new tooltip string to display on the tray icon.
pub fn update_tooltip(text: &str) {
    *PENDING_TOOLTIP.lock() = Some(text.to_owned());
}

/// Applies any queued tooltip update to the tray icon.
///
/// Must be called from the main (iced) thread because `TrayIcon` is not
/// `Send`.  Called from the Tick arm in `app.rs` every 100 ms.
/// If no tooltip update is pending, this is a no-op.
pub fn apply_pending_tooltip() {
    // `take()` atomically clears the pending value and returns it.
    // The lock is held only for this take(), not across the set_tooltip call,
    // preventing lock-contention stalls (T-Q08-03 mitigation).
    let pending = PENDING_TOOLTIP.lock().take();
    if let Some(text) = pending {
        TRAY_ICON.with(|cell| {
            if let Some(icon) = cell.borrow().as_ref() {
                // set_tooltip accepts Option<&str>; None clears the tooltip.
                let _ = icon.set_tooltip(Some(text.as_str()));
            }
        });
    }
}

/// Opens the DLP admin interface URL in the default browser.
///
/// The admin interface is `dlp-admin-cli` (CLI only). In Phase 5, this URL
/// will point to the dlp-server REST API endpoint for administrative operations.
pub fn open_portal() {
    tracing::info!("Show Portal clicked -- dlp-admin-cli is the admin interface (no web portal)");
    unsafe {
        let _ = ShellExecuteW(
            None,
            PCWSTR::from_raw(OP_OPEN.as_ptr()),
            PCWSTR::from_raw(PORTAL_URL.as_ptr()),
            None,
            None,
            SW_SHOWNORMAL,
        );
    }
}

/// Creates a default 16x16 RGBA icon (DLP brand blue).
fn load_default_icon() -> tray_icon::Icon {
    let mut rgba = Vec::with_capacity(16 * 16 * 4);
    for _ in 0..(16 * 16) {
        // DLP brand blue: RGBA = (0x00, 0x66, 0xCC, 0xFF)
        rgba.extend_from_slice(&[0x00, 0x66, 0xCC, 0xFF]);
    }
    tray_icon::Icon::from_rgba(rgba, 16, 16).expect("failed to create tray icon from RGBA data")
}
