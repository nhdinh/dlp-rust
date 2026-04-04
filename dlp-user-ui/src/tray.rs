//! System tray icon and context menu (T-46).
//!
//! Shows a tray icon with status, and a context menu:
//! - "Show Portal" -- opens the DLP admin portal URL
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
    std::sync::LazyLock::new(|| {
        "https://dlp-admin.local\0".encode_utf16().collect()
    });
static OP_OPEN: std::sync::LazyLock<Vec<u16>> =
    std::sync::LazyLock::new(|| "open\0".encode_utf16().collect());

/// Pending status update from the agent (set by Pipe 2, consumed by the
/// main iced tick loop).  `MenuItem` is not `Send` so it cannot be stored
/// in a cross-thread static.  Instead the Pipe 2 handler writes the new
/// status string here, and the iced subscription tick applies it to the
/// menu item on the main thread.
static PENDING_STATUS: parking_lot::Mutex<Option<String>> = parking_lot::Mutex::new(None);

// Handle to the "Agent Status" menu item.  Only accessed from the main
// thread (iced event loop).  Stored in a thread_local because MenuItem
// is not Send.
std::thread_local! {
    static STATUS_ITEM: std::cell::RefCell<Option<MenuItem>> = const {
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
    let exit = MenuItem::with_id(
        "exit",
        "Exit",
        true,
        None::<muda::accelerator::Accelerator>,
    );

    let menu = Menu::with_items(&[
        &show_portal,
        &agent_status,
        &separator,
        &exit,
    ])
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
        .map_err(|e| {
            anyhow::anyhow!("failed to build tray icon: {e}")
        })?;

    // Leak the tray icon so it lives for the process lifetime.
    // tray-icon drops the icon (and removes it from the taskbar)
    // when the TrayIcon value is dropped.
    std::mem::forget(tray);

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

/// Opens the DLP admin portal URL in the default browser.
pub fn open_portal() {
    tracing::info!("Show Portal clicked -- Phase 5 target");
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
    tray_icon::Icon::from_rgba(rgba, 16, 16)
        .expect("failed to create tray icon from RGBA data")
}
