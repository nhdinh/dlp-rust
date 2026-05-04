//! Device-watcher module: hidden Win32 message-only window + WM_DEVICECHANGE
//! dispatcher (Phase 36, DISK-05).
//!
//! Owns the message-only window and the three `RegisterDeviceNotificationW`
//! registrations:
//!
//! 1. `GUID_DEVINTERFACE_VOLUME` -- drive-letter tracking (USB volume arrivals);
//!    dispatched to [`crate::detection::usb::handle_volume_event_dispatch`].
//! 2. `GUID_DEVINTERFACE_USB_DEVICE` -- USB VID/PID/serial capture;
//!    dispatched to [`crate::detection::usb::dispatch_usb_device_arrival`] and
//!    [`crate::detection::usb::dispatch_usb_device_removal`].
//! 3. `GUID_DEVINTERFACE_DISK` -- fixed-disk arrival/removal for allowlist
//!    enforcement (Phase 36); dispatched to
//!    [`crate::detection::disk::on_disk_arrival`] and
//!    [`crate::detection::disk::on_disk_removal`].
//!
//! ## Thread-affinity invariant
//!
//! Per the Win32 contract, `GetMessageW` only dequeues messages for the
//! calling thread. The window MUST be created and the message loop MUST run
//! on the same `std::thread`. The HWND is transmitted to the caller as a
//! `usize` (HWND is `!Send`) and reconstructed from the raw pointer.
//!
//! ## Async-from-callback pattern
//!
//! `device_watcher_wndproc` runs on a plain `std::thread` that does NOT
//! inherit the tokio context. The existing `usb.rs` static globals
//! (`REGISTRY_RUNTIME_HANDLE`, `REGISTRY_CACHE`, `REGISTRY_CLIENT`) provide
//! the bridge for the USB-arrival registry refresh. The disk handler emits
//! audit events synchronously via `emit_audit` (file append is fast and
//! synchronous), reading [`AUDIT_CTX`] for the [`EmitContext`].

use std::sync::OnceLock;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

#[cfg(windows)]
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostMessageW,
    PostQuitMessage, RegisterClassW, RegisterDeviceNotificationW, TranslateMessage,
    UnregisterDeviceNotification, DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE,
    DBT_DEVTYP_DEVICEINTERFACE, DEVICE_NOTIFY_WINDOW_HANDLE, DEV_BROADCAST_DEVICEINTERFACE_W,
    DEV_BROADCAST_HDR, HDEVNOTIFY, MSG, WINDOW_STYLE, WM_CLOSE, WM_DESTROY, WM_DEVICECHANGE,
    WNDCLASSW, WS_EX_NOACTIVATE,
};

use crate::audit_emitter::EmitContext;

// ---------------------------------------------------------------------------
// Device-interface GUIDs (defined here; usb.rs copies are deleted in Task 3)
// ---------------------------------------------------------------------------

/// `GUID_DEVINTERFACE_VOLUME` -- volume arrivals/removals.
/// Windows SDK: {53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}
#[cfg(windows)]
const GUID_DEVINTERFACE_VOLUME: windows::core::GUID = windows::core::GUID::from_values(
    0x53f5_630d,
    0xb6bf,
    0x11d0,
    [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
);

/// `GUID_DEVINTERFACE_USB_DEVICE` -- USB device arrivals/removals.
/// Windows SDK: {A5DCBF10-6530-11D2-901F-00C04FB951ED}
#[cfg(windows)]
const GUID_DEVINTERFACE_USB_DEVICE: windows::core::GUID = windows::core::GUID::from_values(
    0xa5dc_bf10,
    0x6530,
    0x11d2,
    [0x90, 0x1f, 0x00, 0xc0, 0x4f, 0xb9, 0x51, 0xed],
);

/// `GUID_DEVINTERFACE_DISK` -- fixed-disk arrivals/removals (Phase 36 use).
/// Windows SDK: {53F56307-B6BF-11D0-94F2-00A0C91EFB8B}
#[cfg(windows)]
const GUID_DEVINTERFACE_DISK: windows::core::GUID = windows::core::GUID::from_values(
    0x53f5_6307,
    0xb6bf,
    0x11d0,
    [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
);

// ---------------------------------------------------------------------------
// Static globals (mirror usb.rs lifecycle conventions)
// ---------------------------------------------------------------------------

/// Registered device notification handles for cleanup.
/// Tuple ordering: (volume, usb_device, disk).
/// Stored as raw isize values because HDEVNOTIFY is not Send/Sync.
static NOTIFY_HANDLES: Mutex<Option<(isize, isize, isize)>> = Mutex::new(None);

/// Audit context for the disk-arrival handler. Set once during
/// [`spawn_device_watcher_task`]; never updated afterwards (OnceLock contract).
static AUDIT_CTX: OnceLock<EmitContext> = OnceLock::new();

/// Returns the stored [`EmitContext`], or `None` if [`spawn_device_watcher_task`]
/// has not yet been called.
///
/// Reserved for disk-arrival handlers (Phase 36 Task 2+).
#[allow(dead_code)]
pub(crate) fn get_audit_ctx() -> Option<&'static EmitContext> {
    AUDIT_CTX.get()
}

// ---------------------------------------------------------------------------
// Helpers (moved from usb.rs; usb.rs copies deleted in Task 3)
// ---------------------------------------------------------------------------

/// Reads the null-terminated wide-string `dbcc_name` from a
/// `DEV_BROADCAST_DEVICEINTERFACE_W`. The struct is variable-length;
/// `dbcc_name` is the first `u16` of a trailing UTF-16 sequence that extends
/// past the declared `[u16; 1]` field.
///
/// # Safety
///
/// The caller must guarantee that `di` points to a live
/// `DEV_BROADCAST_DEVICEINTERFACE_W` whose storage extends at least to the
/// null terminator of `dbcc_name`. The OS guarantees this for the duration
/// of the `WM_DEVICECHANGE` callback.
#[cfg(windows)]
unsafe fn read_dbcc_name(di: &DEV_BROADCAST_DEVICEINTERFACE_W) -> String {
    let base = di.dbcc_name.as_ptr();
    let mut len = 0usize;
    // SAFETY: walk forward until we hit the null terminator. Bounded by
    // Windows device-path max length (MAX_PATH + driver prefix = 32,768 u16).
    while unsafe { *base.add(len) } != 0 && len < 32_768 {
        len += 1;
    }
    // SAFETY: base..base+len is valid UTF-16 data owned by the OS for this callback.
    let slice = unsafe { std::slice::from_raw_parts(base, len) };
    String::from_utf16_lossy(slice)
}

/// Extracts the device instance ID from a `GUID_DEVINTERFACE_DISK` `dbcc_name`.
///
/// Input:  `\\?\USBSTOR#Disk&Ven_Kingston#...#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`
/// Output: `USBSTOR\Disk&Ven_Kingston\...`
///
/// # Arguments
///
/// * `device_path` - The `dbcc_name` string from a `WM_DEVICECHANGE` callback.
///
/// # Returns
///
/// The SetupDi-compatible instance ID with `\` separators.
///
/// Public so [`crate::detection::disk::on_disk_removal`] can match the
/// arrival's instance ID against `drive_letter_map` entries.
///
/// # Examples
///
/// ```
/// use dlp_agent::detection::device_watcher::extract_disk_instance_id;
/// let input = r"\\?\USBSTOR#Disk#1234#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
/// let id = extract_disk_instance_id(input);
/// assert_eq!(id, r"USBSTOR\Disk\1234");
/// ```
pub fn extract_disk_instance_id(device_path: &str) -> String {
    let without_prefix = device_path.strip_prefix(r"\\?\").unwrap_or(device_path);
    let without_guid = without_prefix.split("#{").next().unwrap_or(without_prefix);
    without_guid.replace('#', r"\")
}

// ---------------------------------------------------------------------------
// Window procedure (dispatcher)
// ---------------------------------------------------------------------------

/// Window procedure for the device-watcher hidden window.
///
/// Handles `WM_DESTROY` (quit message loop) and `WM_DEVICECHANGE`
/// (route arrival/removal events by `dbcc_classguid` to the appropriate
/// per-protocol handler).  All other messages are forwarded to `DefWindowProcW`.
#[cfg(windows)]
unsafe extern "system" fn device_watcher_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_DESTROY => {
            // SAFETY: PostQuitMessage is always safe to call inside a wndproc.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        WM_DEVICECHANGE => {
            // wparam holds the event code: DBT_DEVICEARRIVAL = 0x8000,
            // DBT_DEVICEREMOVECOMPLETE = 0x8004. lparam is a pointer to
            // DEV_BROADCAST_HDR valid only for the duration of this call.
            let event_type = wparam.0 as u32;
            if (event_type == DBT_DEVICEARRIVAL || event_type == DBT_DEVICEREMOVECOMPLETE)
                && lparam.0 != 0
            {
                // SAFETY: lparam points to a DEV_BROADCAST_HDR produced by
                // the OS; valid for the duration of this callback.
                let hdr = unsafe { &*(lparam.0 as *const DEV_BROADCAST_HDR) };
                if hdr.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE {
                    // SAFETY: the header's devicetype confirms the body is
                    // DEV_BROADCAST_DEVICEINTERFACE_W. Extract dbcc_classguid
                    // and dbcc_name (null-terminated wide string) here --
                    // do NOT store the pointer past this callback.
                    let di =
                        unsafe { &*(lparam.0 as *const DEV_BROADCAST_DEVICEINTERFACE_W) };
                    let classguid = di.dbcc_classguid;

                    if classguid == GUID_DEVINTERFACE_VOLUME {
                        // VOLUME arrival/removal: re-scan drive letters and
                        // reconcile with the blocked-drives set.
                        crate::detection::usb::handle_volume_event_dispatch(event_type);
                    } else if classguid == GUID_DEVINTERFACE_USB_DEVICE {
                        // SAFETY: di is valid for this callback duration;
                        // read_dbcc_name extracts the wide string synchronously.
                        let device_path = unsafe { read_dbcc_name(di) };
                        if event_type == DBT_DEVICEARRIVAL {
                            crate::detection::usb::dispatch_usb_device_arrival(&device_path);
                        } else {
                            crate::detection::usb::dispatch_usb_device_removal(&device_path);
                        }
                    } else if classguid == GUID_DEVINTERFACE_DISK {
                        // SAFETY: di is valid for this callback duration;
                        // read_dbcc_name extracts the wide string synchronously.
                        let device_path = unsafe { read_dbcc_name(di) };
                        if event_type == DBT_DEVICEARRIVAL {
                            if let Some(ctx) = AUDIT_CTX.get() {
                                crate::detection::disk::on_disk_arrival(&device_path, ctx);
                            } else {
                                warn!(
                                    "device_watcher: AUDIT_CTX not set; \
                                     skipping disk arrival audit emission"
                                );
                            }
                        } else {
                            crate::detection::disk::on_disk_removal(&device_path);
                        }
                    }
                }
            }
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

// ---------------------------------------------------------------------------
// Spawn / unregister
// ---------------------------------------------------------------------------

/// Registers for VOLUME, USB_DEVICE, and DISK device-interface notifications
/// and starts a message loop on a dedicated thread.
///
/// Replaces the legacy `register_usb_notifications` function (Phase 36, D-12).
///
/// Creates a hidden message-only window and calls `RegisterDeviceNotificationW`
/// three times on the same `hwnd`:
/// 1. `GUID_DEVINTERFACE_VOLUME` -- drive-letter tracking.
/// 2. `GUID_DEVINTERFACE_USB_DEVICE` -- USB VID/PID/serial capture.
/// 3. `GUID_DEVINTERFACE_DISK` -- fixed-disk allowlist enforcement (Phase 36).
///
/// # Arguments
///
/// * `audit_ctx` -- the [`EmitContext`] for the disk-arrival handler's
///   `DiskDiscovery` audit emission. Stored in the [`AUDIT_CTX`] OnceLock.
///
/// # Returns
///
/// * `Ok((HWND, JoinHandle))` -- the notification window handle and the
///   thread handle. Pass both to [`unregister_device_watcher`] on shutdown.
/// * `Err` if window registration or device notification fails.
#[cfg(windows)]
pub fn spawn_device_watcher_task(
    audit_ctx: EmitContext,
) -> windows::core::Result<(HWND, std::thread::JoinHandle<()>)> {
    // Store the audit context for the disk-arrival handler.
    // Subsequent calls are silently ignored (OnceLock contract).
    let _ = AUDIT_CTX.set(audit_ctx);

    // Windows message delivery is thread-affine: WM_DEVICECHANGE is posted to
    // the queue of the thread that called CreateWindowExW. GetMessageW only
    // dequeues messages for the calling thread's own queue. Therefore the window
    // must be created, notifications registered, and the message loop run on the
    // same thread. We spawn that thread first and receive the HWND back via a
    // channel so the caller can pass it to unregister_device_watcher later.
    //
    // HWND is !Send (raw pointer wrapper), so we transmit it as usize and
    // reconstruct it on the caller side.
    let (hwnd_tx, hwnd_rx) =
        std::sync::mpsc::channel::<windows::core::Result<usize>>();

    let thread = std::thread::Builder::new()
        .name("device-watcher".into())
        .spawn(move || {
            // Step 1: register window class on this thread.
            let class_name: Vec<u16> = "DlpDeviceWatcherWindow\0".encode_utf16().collect();
            let wc = WNDCLASSW {
                lpfnWndProc: Some(device_watcher_wndproc),
                lpszClassName: windows::core::PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };

            // SAFETY: class_name is a null-terminated wide string kept alive past
            // RegisterClassW (only the atom is needed by CreateWindowExW below).
            let atom = unsafe { RegisterClassW(&wc) };
            if atom == 0 {
                let _ = hwnd_tx.send(Err(windows::core::Error::from_thread()));
                return;
            }

            // Step 2: create the message-only window on this thread.
            // SAFETY: atom is a valid class atom returned by RegisterClassW.
            let hwnd = match unsafe {
                CreateWindowExW(
                    WS_EX_NOACTIVATE,
                    windows::core::PCWSTR::from_raw(atom as *const u16),
                    windows::core::PCWSTR::null(),
                    WINDOW_STYLE(0),
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    None,
                    None,
                )
            } {
                Ok(h) => h,
                Err(e) => {
                    let _ = hwnd_tx.send(Err(e));
                    return;
                }
            };

            let db_size = std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>();

            // Step 3a: register for VOLUME device notifications (drive-letter tracking).
            let mut vol_buf: Vec<u8> = vec![0u8; db_size];
            let dbc_vol = vol_buf.as_mut_ptr() as *mut DEV_BROADCAST_DEVICEINTERFACE_W;
            // SAFETY: dbc_vol points to db_size bytes that we own and are properly aligned.
            unsafe {
                (*dbc_vol).dbcc_size = db_size as u32;
                (*dbc_vol).dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE.0;
                (*dbc_vol).dbcc_reserved = 0;
                (*dbc_vol).dbcc_classguid = GUID_DEVINTERFACE_VOLUME;
            }
            // SAFETY: hwnd is valid on this thread; dbc_vol points to an initialized struct.
            let vol_handle = unsafe {
                RegisterDeviceNotificationW(
                    hwnd.into(),
                    dbc_vol as *const _,
                    DEVICE_NOTIFY_WINDOW_HANDLE,
                )
            };
            if let Err(e) = vol_handle {
                // SAFETY: hwnd is valid; we are abandoning the window on error.
                let _ = unsafe { DestroyWindow(hwnd) };
                let _ = hwnd_tx.send(Err(e));
                return;
            }

            // Step 3b: register for USB_DEVICE notifications (VID/PID/serial capture).
            let mut usb_buf: Vec<u8> = vec![0u8; db_size];
            let dbc_usb = usb_buf.as_mut_ptr() as *mut DEV_BROADCAST_DEVICEINTERFACE_W;
            // SAFETY: dbc_usb points to db_size bytes that we own and are properly aligned.
            unsafe {
                (*dbc_usb).dbcc_size = db_size as u32;
                (*dbc_usb).dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE.0;
                (*dbc_usb).dbcc_reserved = 0;
                (*dbc_usb).dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE;
            }
            // SAFETY: hwnd is valid; dbc_usb points to an initialized struct.
            let usb_handle = unsafe {
                RegisterDeviceNotificationW(
                    hwnd.into(),
                    dbc_usb as *const _,
                    DEVICE_NOTIFY_WINDOW_HANDLE,
                )
            };
            if let Err(e) = usb_handle {
                // SAFETY: hwnd is valid; we are abandoning the window on error.
                let _ = unsafe { DestroyWindow(hwnd) };
                let _ = hwnd_tx.send(Err(e));
                return;
            }

            // Step 3c: register for DISK device notifications (Phase 36 allowlist).
            let mut disk_buf: Vec<u8> = vec![0u8; db_size];
            let dbc_disk = disk_buf.as_mut_ptr() as *mut DEV_BROADCAST_DEVICEINTERFACE_W;
            // SAFETY: dbc_disk points to db_size bytes that we own and are properly aligned.
            unsafe {
                (*dbc_disk).dbcc_size = db_size as u32;
                (*dbc_disk).dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE.0;
                (*dbc_disk).dbcc_reserved = 0;
                (*dbc_disk).dbcc_classguid = GUID_DEVINTERFACE_DISK;
            }
            // SAFETY: hwnd is valid; dbc_disk points to an initialized struct.
            let disk_handle = unsafe {
                RegisterDeviceNotificationW(
                    hwnd.into(),
                    dbc_disk as *const _,
                    DEVICE_NOTIFY_WINDOW_HANDLE,
                )
            };
            if let Err(e) = disk_handle {
                // SAFETY: hwnd is valid; we are abandoning the window on error.
                let _ = unsafe { DestroyWindow(hwnd) };
                let _ = hwnd_tx.send(Err(e));
                return;
            }

            // Store notification handles for later cleanup.
            let vol_h = vol_handle.unwrap();
            let usb_h = usb_handle.unwrap();
            let disk_h = disk_handle.unwrap();
            *NOTIFY_HANDLES.lock() =
                Some((vol_h.0 as isize, usb_h.0 as isize, disk_h.0 as isize));

            // Signal the caller with the HWND value. Transmit as usize because
            // HWND is !Send; the caller reconstructs it from the raw pointer value.
            // SAFETY: hwnd.0 is a valid non-null HWND pointer on this process.
            let _ = hwnd_tx.send(Ok(hwnd.0 as usize));

            // Step 4: run the message loop on this same thread. WM_DEVICECHANGE
            // events arrive here because the window was created on this thread.
            let mut msg = MSG::default();
            loop {
                // SAFETY: msg is a valid pointer to an MSG struct.
                let ret = unsafe { GetMessageW(&mut msg, None, 0, 0) };
                if ret.0 == 0 {
                    break; // WM_QUIT received via PostQuitMessage in WM_DESTROY handler
                }
                let _ = unsafe { TranslateMessage(&msg) };
                let _ = unsafe { DispatchMessageW(&msg) };
            }
            debug!("device-watcher thread exiting");
        })
        .expect("device-watcher thread must spawn");

    // Block until the spawned thread signals window creation success or failure.
    let hwnd_raw = hwnd_rx
        .recv()
        .expect("device-watcher thread must send HWND result")?;

    // SAFETY: hwnd_raw is a valid HWND pointer value sent from the spawned thread
    // immediately after a successful CreateWindowExW call.
    let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);

    info!("device watcher registered (volume + usb_device + disk interfaces)");
    Ok((hwnd, thread))
}

/// Stops the device-watcher window and cleans up resources.
///
/// Unregisters device notifications, posts `WM_CLOSE` to break the message loop,
/// waits for the thread to exit, and destroys the window.
///
/// Replaces the legacy `unregister_usb_notifications` function (Phase 36, D-12).
///
/// # Arguments
///
/// * `hwnd` -- the window handle returned by [`spawn_device_watcher_task`].
/// * `thread` -- the thread handle returned by [`spawn_device_watcher_task`].
#[cfg(windows)]
pub fn unregister_device_watcher(hwnd: HWND, thread: std::thread::JoinHandle<()>) {
    // Unregister device notifications before destroying the window.
    if let Some((h_vol, h_usb, h_disk)) = NOTIFY_HANDLES.lock().take() {
        // SAFETY: handles were obtained from RegisterDeviceNotificationW above.
        unsafe {
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_vol as *mut _));
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_usb as *mut _));
            let _ = UnregisterDeviceNotification(HDEVNOTIFY(h_disk as *mut _));
        }
    }

    // Post WM_CLOSE to the hidden window to break the message loop.
    // SAFETY: hwnd is the window we created; WPARAM/LPARAM are unused for WM_CLOSE.
    unsafe {
        let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
    }

    // Wait for the thread to exit.
    if let Err(e) = thread.join() {
        warn!("device-watcher thread panicked: {:?}", e);
    }

    // Destroy the window.
    // SAFETY: the message loop has exited (WM_DESTROY was processed);
    // the window is no longer processing messages.
    unsafe {
        let _ = DestroyWindow(hwnd);
    }

    info!("device watcher unregistered");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strips the `\\?\` prefix and the `#{GUID}` suffix and replaces `#` with `\`.
    #[test]
    fn test_extract_disk_instance_id_strips_prefix_and_guid() {
        let input =
            r"\\?\USBSTOR#Disk&Ven_Kingston#1234#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        assert_eq!(
            extract_disk_instance_id(input),
            r"USBSTOR\Disk&Ven_Kingston\1234"
        );
    }

    /// Works without the `\\?\` prefix (defensive case).
    #[test]
    fn test_extract_disk_instance_id_no_prefix() {
        let input = r"USBSTOR#Disk&Ven_Acme#001#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
        assert_eq!(
            extract_disk_instance_id(input),
            r"USBSTOR\Disk&Ven_Acme\001"
        );
    }

    /// Works without the trailing GUID suffix (defensive case).
    #[test]
    fn test_extract_disk_instance_id_no_guid_suffix() {
        let input = r"\\?\USBSTOR#Disk&Ven_Kingston#1234";
        assert_eq!(
            extract_disk_instance_id(input),
            r"USBSTOR\Disk&Ven_Kingston\1234"
        );
    }
}
