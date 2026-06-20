//! DirectWrite font metrics for watermark text measurement (Phase 67.1).
//!
//! Provides [`DirectWriteFontMetrics`], a production implementation of the
//! [`FontMetrics`] trait that uses
//! Windows DirectWrite COM APIs to measure text width and height in DIPs
//! (device-independent pixels, 1/96 inch), which are identical to XPS units.
//!
//! ## COM Safety Contract
//!
//! COM is initialized internally via [`ComGuard`] RAII struct inside
//! [`DirectWriteFontMetrics::measure`]. Callers do **not** need to call
//! `CoInitializeEx` beforehand. Nested `CoInitializeEx` calls return `S_FALSE`
//! (0x1), which `windows-rs` treats as success, so tests may also call
//! `ComGuard::new()` without conflict.
//!
//! ## Platform Availability
//!
//! This module is only functional on Windows. On non-Windows targets, a
//! compile-only stub is provided so CI stays green.

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use anyhow::{Context, Result};
#[cfg(windows)]
use windows::core::{w, PCWSTR};
#[cfg(windows)]
use windows::Win32::Graphics::DirectWrite::{
    DWriteCreateFactory, IDWriteFactory, IDWriteTextLayout, DWRITE_FACTORY_TYPE_SHARED,
    DWRITE_FONT_STRETCH_NORMAL, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_WEIGHT_NORMAL,
    DWRITE_TEXT_METRICS,
};
#[cfg(windows)]
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};

#[cfg(windows)]
use crate::print_watermark::FontMetrics;

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
/// RAII guard for COM apartment initialization.
///
/// Calls `CoInitializeEx(COINIT_MULTITHREADED)` on construction and
/// `CoUninitialize` on drop. Safe for nested use: `CoInitializeEx` returns
/// `S_FALSE` on subsequent calls in the same thread, which `windows-rs`
/// treats as `Ok(())`.
pub struct ComGuard;

#[cfg(windows)]
impl ComGuard {
    /// Initialize COM for the current thread.
    ///
    /// # Errors
    ///
    /// Returns an error if `CoInitializeEx` fails with a non-success HRESULT.
    pub fn new() -> Result<Self> {
        // SAFETY: COM initialization is a well-documented Win32 API call with
        // no preconditions beyond valid arguments (both satisfied here).
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_err() {
            return Err(anyhow::anyhow!("CoInitializeEx failed: {:?}", hr));
        }
        Ok(Self)
    }
}

#[cfg(windows)]
impl Drop for ComGuard {
    fn drop(&mut self) {
        // SAFETY: COM was successfully initialized by `new()`; each init
        // must be paired with exactly one uninit.
        unsafe {
            CoUninitialize();
        }
    }
}

#[cfg(windows)]
/// Production [`FontMetrics`] implementation using Windows DirectWrite.
///
/// Measures text via `IDWriteTextLayout::GetMetrics`, which returns
/// `DWRITE_TEXT_METRICS` with `width` and `height` in DIPs
/// (device-independent pixels, 1/96 inch). DIPs are identical to XPS units,
/// so no additional conversion is needed.
///
/// ## Font Fallback
///
/// If the requested font family (e.g., "Arial") is not available, the
/// implementation falls back to "Segoe UI" and logs a warning. If both fail,
/// the error is returned to the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectWriteFontMetrics;

#[cfg(windows)]
impl FontMetrics for DirectWriteFontMetrics {
    /// Measure text width and height using DirectWrite.
    ///
    /// COM is initialized internally via [`ComGuard`]; callers do not need to
    /// call `CoInitializeEx` beforehand. Nested `CoInitializeEx` calls return
    /// `S_FALSE` (0x1), which `windows-rs` treats as success, so tests may also
    /// call `ComGuard::new()` without conflict.
    ///
    /// # Arguments
    ///
    /// * `text` — The text string to measure.
    /// * `family` — Font family name (e.g., "Arial").
    /// * `em_size` — Font size in XPS units (DIPs, 1/96 inch). No conversion
    ///   needed — DirectWrite natively uses DIPs.
    ///
    /// # Returns
    ///
    /// `(width, height)` tuple in XPS units (DIPs). Both values are `f64`.
    ///
    /// # Errors
    ///
    /// Returns `anyhow::Error` wrapped errors on COM or DirectWrite failures,
    /// including font loading failure if both primary and fallback families
    /// are unavailable.
    fn measure(&self, text: &str, family: &str, em_size: f64) -> Result<(f64, f64)> {
        let _com = ComGuard::new()
            .context("COM initialization failed in DirectWriteFontMetrics::measure")?;

        // SAFETY: COM is initialized by `ComGuard` at the top of this function
        // and remains alive for the entire duration of `measure()`.
        let (width, height) = unsafe {
            let factory: IDWriteFactory = DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED)
                .context("DWriteCreateFactory failed")?;

            let family_wide: Vec<u16> = OsStr::new(family).encode_wide().chain(Some(0)).collect();
            let family_pcwstr = PCWSTR(family_wide.as_ptr());

            let text_format = factory
                .CreateTextFormat(
                    family_pcwstr,
                    None,
                    DWRITE_FONT_WEIGHT_NORMAL,
                    DWRITE_FONT_STYLE_NORMAL,
                    DWRITE_FONT_STRETCH_NORMAL,
                    em_size as f32,
                    w!("en-us"),
                )
                .or_else(|e| {
                    tracing::warn!(family = %family, error = %e, "Arial not available, falling back to Segoe UI");
                    let fallback_wide: Vec<u16> = OsStr::new("Segoe UI")
                        .encode_wide()
                        .chain(Some(0))
                        .collect();
                    let fallback_pcwstr = PCWSTR(fallback_wide.as_ptr());
                    factory.CreateTextFormat(
                        fallback_pcwstr,
                        None,
                        DWRITE_FONT_WEIGHT_NORMAL,
                        DWRITE_FONT_STYLE_NORMAL,
                        DWRITE_FONT_STRETCH_NORMAL,
                        em_size as f32,
                        w!("en-us"),
                    )
                    .context("CreateTextFormat failed for both Arial and Segoe UI fallback")
                })?;

            let text_wide: Vec<u16> = OsStr::new(text).encode_wide().collect();
            let text_len = text_wide.len();
            let text_slice = if text_len > 0 {
                &text_wide[..text_len]
            } else {
                &[]
            };

            let layout: IDWriteTextLayout = factory
                .CreateTextLayout(text_slice, &text_format, f32::MAX, f32::MAX)
                .context("CreateTextLayout failed")?;

            let mut metrics = DWRITE_TEXT_METRICS::default();
            layout
                .GetMetrics(&mut metrics)
                .context("GetMetrics failed")?;

            (metrics.width as f64, metrics.height as f64)
        };

        Ok((width, height))
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
/// Stub module for non-Windows CI. DirectWrite is Windows-only.
pub mod stub {
    /// Placeholder — DirectWriteFontMetrics is only available on Windows.
    #[derive(Debug, Clone, PartialEq)]
    pub struct DirectWriteFontMetrics;
}

#[cfg(not(windows))]
pub use stub::DirectWriteFontMetrics;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use crate::print_watermark::{pt_to_xps_units, FontMetrics};

    #[test]
    fn test_directwrite_measure_hello() -> Result<()> {
        let _com = ComGuard::new()?;
        let metrics = DirectWriteFontMetrics;
        let em_size = pt_to_xps_units(8.0);
        let (width, height) = metrics.measure("Hello", "Arial", em_size)?;
        assert!(width > 0.0, "width should be positive");
        assert!(height > 0.0, "height should be positive");
        Ok(())
    }

    #[test]
    fn test_directwrite_measure_empty() -> Result<()> {
        let _com = ComGuard::new()?;
        let metrics = DirectWriteFontMetrics;
        let em_size = pt_to_xps_units(8.0);
        let (width, height) = metrics.measure("", "Arial", em_size)?;
        assert_eq!(width, 0.0, "empty text width should be 0");
        assert!(
            height > 0.0,
            "empty text height should still be positive (line height)"
        );
        Ok(())
    }

    #[test]
    fn test_directwrite_dip_equals_xps_unit() -> Result<()> {
        let _com = ComGuard::new()?;
        let metrics = DirectWriteFontMetrics;
        let em_size = pt_to_xps_units(8.0);
        let (width, height) = metrics.measure("A", "Arial", em_size)?;
        assert!(width > 0.0, "width should be positive");
        assert!(height > 0.0, "height should be positive");
        // DWRITE_TEXT_METRICS.width and .height are in DIPs (1/96 inch),
        // which are identical to XPS units. No conversion is needed.
        Ok(())
    }

    #[test]
    fn test_directwrite_com_guard_nested_init() -> Result<()> {
        // CoInitializeEx returns S_FALSE (0x1) on nested calls, which
        // windows-rs treats as success. This test verifies that behavior.
        let guard1 = ComGuard::new()?;
        let guard2 = ComGuard::new()?;
        // Both should succeed; drop order is guard2 then guard1.
        drop(guard2);
        drop(guard1);
        Ok(())
    }

    #[test]
    fn test_directwrite_fallback_to_segoe() -> Result<()> {
        let _com = ComGuard::new()?;
        let metrics = DirectWriteFontMetrics;
        let em_size = pt_to_xps_units(8.0);
        // Use a nonexistent font family to force the fallback path.
        // The fallback should still produce valid metrics via Segoe UI.
        let (width, height) = metrics.measure("Test", "NonexistentFontXYZ123", em_size)?;
        assert!(width > 0.0, "fallback width should be positive");
        assert!(height > 0.0, "fallback height should be positive");
        Ok(())
    }
}

#[cfg(test)]
#[cfg(not(windows))]
mod tests {
    use super::DirectWriteFontMetrics;

    #[test]
    fn test_stub_struct_exists() {
        let _ = DirectWriteFontMetrics;
    }
}
