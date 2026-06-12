//! XPS page geometry and watermark text metrics (Phase 67.1).
//!
//! Provides the core building blocks for print watermarking:
//! - [`WatermarkGeometry`] — placement data (origin, font size, text)
//! - [`FontMetrics`] trait — abstraction over text measurement
//! - [`TestFontMetrics`] — deterministic stub for CI testing
//! - [`extract_page_geometry`] — streaming XML parse of `FixedPage` dimensions
//! - [`compute_watermark_geometry`] — pure function for placement math
//! - [`build_watermark_text`] — pipe-delimited watermark string builder
//! - [`truncate_with_ellipsis`] — iterative truncation with re-measurement
//! - [`pt_to_xps_units`] — single source of truth for point-to-XPS conversion
//! - [`dip_to_xps_units`] — identity documenting DIP == XPS unit equivalence

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::str::FromStr;

/// Convert points (pt) to XPS units (1/96 inch).
///
/// 1 XPS unit = 1/96 inch (DPI basis).
/// 1 pt = 1/72 inch.
/// Therefore: `pt_to_xps_units(pt) = pt * 96.0 / 72.0`.
///
/// # Examples
///
/// ```
/// use dlp_agent::print_watermark::pt_to_xps_units;
///
/// let xps = pt_to_xps_units(8.0);
/// assert_eq!(xps, 10.666666666666666);
/// ```
pub fn pt_to_xps_units(pt: f64) -> f64 {
    pt * 96.0 / 72.0
}

/// Identity function documenting that DirectWrite DIPs equal XPS units.
///
/// DirectWrite `DWRITE_TEXT_METRICS.width` and `.height` are returned in DIPs
/// (device-independent pixels, 1/96 inch), which are identical to XPS units.
/// This function exists purely for documentation clarity and returns the
/// input unchanged.
///
/// # Examples
///
/// ```
/// use dlp_agent::print_watermark::dip_to_xps_units;
///
/// assert_eq!(dip_to_xps_units(42.0), 42.0);
/// ```
pub fn dip_to_xps_units(dip: f64) -> f64 {
    dip
}

/// Geometry data for a watermark on a single XPS page.
///
/// All dimensional fields are in XPS units (1/96 inch, also called DIPs).
#[derive(Debug, Clone, PartialEq)]
pub struct WatermarkGeometry {
    /// X coordinate of the watermark origin (bottom-right placement).
    pub origin_x: f64,
    /// Y coordinate of the watermark origin (bottom-right placement).
    pub origin_y: f64,
    /// Font em-size in XPS units (DIPs).
    pub font_em_size: f64,
    /// Page width in XPS units.
    pub page_width: f64,
    /// Page height in XPS units.
    pub page_height: f64,
    /// Truncated watermark text (may equal original if it fits).
    pub truncated_text: String,
    /// Padding from page edges in XPS units.
    pub padding: f64,
}

/// Trait for measuring text width and height.
///
/// Width and height are returned in XPS units (1/96 inch, also called DIPs).
/// Implementors may return `anyhow::Error` wrapped errors.
///
/// The `em_size` parameter is already in XPS units (i.e., DIPs) and no further
/// conversion is needed by the caller.
pub trait FontMetrics: Send + Sync {
    /// Measure the bounding box of `text` rendered in `family` at `em_size`.
    ///
    /// # Arguments
    ///
    /// * `text` — The string to measure.
    /// * `family` — Font family name (e.g., "Arial").
    /// * `em_size` — Font size in XPS units (DIPs).
    ///
    /// # Returns
    ///
    /// `(width, height)` tuple in XPS units.
    ///
    /// # Errors
    ///
    /// Returns `anyhow::Error` on measurement failure (e.g., font not found).
    fn measure(&self, text: &str, family: &str, em_size: f64) -> Result<(f64, f64)>;
}

/// Deterministic stub implementation of [`FontMetrics`] for CI testing.
///
/// Uses Unicode scalar value count (not grapheme clusters) as a deliberate
/// simplification. This is an approximation for CI on non-Windows runners.
#[derive(Debug, Clone, PartialEq)]
pub struct TestFontMetrics {
    /// Width per character in XPS units.
    pub char_width: f64,
    /// Line height in XPS units.
    pub line_height: f64,
}

impl FontMetrics for TestFontMetrics {
    fn measure(&self, text: &str, _family: &str, _em_size: f64) -> Result<(f64, f64)> {
        let width = text.chars().count() as f64 * self.char_width;
        let height = self.line_height;
        Ok((width, height))
    }
}

/// Extract page width and height from `.fpage` XML.
///
/// Parses the first `FixedPage` start/empty event and extracts `Width` and
/// `Height` attributes. If either attribute is missing, logs a warning and
/// falls back to `(816.0, 1056.0)` (standard US Letter in XPS units).
/// If no `FixedPage` element is found, returns an error.
///
/// # Arguments
///
/// * `xml` — Raw XML bytes of a `.fpage` file.
///
/// # Returns
///
/// `(width, height)` tuple in XPS units, or default if attributes missing.
///
/// # Errors
///
/// Returns `Err` if `FixedPage` element is not found in the XML.
pub fn extract_page_geometry(xml: &[u8]) -> Result<(f64, f64)> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut width: Option<f64> = None;
    let mut height: Option<f64> = None;
    let mut found_fixed_page = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                if e.name().as_ref() == b"FixedPage" {
                    found_fixed_page = true;
                    for attr_result in e.attributes() {
                        let attr = attr_result.context("invalid XML attribute")?;
                        let key = attr.key.as_ref();
                        let value = attr
                            .decode_and_unescape_value(reader.decoder())
                            .unwrap_or_default()
                            .into_owned();

                        if key == b"Width" {
                            width = f64::from_str(&value).ok();
                        } else if key == b"Height" {
                            height = f64::from_str(&value).ok();
                        }
                    }
                    break;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                anyhow::bail!(
                    "XML parse error at position {}: {:?}",
                    reader.buffer_position(),
                    e
                );
            }
            _ => {}
        }
        buf.clear();
    }

    if !found_fixed_page {
        return Err(anyhow::anyhow!("FixedPage element not found in XML"));
    }

    match (width, height) {
        (Some(w), Some(h)) => Ok((w, h)),
        _ => {
            tracing::warn!(
                width = ?width,
                height = ?height,
                "Missing FixedPage dimensions; falling back to 816x1056 (US Letter)"
            );
            Ok((816.0, 1056.0))
        }
    }
}

/// Build a pipe-delimited watermark text string.
///
/// # Arguments
///
/// * `username` — User name or SID.
/// * `timestamp` — ISO-8601 or formatted timestamp.
/// * `device_fingerprint_prefix` — Short device identifier prefix.
/// * `tier_label` — Data classification tier (e.g., "T3-Confidential").
/// * `approval_id` — Approval workflow token ID.
///
/// # Returns
///
/// Formatted string: `"{username} | {timestamp} | {fp_prefix} | {tier} | {approval_id}"`.
///
/// # Examples
///
/// ```
/// use dlp_agent::print_watermark::build_watermark_text;
///
/// let text = build_watermark_text("jdoe", "2026-06-12T10:00:00Z", "DEV-AB12", "T3", "APV-12345");
/// assert_eq!(text, "jdoe | 2026-06-12T10:00:00Z | DEV-AB12 | T3 | APV-12345");
/// ```
pub fn build_watermark_text(
    username: &str,
    timestamp: &str,
    device_fingerprint_prefix: &str,
    tier_label: &str,
    approval_id: &str,
) -> String {
    format!(
        "{} | {} | {} | {} | {}",
        username, timestamp, device_fingerprint_prefix, tier_label, approval_id
    )
}

/// Truncate text with ellipsis so it fits within `available_width`.
///
/// Iteratively removes the last character and re-measures (text + "...") until
/// width <= `available_width` or only "..." remains. If even "..." exceeds
/// the width, returns "..." anyway (caller must handle extreme cases).
///
/// ## Complexity
///
/// O(n^2) where n = text length, because each truncation requires a re-measure.
/// This is acceptable for bounded watermark strings (~80-120 chars).
///
/// # Arguments
///
/// * `text` — Original text to truncate.
/// * `metrics` — [`FontMetrics`] implementation for measurement.
/// * `em_size` — Font size in XPS units.
/// * `available_width` — Maximum allowed width in XPS units.
///
/// # Returns
///
/// Truncated text with ellipsis, or "..." if nothing fits.
///
/// # Errors
///
/// Returns `anyhow::Error` on measurement failure.
pub fn truncate_with_ellipsis(
    text: &str,
    metrics: &dyn FontMetrics,
    em_size: f64,
    available_width: f64,
) -> Result<String> {
    let ellipsis = "...";
    let _ellipsis_width = metrics.measure(ellipsis, "Arial", em_size)?.0;

    // If the full text fits, no truncation needed.
    let full_width = metrics.measure(text, "Arial", em_size)?.0;
    if full_width <= available_width {
        return Ok(text.to_string());
    }

    // Iteratively remove characters and re-measure.
    let mut chars: Vec<char> = text.chars().collect();
    let max_iterations = chars.len() + 5;

    for i in 0..max_iterations {
        if chars.is_empty() {
            tracing::warn!("Truncation reached empty string; returning ellipsis as minimum");
            return Ok(ellipsis.to_string());
        }

        let candidate: String = chars.iter().collect::<String>() + ellipsis;
        let candidate_width = metrics.measure(&candidate, "Arial", em_size)?.0;

        if candidate_width <= available_width {
            return Ok(candidate);
        }

        chars.pop();

        // Safety guard: if we've done too many iterations, stop.
        if i >= max_iterations - 1 {
            tracing::warn!(
                "Truncation exceeded max iterations ({}); returning ellipsis",
                max_iterations
            );
            return Ok(ellipsis.to_string());
        }
    }

    Ok(ellipsis.to_string())
}

/// Compute watermark placement geometry for a page.
///
/// Places the watermark at the bottom-right corner with `padding` XPS units
/// from both edges. If the text is too wide, it is truncated with ellipsis.
///
/// # Arguments
///
/// * `page_width` — Page width in XPS units.
/// * `page_height` — Page height in XPS units.
/// * `text` — Watermark text (before truncation).
/// * `metrics` — [`FontMetrics`] implementation for measurement.
/// * `padding` — Distance from page edges in XPS units.
///
/// # Returns
///
/// [`WatermarkGeometry`] with computed origin, font size, and truncated text.
///
/// # Errors
///
/// Returns `anyhow::Error` on measurement failure.
pub fn compute_watermark_geometry(
    page_width: f64,
    page_height: f64,
    text: &str,
    metrics: &dyn FontMetrics,
    padding: f64,
) -> Result<WatermarkGeometry> {
    let em_size = pt_to_xps_units(8.0);
    let (text_width, _text_height) = metrics.measure(text, "Arial", em_size)?;

    let available_width = page_width - 2.0 * padding;

    let truncated_text = if text_width > available_width {
        truncate_with_ellipsis(text, metrics, em_size, available_width)?
    } else {
        text.to_string()
    };

    let (final_width, _final_height) = metrics.measure(&truncated_text, "Arial", em_size)?;

    let origin_x = page_width - padding - final_width;
    let origin_y = page_height - padding;

    Ok(WatermarkGeometry {
        origin_x,
        origin_y,
        font_em_size: em_size,
        page_width,
        page_height,
        truncated_text,
        padding,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pt_to_xps_units_8pt() {
        let result = pt_to_xps_units(8.0);
        assert!((result - 10.666666666666666).abs() < f64::EPSILON);
    }

    #[test]
    fn pt_to_xps_units_15pt() {
        let result = pt_to_xps_units(15.0);
        assert!((result - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dip_to_xps_units_identity() {
        assert_eq!(dip_to_xps_units(42.0), 42.0);
        assert_eq!(dip_to_xps_units(0.0), 0.0);
        assert_eq!(dip_to_xps_units(-5.0), -5.0);
    }

    #[test]
    fn extract_page_geometry_valid() {
        let xml = br#"<?xml version="1.0"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" Width="612" Height="792"/>"#;
        let (w, h) = extract_page_geometry(xml).unwrap();
        assert_eq!(w, 612.0);
        assert_eq!(h, 792.0);
    }

    #[test]
    fn extract_page_geometry_missing_dimensions_defaults() {
        let xml = br#"<?xml version="1.0"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06"/>"#;
        let (w, h) = extract_page_geometry(xml).unwrap();
        assert_eq!(w, 816.0);
        assert_eq!(h, 1056.0);
    }

    #[test]
    fn extract_page_geometry_no_fixedpage_returns_err() {
        let xml = br#"<?xml version="1.0"?>
<OtherElement/>"#;
        assert!(extract_page_geometry(xml).is_err());
    }

    #[test]
    fn test_font_metrics_measure() {
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let (w, h) = metrics.measure("Hello", "Arial", 12.0).unwrap();
        assert_eq!(w, 25.0); // 5 chars * 5.0
        assert_eq!(h, 10.0);
    }

    #[test]
    fn test_font_metrics_measure_empty() {
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let (w, h) = metrics.measure("", "Arial", 12.0).unwrap();
        assert_eq!(w, 0.0);
        assert_eq!(h, 10.0);
    }

    #[test]
    fn test_font_metrics_unicode() {
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        // Useré = 5 chars (U+0055, U+0073, U+0065, U+0072, U+00E9)
        let (w, h) = metrics.measure("User\u{00E9}", "Arial", 12.0).unwrap();
        assert_eq!(w, 25.0); // 5 chars * 5.0
        assert_eq!(h, 10.0);
    }

    #[test]
    fn compute_watermark_geometry_fits_no_truncation() {
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        // "Short" = 5 chars * 5.0 = 25.0 width. Page 200 wide, padding 20.
        // Available = 200 - 40 = 160. 25 < 160, so no truncation.
        let geo = compute_watermark_geometry(200.0, 300.0, "Short", &metrics, 20.0).unwrap();
        assert_eq!(geo.truncated_text, "Short");
        assert_eq!(geo.origin_x, 200.0 - 20.0 - 25.0); // 155
        assert_eq!(geo.origin_y, 300.0 - 20.0); // 280
        assert_eq!(geo.padding, 20.0);
    }

    #[test]
    fn compute_watermark_geometry_overflow_truncates() {
        let metrics = TestFontMetrics {
            char_width: 10.0,
            line_height: 10.0,
        };
        // "VeryLongText" = 12 chars * 10.0 = 120.0 width. Page 100 wide, padding 20.
        // Available = 100 - 40 = 60. 120 > 60, so truncation needed.
        let geo = compute_watermark_geometry(100.0, 150.0, "VeryLongText", &metrics, 20.0).unwrap();
        // Truncated text should end with "..."
        assert!(
            geo.truncated_text.ends_with("..."),
            "expected truncated text to end with ellipsis, got: {}",
            geo.truncated_text
        );
        // Origin should be at bottom-right with padding
        assert!(geo.origin_x > 0.0);
        assert_eq!(geo.origin_y, 150.0 - 20.0); // 130
    }

    #[test]
    fn compute_watermark_geometry_origin_bottom_right() {
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let geo = compute_watermark_geometry(400.0, 600.0, "Test", &metrics, 20.0).unwrap();
        // "Test" = 4 * 5.0 = 20.0 width
        assert_eq!(geo.origin_x, 400.0 - 20.0 - 20.0); // 360
        assert_eq!(geo.origin_y, 600.0 - 20.0); // 580
    }

    #[test]
    fn build_watermark_text_format() {
        let text = build_watermark_text(
            "jdoe",
            "2026-06-12T10:00:00Z",
            "DEV-AB12",
            "T3",
            "APV-12345",
        );
        assert_eq!(
            text,
            "jdoe | 2026-06-12T10:00:00Z | DEV-AB12 | T3 | APV-12345"
        );
    }

    #[test]
    fn truncate_with_ellipsis_even_ellipsis_exceeds() {
        // If even "..." exceeds available width, we still return "...".
        // The caller (compute_watermark_geometry) must handle this.
        let metrics = TestFontMetrics {
            char_width: 100.0,
            line_height: 10.0,
        };
        let result = truncate_with_ellipsis("A", &metrics, 12.0, 50.0).unwrap();
        assert_eq!(result, "...");
    }

    #[test]
    fn truncate_with_ellipsis_no_truncation_needed() {
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let result = truncate_with_ellipsis("Short", &metrics, 12.0, 100.0).unwrap();
        assert_eq!(result, "Short");
    }

    #[test]
    fn truncate_with_ellipsis_partial_truncation() {
        let metrics = TestFontMetrics {
            char_width: 10.0,
            line_height: 10.0,
        };
        // "VeryLong" = 8 * 10 = 80. Available = 50. Need to truncate.
        // "V..." = 4 * 10 = 40 <= 50. "Ve..." = 5 * 10 = 50 <= 50.
        let result = truncate_with_ellipsis("VeryLong", &metrics, 12.0, 50.0).unwrap();
        assert!(result.ends_with("..."));
        assert!(result.len() <= "VeryLong...".len());
    }
}
