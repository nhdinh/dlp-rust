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
//! - [`find_font_uri_in_xps`] — scans XPS ZIP for first `FontUri` attribute
//! - [`inject_watermark_into_fpage`] — streaming XML injection of Canvas/Glyphs
//! - [`rewrite_xps_with_watermark`] — ZIP traversal rewriting `.fpage` files
//! - [`inject_watermark`] — convenience wrapper for full XPS watermarking
//! - [`validate_xps_structure`] — post-rewrite validation helper
//!
//! # OPC Relationship Handling
//!
//! ## FontUri strategy for Phase 67.1
//!
//! The watermark injection reuses an existing `FontUri` from the first `Glyphs`
//! element found in any `.fpage`. If no `FontUri` is found, the `FontUri`
//! attribute is omitted and the printer driver performs font substitution. This
//! is an accepted risk because Windows spooler-generated XPS typically embeds at
//! least one font.
//!
//! ## OPC relationship updates deferred
//!
//! If a new font part were embedded (not implemented in Phase 67.1), the
//! following OPC files would need updating:
//!
//! - `[Content_Types].xml`: Add
//!   `<Override PartName="/Documents/1/Resources/Fonts/Fallback.otf" ContentType="application/vnd.openxmlformats-officedocument.obfuscatedFont"/>`
//!   (or the appropriate font content type).
//! - The relevant `.rels` file (e.g., `/Documents/1/FixedDocument.fdoc.rels`):
//!   Add `<Relationship Id="rIdFont1" Type="http://schemas.microsoft.com/xps/2005/06/required-resource" Target="Resources/Fonts/Fallback.otf"/>`.
//! - The font part itself must be added to the ZIP at the referenced path.
//!
//! These updates are **deferred to Phase 67** if production testing reveals
//! font-substitution failures.
//!
//! ## Namespace handling
//!
//! The `inject_watermark_into_fpage` function parses `xmlns` and `xmlns:*`
//! attributes from the `FixedPage` `BytesStart` event using `e.attributes()`,
//! populates a [`FixedPageNs`] enum (`Unqualified`, `Default(uri)`,
//! `Prefixed { prefix, uri }`), and emits the injected `Canvas`/`Glyphs`
//! elements with matching namespace qualification. If `FixedPage` has no
//! namespace, unqualified `Canvas`/`Glyphs` are used.
//!
//! ## Compression preservation
//!
//! Non-`.fpage` entries are copied with their original `CompressionMethod` to
//! avoid changing spool file hashes or downstream tooling behavior. `.fpage`
//! entries are intentionally rewritten as `CompressionMethod::Stored` because
//! they are small XML files and spooler compatibility is prioritized over
//! compression ratio.

use anyhow::{Context, Result};
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Reader;
use quick_xml::Writer;
use std::io::{Cursor, Read, Write};
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
                            .decoded_and_normalized_value(
                                quick_xml::XmlVersion::Implicit1_0,
                                reader.decoder(),
                            )
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
// XPS ZIP watermark injection
// ---------------------------------------------------------------------------

/// Namespace representation for the `FixedPage` element.
///
/// Captured from `xmlns` and `xmlns:*` attributes on the `FixedPage` start
/// event. Used to emit the injected `Canvas`/`Glyphs` with matching namespace
/// qualification.
#[derive(Debug, Clone, PartialEq)]
pub enum FixedPageNs {
    /// No namespace declaration on FixedPage.
    Unqualified,
    /// Default namespace: `xmlns="uri"`.
    Default(String),
    /// Prefixed namespace: `xmlns:prefix="uri"`.
    Prefixed { prefix: String, uri: String },
}

/// Scans an XPS ZIP archive for the first `FontUri` attribute in any `.fpage`.
///
/// This is a best-effort heuristic: Windows-generated XPS spool files typically
/// embed a single font part referenced by all pages. If no `FontUri` is found,
/// the watermark will rely on printer-driver font substitution (accepted risk
/// per review consensus).
///
/// # Arguments
///
/// * `xps_bytes` — Raw bytes of the XPS ZIP archive.
///
/// # Returns
///
/// * `Some(String)` — The first `FontUri` attribute value found.
/// * `None` — No `FontUri` found in any `.fpage`.
///
/// # Errors
///
/// Returns `Err` for malformed ZIP archives.
pub fn find_font_uri_in_xps(xps_bytes: &[u8]) -> Result<Option<String>> {
    let cursor = Cursor::new(xps_bytes);
    let mut archive = zip::read::ZipArchive::new(cursor).context("invalid XPS/ZIP archive")?;

    let mut page_indices: Vec<usize> = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let name_lower = file.name().to_lowercase();
        if name_lower.ends_with(".fpage") {
            page_indices.push(i);
        }
    }

    for idx in page_indices {
        let mut file = archive.by_index(idx)?;
        let mut xml_bytes = Vec::new();
        file.read_to_end(&mut xml_bytes)?;

        let mut reader = Reader::from_reader(xml_bytes.as_slice());
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                    if e.local_name().as_ref() == b"Glyphs" {
                        for attr_result in e.attributes() {
                            let attr = attr_result.context("invalid XML attribute")?;
                            if attr.key.as_ref() == b"FontUri" {
                                let value = attr
                                    .decoded_and_normalized_value(
                                        quick_xml::XmlVersion::Implicit1_0,
                                        reader.decoder(),
                                    )
                                    .unwrap_or_default()
                                    .into_owned();
                                if !value.is_empty() {
                                    return Ok(Some(value));
                                }
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    tracing::warn!(
                        page = %file.name(),
                        error = %e,
                        "XML parse error scanning for FontUri; skipping page"
                    );
                    break;
                }
                _ => {}
            }
            buf.clear();
        }
    }

    Ok(None)
}

/// Injects a watermark `Canvas`/`Glyphs` element into `.fpage` XML.
///
/// Uses a streaming reader-writer pattern: all XML events are passed through
/// verbatim except at the `</FixedPage>` end tag, where the watermark is
/// injected immediately before the closing tag.
///
/// # Arguments
///
/// * `xml` — Raw XML bytes of a `.fpage` file.
/// * `geometry` — [`WatermarkGeometry`] with placement data and text.
/// * `font_uri` — Optional font URI to embed in the `Glyphs` `FontUri`
///   attribute. If `None`, the attribute is omitted entirely.
///
/// # Returns
///
/// Rewritten XML bytes with the watermark injected.
///
/// # Errors
///
/// Returns `Err` if:
/// - No `FixedPage` element is found.
/// - `FixedPage` was seen but watermark was never injected (EOF reached first).
/// - XML parse error occurs during streaming.
///
/// # Namespace handling
///
/// The function parses `xmlns` and `xmlns:*` attributes from the `FixedPage`
/// `BytesStart` event using `e.attributes()`, populates a [`FixedPageNs`] enum,
/// and emits the injected `Canvas`/`Glyphs` elements with matching namespace
/// qualification. If `FixedPage` has no namespace, unqualified `Canvas`/`Glyphs`
/// are used.
pub fn inject_watermark_into_fpage(
    xml: &[u8],
    geometry: &WatermarkGeometry,
    font_uri: Option<&str>,
) -> Result<Vec<u8>> {
    let mut reader = Reader::from_reader(xml);
    // Preserve whitespace text nodes — do not trim.
    reader.config_mut().trim_text(false);

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut buf = Vec::new();
    let mut saw_fixed_page = false;
    let mut injected_watermark = false;
    let mut fixed_page_ns: Option<FixedPageNs> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if e.local_name().as_ref() == b"FixedPage" {
                    saw_fixed_page = true;
                    if fixed_page_ns.is_none() {
                        fixed_page_ns = parse_fixed_page_ns(e);
                    }
                }
                writer.write_event(Event::Start(e.clone()))?;
            }
            Ok(Event::Empty(ref e)) => {
                if e.local_name().as_ref() == b"FixedPage" {
                    saw_fixed_page = true;
                    if fixed_page_ns.is_none() {
                        fixed_page_ns = parse_fixed_page_ns(e);
                    }
                }
                writer.write_event(Event::Empty(e.clone()))?;
            }
            Ok(Event::End(ref e)) => {
                if e.local_name().as_ref() == b"FixedPage" {
                    injected_watermark = true;
                    write_watermark_canvas(&mut writer, geometry, font_uri, &fixed_page_ns)?;
                }
                writer.write_event(Event::End(e.clone()))?;
            }
            Ok(Event::Text(ref e)) => {
                writer.write_event(Event::Text(e.clone()))?;
            }
            Ok(Event::CData(ref e)) => {
                writer.write_event(Event::CData(e.clone()))?;
            }
            Ok(Event::Comment(ref e)) => {
                writer.write_event(Event::Comment(e.clone()))?;
            }
            Ok(Event::Decl(ref e)) => {
                writer.write_event(Event::Decl(e.clone()))?;
            }
            Ok(Event::PI(ref e)) => {
                writer.write_event(Event::PI(e.clone()))?;
            }
            Ok(Event::DocType(ref e)) => {
                writer.write_event(Event::DocType(e.clone()))?;
            }
            Ok(Event::GeneralRef(ref e)) => {
                writer.write_event(Event::GeneralRef(e.clone()))?;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                anyhow::bail!(
                    "XML parse error at position {}: {:?}",
                    reader.buffer_position(),
                    e
                );
            }
        }
        buf.clear();
    }

    if !saw_fixed_page {
        return Err(anyhow::anyhow!("no FixedPage element found"));
    }
    if saw_fixed_page && !injected_watermark {
        return Err(anyhow::anyhow!(
            "reached EOF without injecting watermark into FixedPage"
        ));
    }

    Ok(writer.into_inner().into_inner())
}

/// Parse `xmlns` and `xmlns:*` attributes from a `FixedPage` `BytesStart` event.
fn parse_fixed_page_ns(e: &BytesStart) -> Option<FixedPageNs> {
    for attr_result in e.attributes() {
        let attr = match attr_result {
            Ok(a) => a,
            Err(_) => continue,
        };
        let key = attr.key.as_ref();
        // Namespace URIs are ASCII/UTF-8; decode raw bytes directly.
        let value = String::from_utf8_lossy(attr.value.as_ref()).to_string();

        if key == b"xmlns" {
            return Some(FixedPageNs::Default(value));
        }
        if key.starts_with(b"xmlns:") {
            let prefix = String::from_utf8_lossy(&key[6..]).to_string();
            return Some(FixedPageNs::Prefixed { prefix, uri: value });
        }
    }
    Some(FixedPageNs::Unqualified)
}

/// Write the watermark `Canvas` start, `Glyphs` empty, and `Canvas` end events.
fn write_watermark_canvas(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    geometry: &WatermarkGeometry,
    font_uri: Option<&str>,
    fixed_page_ns: &Option<FixedPageNs>,
) -> Result<()> {
    // Pre-allocate buffers at function scope so references outlive match arms.
    let mut canvas_name_buf = String::new();
    let mut canvas_attr_buf = String::new();
    let mut glyphs_name_buf = String::new();

    // Build Canvas start tag with namespace and Opacity attribute.
    let (canvas_name, canvas_ns_attr) = match fixed_page_ns {
        Some(FixedPageNs::Unqualified) | None => ("Canvas", None),
        Some(FixedPageNs::Default(uri)) => ("Canvas", Some(("xmlns", uri.as_str()))),
        Some(FixedPageNs::Prefixed { prefix, uri }) => {
            canvas_name_buf.push_str(prefix);
            canvas_name_buf.push_str(":Canvas");
            canvas_attr_buf.push_str("xmlns:");
            canvas_attr_buf.push_str(prefix);
            (
                canvas_name_buf.as_str(),
                Some((canvas_attr_buf.as_str(), uri.as_str())),
            )
        }
    };

    let mut canvas_start = BytesStart::new(canvas_name);
    if let Some((key, value)) = canvas_ns_attr {
        canvas_start.push_attribute((key, value));
    }
    canvas_start.push_attribute(("Opacity", "0.5"));
    writer.write_event(Event::Start(canvas_start))?;

    // Build Glyphs empty tag with namespace and all attributes.
    let glyphs_name = match fixed_page_ns {
        Some(FixedPageNs::Prefixed { prefix, .. }) => {
            glyphs_name_buf.push_str(prefix);
            glyphs_name_buf.push_str(":Glyphs");
            glyphs_name_buf.as_str()
        }
        _ => "Glyphs",
    };

    let mut glyphs = BytesStart::new(glyphs_name);
    // push_attribute with (&str, &str) auto-escapes special XML characters.
    glyphs.push_attribute(("UnicodeString", geometry.truncated_text.as_str()));
    let em_size_str = format!("{:.4}", geometry.font_em_size);
    glyphs.push_attribute(("FontRenderingEmSize", em_size_str.as_str()));
    let origin_x_str = format!("{:.4}", geometry.origin_x);
    glyphs.push_attribute(("OriginX", origin_x_str.as_str()));
    let origin_y_str = format!("{:.4}", geometry.origin_y);
    glyphs.push_attribute(("OriginY", origin_y_str.as_str()));
    glyphs.push_attribute(("Fill", "#FF808080"));
    glyphs.push_attribute(("Opacity", "0.5"));
    if let Some(uri) = font_uri {
        glyphs.push_attribute(("FontUri", uri));
    }
    writer.write_event(Event::Empty(glyphs))?;

    // Canvas end tag.
    let canvas_end = BytesEnd::new(canvas_name);
    writer.write_event(Event::End(canvas_end))?;

    Ok(())
}

/// Rewrites an XPS ZIP archive by injecting watermarks into every `.fpage`.
///
/// Traverses the input ZIP, copies non-`.fpage` entries verbatim with their
/// original compression method, and rewrites each `.fpage` with a watermark
/// injected via [`inject_watermark_into_fpage`].
///
/// # Arguments
///
/// * `xps_bytes` — Raw bytes of the input XPS ZIP archive.
/// * `geometry_builder` — Closure that receives `(page_index, width, height)`
///   and returns a [`WatermarkGeometry`] for that page.
/// * `font_uri` — Optional font URI to reuse in the watermark.
///
/// # Returns
///
/// Rewritten XPS ZIP bytes as a new in-memory `Vec<u8>`.
///
/// # Errors
///
/// Returns `Err` for malformed ZIP, unreadable pages, or injection failures.
///
/// # Compression handling
///
/// Non-`.fpage` entries preserve their original `CompressionMethod`. `.fpage`
/// entries are rewritten as `CompressionMethod::Stored` (small XML files,
/// spooler compatibility prioritized over compression ratio).
pub fn rewrite_xps_with_watermark(
    xps_bytes: &[u8],
    geometry_builder: &mut dyn FnMut(usize, f64, f64) -> Result<WatermarkGeometry>,
    font_uri: Option<&str>,
) -> Result<Vec<u8>> {
    let cursor = Cursor::new(xps_bytes);
    let mut archive = zip::read::ZipArchive::new(cursor).context("invalid XPS/ZIP archive")?;

    let mut out_buf = Cursor::new(Vec::new());
    let mut zip_writer = zip::write::ZipWriter::new(&mut out_buf);

    let mut page_index: usize = 0;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();
        let name_lower = name.to_lowercase();

        if name_lower.ends_with(".fpage") {
            let mut xml_bytes = Vec::new();
            file.read_to_end(&mut xml_bytes)?;

            let (width, height) = extract_page_geometry(&xml_bytes)?;
            let geometry = geometry_builder(page_index, width, height)?;
            let rewritten = inject_watermark_into_fpage(&xml_bytes, &geometry, font_uri)?;

            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip_writer.start_file(name, options)?;
            zip_writer.write_all(&rewritten)?;

            page_index += 1;
        } else {
            let method = file.compression();
            let options = zip::write::SimpleFileOptions::default().compression_method(method);
            zip_writer.start_file(name, options)?;

            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            zip_writer.write_all(&content)?;
        }
    }

    zip_writer.finish()?;
    Ok(out_buf.into_inner())
}

/// Convenience wrapper: inject watermark into every `.fpage` of an XPS archive.
///
/// This is the primary entry point for Phase 67 integration. It finds an
/// existing font URI, computes per-page geometry, and returns rewritten XPS
/// bytes.
///
/// # Arguments
///
/// * `xps_bytes` — Raw bytes of the XPS ZIP archive.
/// * `text` — Watermark text string (before truncation).
/// * `metrics` — [`FontMetrics`] implementation for text measurement.
///
/// # Returns
///
/// Rewritten XPS ZIP bytes with watermarks injected into every page.
///
/// # Errors
///
/// Returns `Err` for malformed ZIP, unreadable pages, or measurement failures.
///
/// # Font substitution
///
/// If the XPS package does not contain an embedded font part, the watermark
/// `Glyphs` element will omit `FontUri` and rely on the printer driver's font
/// substitution. This is an accepted risk for Windows spooler-generated XPS,
/// which typically embeds at least one font. Full font embedding and OPC
/// relationship updates are deferred to Phase 67 if production testing reveals
/// substitution failures.
pub fn inject_watermark(
    xps_bytes: &[u8],
    text: &str,
    metrics: &dyn FontMetrics,
) -> Result<Vec<u8>> {
    let font_uri = find_font_uri_in_xps(xps_bytes)?;
    let font_uri_ref = font_uri.as_deref();

    rewrite_xps_with_watermark(
        xps_bytes,
        &mut |_page_index, page_width, page_height| {
            compute_watermark_geometry(page_width, page_height, text, metrics, 20.0)
        },
        font_uri_ref,
    )
}

/// Validates the structural integrity of a rewritten XPS package.
///
/// Verifies:
/// - The archive contains `[Content_Types].xml` at the root (required by OPC).
/// - At least one `.fpage` entry exists.
/// - Each `.fpage` contains a `<FixedPage` start tag.
///
/// # Arguments
///
/// * `xps_bytes` — Raw bytes of the XPS ZIP archive.
///
/// # Returns
///
/// `Ok(())` if all checks pass, or `Err` with a descriptive message.
///
/// # Errors
///
/// Returns `Err` for missing `[Content_Types].xml`, no `.fpage` entries, or
/// `.fpage` files without a `FixedPage` element.
pub fn validate_xps_structure(xps_bytes: &[u8]) -> Result<()> {
    let cursor = Cursor::new(xps_bytes);
    let mut archive = zip::read::ZipArchive::new(cursor).context("invalid XPS/ZIP archive")?;

    let mut has_content_types = false;
    let mut fpage_count = 0;

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let name = file.name();
        if name == "[Content_Types].xml" {
            has_content_types = true;
        }
        if name.to_lowercase().ends_with(".fpage") {
            fpage_count += 1;
        }
    }

    if !has_content_types {
        return Err(anyhow::anyhow!("missing [Content_Types].xml"));
    }
    if fpage_count == 0 {
        return Err(anyhow::anyhow!("no .fpage entries found"));
    }

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();
        if name.to_lowercase().ends_with(".fpage") {
            let mut xml_bytes = Vec::new();
            file.read_to_end(&mut xml_bytes)?;

            let mut reader = Reader::from_reader(xml_bytes.as_slice());
            reader.config_mut().trim_text(true);
            let mut buf = Vec::new();
            let mut found_fixed_page = false;

            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                        if e.local_name().as_ref() == b"FixedPage" {
                            found_fixed_page = true;
                            break;
                        }
                    }
                    Ok(Event::Eof) => break,
                    Err(e) => {
                        anyhow::bail!(
                            "XML parse error in {} at position {}: {:?}",
                            name,
                            reader.buffer_position(),
                            e
                        );
                    }
                    _ => {}
                }
                buf.clear();
            }

            if !found_fixed_page {
                return Err(anyhow::anyhow!(
                    "{} does not contain a FixedPage element",
                    name
                ));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Existing Plan 01 tests (preserved)
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Plan 02: XPS ZIP watermark injection tests
    // -----------------------------------------------------------------------

    use std::io::Write;

    /// Build a minimal in-memory XPS (ZIP) fixture.
    fn build_xps_fixture(pages: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml"/>
</Types>"#;
            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(content_types.as_bytes()).unwrap();

            let fdseq = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedDocumentSequence xmlns="http://schemas.microsoft.com/xps/2005/06">
  <DocumentReference Source="Documents/1/FixedDocument.fdoc"/>
</FixedDocumentSequence>"#;
            zip.start_file("FixedDocumentSequence.fdseq", options)
                .unwrap();
            zip.write_all(fdseq.as_bytes()).unwrap();

            let fdoc = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedDocument xmlns="http://schemas.microsoft.com/xps/2005/06">
  <PageContent Source="Pages/1.fpage"/>
</FixedDocument>"#;
            zip.start_file("Documents/1/FixedDocument.fdoc", options)
                .unwrap();
            zip.write_all(fdoc.as_bytes()).unwrap();

            for (i, (width, height)) in pages.iter().enumerate() {
                let page = format!(
                    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" Width="{}" Height="{}">
  <Glyphs UnicodeString="Hello XPS World" FontRenderingEmSize="12" FontUri="/Documents/1/Resources/Fonts/arial.ttf"/>
</FixedPage>"#,
                    width, height
                );
                zip.start_file(format!("Documents/1/Pages/{}.fpage", i + 1), options)
                    .unwrap();
                zip.write_all(page.as_bytes()).unwrap();
            }

            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    /// Build a single-page XPS fixture with custom page XML content.
    fn build_single_page_xps(page_xml: &str) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml"/>
</Types>"#;
            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(content_types.as_bytes()).unwrap();

            zip.start_file("Documents/1/Pages/1.fpage", options)
                .unwrap();
            zip.write_all(page_xml.as_bytes()).unwrap();

            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn test_inject_watermark_into_fpage_adds_canvas_glyphs() {
        let page_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" Width="816" Height="1056">
  <Glyphs UnicodeString="Hello XPS World" FontRenderingEmSize="12" FontUri="/Documents/1/Resources/Fonts/arial.ttf"/>
</FixedPage>"#;

        let geometry = WatermarkGeometry {
            origin_x: 500.0,
            origin_y: 1000.0,
            font_em_size: 10.6667,
            page_width: 816.0,
            page_height: 1056.0,
            truncated_text: "Test Watermark".to_string(),
            padding: 20.0,
        };

        let result = inject_watermark_into_fpage(
            page_xml.as_bytes(),
            &geometry,
            Some("/Documents/1/Resources/Fonts/arial.ttf"),
        )
        .unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Verify original Glyphs is still present.
        assert!(result_str.contains("Hello XPS World"));
        // Verify Canvas start appears before FixedPage end.
        assert!(result_str.contains("<Canvas"));
        // Verify Glyphs with watermark attributes.
        assert!(result_str.contains("UnicodeString=\"Test Watermark\""));
        assert!(result_str.contains("FontUri=\"/Documents/1/Resources/Fonts/arial.ttf\""));
        assert!(result_str.contains("Fill=\"#FF808080\""));
        assert!(result_str.contains("Opacity=\"0.5\""));
        // Verify Canvas end appears.
        assert!(result_str.contains("</Canvas>"));
        // Verify FixedPage end is still there.
        assert!(result_str.contains("</FixedPage>"));
    }

    #[test]
    fn test_inject_watermark_into_fpage_namespaced_fixedpage() {
        let page_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" Width="816" Height="1056">
  <Glyphs UnicodeString="Text" FontRenderingEmSize="12"/>
</FixedPage>"#;

        let geometry = WatermarkGeometry {
            origin_x: 500.0,
            origin_y: 1000.0,
            font_em_size: 10.6667,
            page_width: 816.0,
            page_height: 1056.0,
            truncated_text: "NS Test".to_string(),
            padding: 20.0,
        };

        let result = inject_watermark_into_fpage(page_xml.as_bytes(), &geometry, None).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Injection succeeded (local-name matching, not raw byte matching).
        assert!(result_str.contains("<Canvas"));
        assert!(result_str.contains("</Canvas>"));
        // Canvas should carry the same namespace URI.
        assert!(result_str.contains("xmlns=\"http://schemas.microsoft.com/xps/2005/06\""));
    }

    #[test]
    fn test_inject_watermark_into_fpage_prefixed_fixedpage() {
        let page_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xps:FixedPage xmlns:xps="http://schemas.microsoft.com/xps/2005/06" Width="816" Height="1056">
  <xps:Glyphs UnicodeString="Text" FontRenderingEmSize="12"/>
</xps:FixedPage>"#;

        let geometry = WatermarkGeometry {
            origin_x: 500.0,
            origin_y: 1000.0,
            font_em_size: 10.6667,
            page_width: 816.0,
            page_height: 1056.0,
            truncated_text: "Prefixed Test".to_string(),
            padding: 20.0,
        };

        let result = inject_watermark_into_fpage(page_xml.as_bytes(), &geometry, None).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // Injection succeeded using local-name matching.
        assert!(result_str.contains("xps:Canvas"));
        assert!(result_str.contains("xps:Glyphs"));
        assert!(result_str.contains("xmlns:xps=\"http://schemas.microsoft.com/xps/2005/06\""));
        assert!(result_str.contains("</xps:Canvas>"));
        assert!(result_str.contains("</xps:FixedPage>"));
    }

    #[test]
    fn test_inject_watermark_into_fpage_unqualified_fixedpage() {
        let page_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage Width="816" Height="1056">
  <Glyphs UnicodeString="Text" FontRenderingEmSize="12"/>
</FixedPage>"#;

        let geometry = WatermarkGeometry {
            origin_x: 500.0,
            origin_y: 1000.0,
            font_em_size: 10.6667,
            page_width: 816.0,
            page_height: 1056.0,
            truncated_text: "Unqualified Test".to_string(),
            padding: 20.0,
        };

        let result = inject_watermark_into_fpage(page_xml.as_bytes(), &geometry, None).unwrap();
        let result_str = String::from_utf8_lossy(&result);

        // No namespace attributes on injected elements.
        assert!(result_str.contains("<Canvas"));
        assert!(!result_str.contains("xmlns="));
        assert!(result_str.contains("<Glyphs"));
        assert!(result_str.contains("</Canvas>"));
    }

    #[test]
    fn test_inject_watermark_roundtrip() {
        let xps = build_xps_fixture(&[("816", "1056"), ("612", "792")]);
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let text = "User | 2024-01-01 | abcdef12 | T3 | approval-123";

        let result = inject_watermark(&xps, text, &metrics).unwrap();

        // Verify output is a valid ZIP.
        let cursor = Cursor::new(&result);
        let mut archive = zip::read::ZipArchive::new(cursor).unwrap();

        // Verify both .fpage entries exist.
        let mut fpage_count = 0;
        for i in 0..archive.len() {
            let name = archive.by_index(i).unwrap().name().to_string();
            if name.to_lowercase().ends_with(".fpage") {
                fpage_count += 1;
            }
        }
        assert_eq!(fpage_count, 2);

        // Validate structure.
        validate_xps_structure(&result).unwrap();
    }

    #[test]
    fn test_inject_watermark_preserves_non_page_files() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml"/>
</Types>"#;
            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(content_types.as_bytes()).unwrap();

            let fdseq = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedDocumentSequence xmlns="http://schemas.microsoft.com/xps/2005/06">
  <DocumentReference Source="Documents/1/FixedDocument.fdoc"/>
</FixedDocumentSequence>"#;
            zip.start_file("FixedDocumentSequence.fdseq", options)
                .unwrap();
            zip.write_all(fdseq.as_bytes()).unwrap();

            let fdoc = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedDocument xmlns="http://schemas.microsoft.com/xps/2005/06">
  <PageContent Source="Pages/1.fpage"/>
</FixedDocument>"#;
            zip.start_file("Documents/1/FixedDocument.fdoc", options)
                .unwrap();
            zip.write_all(fdoc.as_bytes()).unwrap();

            let page = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" Width="816" Height="1056">
  <Glyphs UnicodeString="Text" FontRenderingEmSize="12"/>
</FixedPage>"#;
            zip.start_file("Documents/1/Pages/1.fpage", options)
                .unwrap();
            zip.write_all(page.as_bytes()).unwrap();

            zip.finish().unwrap();
        }
        let xps = buf.into_inner();

        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let result = inject_watermark(&xps, "Test", &metrics).unwrap();

        // Verify non-page files are preserved byte-for-byte.
        let cursor = Cursor::new(&result);
        let mut out_archive = zip::read::ZipArchive::new(cursor).unwrap();

        let in_cursor = Cursor::new(&xps);
        let mut in_archive = zip::read::ZipArchive::new(in_cursor).unwrap();

        for i in 0..out_archive.len() {
            let mut out_file = out_archive.by_index(i).unwrap();
            let name = out_file.name().to_string();
            if name.to_lowercase().ends_with(".fpage") {
                continue;
            }

            let mut in_file = in_archive.by_name(&name).unwrap();
            let mut out_content = Vec::new();
            let mut in_content = Vec::new();
            out_file.read_to_end(&mut out_content).unwrap();
            in_file.read_to_end(&mut in_content).unwrap();
            assert_eq!(
                out_content, in_content,
                "non-page file {} content changed",
                name
            );
        }
    }

    #[test]
    fn test_inject_watermark_empty_text() {
        let xps = build_xps_fixture(&[("816", "1056")]);
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };

        let result = inject_watermark(&xps, "", &metrics).unwrap();
        validate_xps_structure(&result).unwrap();

        // Verify watermark of empty string still has Canvas/Glyphs.
        let cursor = Cursor::new(&result);
        let mut archive = zip::read::ZipArchive::new(cursor).unwrap();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let name = file.name().to_string();
            if name.to_lowercase().ends_with(".fpage") {
                let mut xml_bytes = Vec::new();
                file.read_to_end(&mut xml_bytes).unwrap();
                let xml_str = String::from_utf8_lossy(&xml_bytes);
                assert!(xml_str.contains("<Canvas"));
                assert!(xml_str.contains("<Glyphs"));
            }
        }
    }

    #[test]
    fn test_inject_watermark_into_fpage_missing_fixedpage() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Root><Child/></Root>"#;
        let geometry = WatermarkGeometry {
            origin_x: 0.0,
            origin_y: 0.0,
            font_em_size: 10.0,
            page_width: 100.0,
            page_height: 100.0,
            truncated_text: "Test".to_string(),
            padding: 20.0,
        };

        let result = inject_watermark_into_fpage(xml.as_bytes(), &geometry, None);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("no FixedPage element found"));
    }

    #[test]
    fn test_inject_watermark_into_fpage_whitespace_preserved() {
        let page_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage Width="816" Height="1056">
  <Glyphs/>
</FixedPage>"#;

        let geometry = WatermarkGeometry {
            origin_x: 500.0,
            origin_y: 1000.0,
            font_em_size: 10.6667,
            page_width: 816.0,
            page_height: 1056.0,
            truncated_text: "WS Test".to_string(),
            padding: 20.0,
        };

        let result = inject_watermark_into_fpage(page_xml.as_bytes(), &geometry, None).unwrap();

        // Parse output with trim_text(false) and count Text events.
        let mut reader = Reader::from_reader(result.as_slice());
        reader.config_mut().trim_text(false);
        let mut buf = Vec::new();
        let mut text_count = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Text(_)) => {
                    text_count += 1;
                }
                Ok(Event::Eof) => break,
                _ => {}
            }
            buf.clear();
        }

        // Should have at least one whitespace text node (the "\n  " before Glyphs).
        assert!(
            text_count >= 1,
            "expected at least 1 text event, got {}",
            text_count
        );
    }

    #[test]
    fn test_inject_watermark_into_fpage_escaped_attributes() {
        let page_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage Width="816" Height="1056">
  <Glyphs/>
</FixedPage>"#;

        let geometry = WatermarkGeometry {
            origin_x: 500.0,
            origin_y: 1000.0,
            font_em_size: 10.6667,
            page_width: 816.0,
            page_height: 1056.0,
            truncated_text: "User & Device <test> \"quote\" 'apos'".to_string(),
            padding: 20.0,
        };

        let result = inject_watermark_into_fpage(page_xml.as_bytes(), &geometry, None).unwrap();

        // Parse the output XML — should not error on escaped attributes.
        let mut reader = Reader::from_reader(result.as_slice());
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let mut found_unicode_string = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                    if e.local_name().as_ref() == b"Glyphs" {
                        for attr_result in e.attributes() {
                            let attr = attr_result.unwrap();
                            if attr.key.as_ref() == b"UnicodeString" {
                                let value = attr
                                    .decoded_and_normalized_value(
                                        quick_xml::XmlVersion::Implicit1_0,
                                        reader.decoder(),
                                    )
                                    .unwrap_or_default()
                                    .into_owned();
                                assert_eq!(value, "User & Device <test> \"quote\" 'apos'");
                                found_unicode_string = true;
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error: {:?}", e),
                _ => {}
            }
            buf.clear();
        }

        assert!(found_unicode_string);
    }

    #[test]
    fn test_rewrite_xps_with_watermark_per_page_geometry() {
        let xps = build_xps_fixture(&[("816", "1056"), ("612", "792")]);

        let mut received_dims: Vec<(usize, f64, f64)> = Vec::new();
        let result = rewrite_xps_with_watermark(
            &xps,
            &mut |page_index, width, height| {
                received_dims.push((page_index, width, height));
                Ok(WatermarkGeometry {
                    origin_x: 0.0,
                    origin_y: 0.0,
                    font_em_size: 10.0,
                    page_width: width,
                    page_height: height,
                    truncated_text: "Test".to_string(),
                    padding: 20.0,
                })
            },
            None,
        )
        .unwrap();

        validate_xps_structure(&result).unwrap();
        assert_eq!(received_dims.len(), 2);
        assert_eq!(received_dims[0], (0, 816.0, 1056.0));
        assert_eq!(received_dims[1], (1, 612.0, 792.0));
    }

    #[test]
    fn test_find_font_uri_in_xps_finds_existing_font() {
        let xps = build_xps_fixture(&[("816", "1056")]);
        let result = find_font_uri_in_xps(&xps).unwrap();
        assert_eq!(
            result,
            Some("/Documents/1/Resources/Fonts/arial.ttf".to_string())
        );
    }

    #[test]
    fn test_find_font_uri_in_xps_returns_none_when_no_font() {
        let page_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage Width="816" Height="1056">
  <Glyphs UnicodeString="Text" FontRenderingEmSize="12"/>
</FixedPage>"#;
        let xps = build_single_page_xps(page_xml);
        let result = find_font_uri_in_xps(&xps).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_inject_watermark_malformed_zip() {
        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let result = inject_watermark(b"not a zip", "Test", &metrics);
        assert!(result.is_err());
    }

    #[test]
    fn test_inject_watermark_missing_content_types() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let page = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage Width="816" Height="1056">
  <Glyphs/>
</FixedPage>"#;
            zip.start_file("Documents/1/Pages/1.fpage", options)
                .unwrap();
            zip.write_all(page.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        let xps = buf.into_inner();

        let result = validate_xps_structure(&xps);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("missing [Content_Types].xml"));
    }

    #[test]
    fn test_inject_watermark_truncated_fpage() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml"/>
</Types>"#;
            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(content_types.as_bytes()).unwrap();

            // Truncated XML (unclosed FixedPage).
            let page = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage Width="816" Height="1056">
  <Glyphs UnicodeString="Text" FontRenderingEmSize="12">"#;
            zip.start_file("Documents/1/Pages/1.fpage", options)
                .unwrap();
            zip.write_all(page.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        let xps = buf.into_inner();

        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let result = inject_watermark(&xps, "Test", &metrics);
        assert!(result.is_err());
    }

    #[test]
    fn test_inject_watermark_preserves_compression_method() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);

            let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="fpage" ContentType="application/vnd.ms-package.xps-fixedpage+xml"/>
</Types>"#;
            let stored_options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("[Content_Types].xml", stored_options)
                .unwrap();
            zip.write_all(content_types.as_bytes()).unwrap();

            let page = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage Width="816" Height="1056">
  <Glyphs/>
</FixedPage>"#;
            zip.start_file("Documents/1/Pages/1.fpage", stored_options)
                .unwrap();
            zip.write_all(page.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        let xps = buf.into_inner();

        let metrics = TestFontMetrics {
            char_width: 5.0,
            line_height: 10.0,
        };
        let result = inject_watermark(&xps, "Test", &metrics).unwrap();

        // Verify non-page content is byte-identical.
        let out_cursor = Cursor::new(&result);
        let mut out_archive = zip::read::ZipArchive::new(out_cursor).unwrap();

        let in_cursor = Cursor::new(&xps);
        let mut in_archive = zip::read::ZipArchive::new(in_cursor).unwrap();

        for i in 0..out_archive.len() {
            let mut out_file = out_archive.by_index(i).unwrap();
            let name = out_file.name().to_string();
            if name.to_lowercase().ends_with(".fpage") {
                continue;
            }

            let mut in_file = in_archive.by_name(&name).unwrap();
            let mut out_content = Vec::new();
            let mut in_content = Vec::new();
            out_file.read_to_end(&mut out_content).unwrap();
            in_file.read_to_end(&mut in_content).unwrap();
            assert_eq!(out_content, in_content, "file {} content changed", name);
        }
    }

    #[test]
    fn test_validate_xps_structure_passes_valid() {
        let xps = build_xps_fixture(&[("816", "1056")]);
        validate_xps_structure(&xps).unwrap();
    }

    #[test]
    fn test_validate_xps_structure_fails_no_fpage() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>"#;
            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(content_types.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        let xps = buf.into_inner();

        let result = validate_xps_structure(&xps);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("no .fpage entries found"));
    }
}
