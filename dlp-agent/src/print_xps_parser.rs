//! XPS text extraction parser (M017 T03).
//!
//! Extracts text content from XPS spool files (ZIP archives containing
//! FixedDocumentSequence + FixedDocument + page `.fpage` XML files).
//!
//! ## Redaction
//!
//! Text content is parsed in-memory and never written to disk or logs.
//! Only document metadata (name, job ID) appears in audit events.

use std::io::{Cursor, Read};

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;

/// Extracts plain text from XPS spool bytes.
///
/// # Arguments
///
/// * `xps_bytes` — Raw bytes of the XPS file (a ZIP archive).
/// * `max_pages` — Maximum number of `.fpage` files to parse. 0 means
///   return empty string immediately.
///
/// # Returns
///
/// * `Ok(text)` — Concatenated text from all parsed pages, space-separated.
///   Empty string if no text is found or `max_pages` is 0.
/// * `Err(...)` — Malformed ZIP or other unrecoverable read error.
///
/// # Failure modes
///
/// * Malformed ZIP → error returned (no panic).
/// * Missing `.fpage` entries → empty string (caller falls back to metadata-only).
/// * XML parse error on one page → that page is skipped, others continue.
pub fn extract_text(xps_bytes: &[u8], max_pages: usize) -> Result<String> {
    if max_pages == 0 || xps_bytes.is_empty() {
        return Ok(String::new());
    }

    let cursor = Cursor::new(xps_bytes);
    let mut archive = zip::read::ZipArchive::new(cursor)
        .context("invalid XPS/ZIP archive")?;

    let mut page_count: usize = 0;
    let mut all_text: Vec<String> = Vec::new();

    // Collect matching entry indices first to avoid borrow issues with archive.
    let mut page_indices: Vec<usize> = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        let name_lower = file.name().to_lowercase();
        if name_lower.contains("/pages/") && name_lower.ends_with(".fpage") {
            page_indices.push(i);
        }
    }

    for idx in page_indices {
        if page_count >= max_pages {
            break;
        }

        let mut file = archive.by_index(idx)?;
        let mut xml_bytes = Vec::new();
        if let Err(e) = file.read_to_end(&mut xml_bytes) {
            // Skip unreadable pages.
            tracing::warn!(page = %file.name(), error = %e, "failed to read XPS page");
            continue;
        }

        match parse_page_text(&xml_bytes) {
            Ok(page_text) => {
                if !page_text.is_empty() {
                    all_text.push(page_text);
                }
            }
            Err(e) => {
                tracing::warn!(page = %file.name(), error = %e, "failed to parse XPS page XML");
                // Skip corrupted pages, continue with others.
            }
        }

        page_count += 1;
    }

    Ok(all_text.join(" "))
}

/// Parse a single `.fpage` XML buffer and extract text from `Glyphs` elements.
fn parse_page_text(xml: &[u8]) -> Result<String> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut page_text: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                if e.name().as_ref() == b"Glyphs" {
                    for attr_result in e.attributes() {
                        let attr = attr_result.context("invalid XML attribute")?;
                        if attr.key.as_ref() == b"UnicodeString" {
                            let value = attr
                                .decode_and_unescape_value(reader.decoder())
                                .unwrap_or_default()
                                .into_owned();
                            if !value.is_empty() {
                                page_text.push(value);
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                anyhow::bail!("XML parse error at position {}: {:?}", reader.buffer_position(), e);
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(page_text.join(" "))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal in-memory XPS (ZIP) fixture with known text.
    fn build_xps_fixture() -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            // Required XPS structure files.
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
            zip.start_file("FixedDocumentSequence.fdseq", options).unwrap();
            zip.write_all(fdseq.as_bytes()).unwrap();

            let fdoc = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedDocument xmlns="http://schemas.microsoft.com/xps/2005/06">
  <PageContent Source="Pages/1.fpage"/>
  <PageContent Source="Pages/2.fpage"/>
</FixedDocument>"#;
            zip.start_file("Documents/1/FixedDocument.fdoc", options).unwrap();
            zip.write_all(fdoc.as_bytes()).unwrap();

            let page1 = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" Width="816" Height="1056">
  <Glyphs UnicodeString="Hello XPS World" FontRenderingEmSize="12"/>
  <Glyphs UnicodeString="Second sentence" FontRenderingEmSize="12"/>
</FixedPage>"#;
            zip.start_file("Documents/1/Pages/1.fpage", options).unwrap();
            zip.write_all(page1.as_bytes()).unwrap();

            let page2 = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06" Width="816" Height="1056">
  <Glyphs UnicodeString="Page two text" FontRenderingEmSize="12"/>
</FixedPage>"#;
            zip.start_file("Documents/1/Pages/2.fpage", options).unwrap();
            zip.write_all(page2.as_bytes()).unwrap();

            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn extract_text_returns_known_text() {
        let xps = build_xps_fixture();
        let text = extract_text(&xps, 10).unwrap();
        assert!(text.contains("Hello XPS World"));
        assert!(text.contains("Second sentence"));
        assert!(text.contains("Page two text"));
    }

    #[test]
    fn extract_text_max_pages_zero() {
        let xps = build_xps_fixture();
        let text = extract_text(&xps, 0).unwrap();
        assert_eq!(text, "");
    }

    #[test]
    fn extract_text_max_pages_one() {
        let xps = build_xps_fixture();
        let text = extract_text(&xps, 1).unwrap();
        assert!(text.contains("Hello XPS World"));
        assert!(!text.contains("Page two text"));
    }

    #[test]
    fn extract_text_empty_zip_bytes() {
        let result = extract_text(b"not a zip", 10);
        assert!(result.is_err());
    }

    #[test]
    fn extract_text_no_fpage_entries() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("readme.txt", options).unwrap();
            zip.write_all(b"no pages here").unwrap();
            zip.finish().unwrap();
        }
        let text = extract_text(&buf.into_inner(), 10).unwrap();
        assert_eq!(text, "");
    }

    #[test]
    fn extract_text_corrupted_xml_page() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            // Page 1: valid XML with text.
            let page1 = r#"<?xml version="1.0"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06">
  <Glyphs UnicodeString="Valid text" FontRenderingEmSize="12"/>
</FixedPage>"#;
            zip.start_file("Documents/1/Pages/1.fpage", options).unwrap();
            zip.write_all(page1.as_bytes()).unwrap();

            // Page 2: corrupted XML (unclosed tag).
            let page2 = r#"<?xml version="1.0"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06">
  <Glyphs UnicodeString="Broken" FontRenderingEmSize="12">
</FixedPage>"#;
            zip.start_file("Documents/1/Pages/2.fpage", options).unwrap();
            zip.write_all(page2.as_bytes()).unwrap();

            zip.finish().unwrap();
        }
        let text = extract_text(&buf.into_inner(), 10).unwrap();
        assert!(text.contains("Valid text"));
        // Page 2 should be skipped due to XML error, so "Broken" won't appear.
        assert!(!text.contains("Broken"));
    }

    #[test]
    fn extract_text_empty_bytes() {
        let text = extract_text(b"", 10).unwrap();
        assert_eq!(text, "");
    }

    #[test]
    fn extract_text_case_insensitive_fpage() {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zip = zip::write::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            let page = r#"<?xml version="1.0"?>
<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06">
  <Glyphs UnicodeString="Case insensitive" FontRenderingEmSize="12"/>
</FixedPage>"#;
            // Uppercase path — still matches case-insensitive search.
            zip.start_file("DOCUMENTS/1/PAGES/1.FPAGE", options).unwrap();
            zip.write_all(page.as_bytes()).unwrap();

            zip.finish().unwrap();
        }
        let text = extract_text(&buf.into_inner(), 10).unwrap();
        assert!(text.contains("Case insensitive"));
    }
}
