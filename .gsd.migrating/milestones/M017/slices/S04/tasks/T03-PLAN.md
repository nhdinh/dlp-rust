---
estimated_steps: 24
estimated_files: 2
skills_used: []
---

# T03: Build XPS text extraction parser

Create a ZIP+XML parser that extracts text content from XPS spool files for classification.

**Steps:**
1. Create `dlp-agent/src/print_xps_parser.rs`.
2. Implement `extract_text(xps_bytes: &[u8], max_pages: usize) -> Result<String>`.
3. Use `zip::read::ZipArchive::new(std::io::Cursor::new(xps_bytes))` to read the ZIP.
4. Iterate entries matching `Documents/*/Pages/*.fpage` (case-insensitive).
5. For each matched page, parse XML with `quick_xml::Reader`, extract `UnicodeString` attribute values from `Glyphs` elements.
6. Concatenate all extracted text with spaces, stop after `max_pages` entries.
7. Return empty string if no text found (not an error).
8. Add `#[cfg(windows)] pub mod print_xps_parser;` to `dlp-agent/src/lib.rs`.
9. Write unit tests with an inline XPS fixture:
   - Build a minimal ZIP in memory containing `[Content_Types].xml`, `FixedDocumentSequence.fdseq`, `Documents/1/FixedDocument.fdoc`, `Documents/1/Pages/1.fpage` with known `Glyphs` text.
   - Assert `extract_text` returns the known text.
   - Assert `max_pages=0` returns empty string.
   - Assert `max_pages=1` returns only first page text.

**Skills used:** rust-engineer, test

**Failure Modes:**
- Malformed ZIP → return error (don't panic).
- Missing `.fpage` entries → return empty string (metadata-only fallback triggered by caller).
- XML parse error on one page → skip that page, continue with others.

**Negative Tests:**
- Empty ZIP bytes → error returned, not panic.
- ZIP with no `.fpage` entries → empty string.
- Corrupted XML inside `.fpage` → skip page, return text from other pages.

## Inputs

- `dlp-agent/src/lib.rs`
- `dlp-agent/Cargo.toml`

## Expected Output

- ``dlp-agent/src/print_xps_parser.rs` — new XPS parser module`
- ``dlp-agent/src/lib.rs` — mod declaration added`

## Verification

cargo test --lib print_xps_parser passes

## Observability Impact

No new runtime signals; pure parser module.
