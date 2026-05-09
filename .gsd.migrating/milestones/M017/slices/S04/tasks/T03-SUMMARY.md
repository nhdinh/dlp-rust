---
id: T03
parent: S04
milestone: M017
key_files:
  - dlp-agent/src/print_xps_parser.rs
  - dlp-agent/src/lib.rs
key_decisions:
  - Used `reader.decoder()` for `decode_and_unescape_value` per quick-xml 0.36 API (expects Decoder, not &Reader)
duration: 
verification_result: passed
completed_at: 2026-05-08T15:35:17.823Z
blocker_discovered: false
---

# T03: Built XPS text extraction parser with ZIP+XML parsing, in-memory text extraction from Glyphs elements, and comprehensive unit tests

**Built XPS text extraction parser with ZIP+XML parsing, in-memory text extraction from Glyphs elements, and comprehensive unit tests**

## What Happened

Created `dlp-agent/src/print_xps_parser.rs` implementing `extract_text(xps_bytes: &[u8], max_pages: usize) -> Result<String>`. The parser opens the XPS archive as a ZIP using `zip::read::ZipArchive`, iterates entries matching `Documents/*/Pages/*.fpage` (case-insensitive), and parses each page with `quick_xml::Reader`. It extracts `UnicodeString` attribute values from `Glyphs` elements and concatenates them with spaces, stopping after `max_pages`. Malformed ZIPs return an error (no panic). Missing `.fpage` entries return an empty string. XML parse errors on individual pages skip that page and continue with others. Added `#[cfg(windows)] pub mod print_xps_parser;` to `dlp-agent/src/lib.rs`. Wrote 8 unit tests with an inline in-memory XPS fixture: happy path returns known text, max_pages=0 returns empty, max_pages=1 limits to first page, empty ZIP bytes returns error, ZIP with no .fpage returns empty, corrupted XML page is skipped, empty input bytes returns empty, and case-insensitive path matching works.

## Verification

All 8 print_xps_parser unit tests pass. The print_job_info tests (6) also pass confirming no regression. The parser correctly handles malformed ZIP, missing pages, corrupted XML pages, and case-insensitive path matching.

## Verification Evidence

| # | Command | Exit Code | Verdict | Duration |
|---|---------|-----------|---------|----------|
| 1 | `cargo test -p dlp-agent --lib print_xps_parser` | 0 | ✅ pass | 483ms |
| 2 | `cargo test -p dlp-agent --lib print_job_info` | 0 | ✅ pass | 447ms |

## Deviations

None.

## Known Issues

Pre-existing test failure in `detection::disk::tests::test_global_static_get_set` unrelated to this task; it fails before and after this change.

## Files Created/Modified

- `dlp-agent/src/print_xps_parser.rs`
- `dlp-agent/src/lib.rs`
