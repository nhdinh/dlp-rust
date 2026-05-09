//! Cloud share-link detection and ABAC enforcement (M017/S03).
//!
//! This module is intentionally free of Windows APIs so it compiles and tests
//! on any platform. All detection is pure string matching — no I/O, no async.

use dlp_common::{Classification, Decision};

// CloudProvider is defined in cloud_enforcer, which is Windows-only. We re-declare
// a cross-platform alias here by conditionally importing or defining a local mirror.
//
// On Windows we re-use the real enum to keep a single canonical type.
// On non-Windows (e.g. CI running on Linux) we define a structurally identical
// local enum so the module still compiles and tests can run.
#[cfg(windows)]
use crate::cloud_enforcer::CloudProvider;

/// Four cloud storage providers whose share links this module detects.
///
/// Mirrors `cloud_enforcer::CloudProvider` exactly so that on Windows both
/// types unify; on non-Windows the local definition satisfies the compiler.
#[cfg(not(windows))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProvider {
    /// Microsoft OneDrive (personal or business).
    OneDrive,
    /// Google Drive / Drive for Desktop.
    GoogleDrive,
    /// Dropbox.
    Dropbox,
    /// Box Drive.
    Box,
}


/// A share URL found in clipboard text, attributed to its cloud provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedShareLink {
    /// The cloud storage provider that issued this share link.
    pub provider: CloudProvider,
    /// The raw URL as it appeared in the pasted text (not lowercased).
    pub url: String,
}

/// The result of evaluating a single [`DetectedShareLink`] against ABAC policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLinkAlertResult {
    /// Human-readable provider name (e.g. `"OneDrive"`).
    pub provider: String,
    /// The share URL (may be truncated for audit log purposes).
    pub url: String,
    /// ABAC decision. Always [`Decision::DENY`] for T3/T4 content.
    pub decision: Decision,
}

/// Per-provider share-path substrings.
///
/// Each slice contains the path segments that conclusively identify a *shared*
/// URL for that provider. Domain-only strings (e.g. bare `dropbox.com`) are
/// intentionally absent — the substring must include the share path segment.
struct ProviderPatterns {
    provider: CloudProvider,
    /// Lowercased substrings; any match is sufficient.
    patterns: &'static [&'static str],
}

const PROVIDER_PATTERNS: &[ProviderPatterns] = &[
    ProviderPatterns {
        provider: CloudProvider::OneDrive,
        patterns: &[
            "1drv.ms/",
            "onedrive.live.com/",
            "sharepoint.com/s/",
            "sharepoint.com/?share=",
        ],
    },
    ProviderPatterns {
        provider: CloudProvider::GoogleDrive,
        patterns: &[
            "drive.google.com/file/d/",
            "drive.google.com/drive/folders/",
            "docs.google.com/document/d/",
            "docs.google.com/spreadsheets/d/",
            "docs.google.com/presentation/d/",
        ],
    },
    ProviderPatterns {
        provider: CloudProvider::Dropbox,
        patterns: &[
            "dropbox.com/s/",
            "dropbox.com/sh/",
            "dropbox.com/scl/",
        ],
    },
    ProviderPatterns {
        // Use "//app.box.com/s/" and "//box.com/s/" to avoid matching "dropbox.com/s/".
        provider: CloudProvider::Box,
        patterns: &["//app.box.com/s/", "//box.com/s/"],
    },
];

/// Scan `text` for cloud share links and return one entry per provider (first match wins).
///
/// Detection operates on a lowercased copy of `text` so that URL casing
/// variations do not affect results. The original (non-lowercased) URL is
/// preserved in `DetectedShareLink::url` by locating the match offset and
/// slicing the original text.
///
/// # Arguments
///
/// * `text` — The clipboard text to scan; may contain multiple URLs.
///
/// # Returns
///
/// A `Vec<DetectedShareLink>` with at most one entry per provider, ordered
/// by the position of the first match for that provider.
pub fn detect_share_links(text: &str) -> Vec<DetectedShareLink> {
    let lower = text.to_lowercase();
    let mut results = Vec::new();

    'provider: for pp in PROVIDER_PATTERNS {
        for &pattern in pp.patterns {
            if let Some(match_start) = lower.find(pattern) {
                // Walk backward from match_start to find the URL boundary
                // (start of "http://" or "https://", or fallback to match_start).
                let url_start = lower[..match_start]
                    .rfind("http")
                    .unwrap_or(match_start);

                // Walk forward to the next whitespace or end-of-string.
                let url_slice = &text[url_start..];
                let url_end = url_slice
                    .find(|c: char| c.is_ascii_whitespace())
                    .unwrap_or(url_slice.len());
                let url = url_slice[..url_end].to_string();

                results.push(DetectedShareLink {
                    provider: pp.provider.clone(),
                    url,
                });
                // Only the first matching pattern per provider is emitted.
                continue 'provider;
            }
        }
    }

    results
}

/// Returns the human-readable display name for a cloud provider.
///
/// Kept module-local because `cloud_enforcer::CloudProvider::display_name` is
/// `fn` (private). Both the Windows import and the non-Windows mirror are
/// covered here to avoid duplicating the match in every call site.
fn provider_display_name(provider: &CloudProvider) -> &'static str {
    match provider {
        CloudProvider::OneDrive => "OneDrive",
        CloudProvider::GoogleDrive => "Google Drive",
        CloudProvider::Dropbox => "Dropbox",
        CloudProvider::Box => "Box",
    }
}

/// Stateless enforcer that converts detected share links into ABAC decisions.
pub struct ShareLinkEnforcer;

impl ShareLinkEnforcer {
    /// Evaluate detected share links against the resource classification.
    ///
    /// Returns `Some(results)` when `classification >= T3` and `links` is
    /// non-empty; each link maps to one [`ShareLinkAlertResult`] with
    /// [`Decision::DENY`]. Returns `None` when the classification is below
    /// T3 or when no share links were detected.
    ///
    /// # Arguments
    ///
    /// * `links` — Share links previously detected by [`detect_share_links`].
    /// * `classification` — Sensitivity tier of the resource being shared.
    ///
    /// # Returns
    ///
    /// `Some(Vec<ShareLinkAlertResult>)` on T3/T4 with detected links,
    /// `None` otherwise.
    #[must_use]
    pub fn check(
        links: &[DetectedShareLink],
        classification: Classification,
    ) -> Option<Vec<ShareLinkAlertResult>> {
        // T3 and T4 require action; T1 and T2 are permitted without alerting.
        if classification < Classification::T3 || links.is_empty() {
            return None;
        }

        let results = links
            .iter()
            .map(|link| ShareLinkAlertResult {
                provider: provider_display_name(&link.provider).to_string(),
                url: link.url.clone(),
                decision: Decision::DENY,
            })
            .collect();

        Some(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // detect_share_links
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_no_links_returns_empty() {
        let links = detect_share_links("Just some plain text with no URLs at all.");
        assert!(links.is_empty());
    }

    #[test]
    fn test_detect_onedrive_1drv_ms() {
        let text = "Check out this file: https://1drv.ms/u/s!AaBbCcDd?e=xyz";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::OneDrive);
        assert!(links[0].url.starts_with("https://1drv.ms/"));
    }

    #[test]
    fn test_detect_onedrive_live_com() {
        let text = "https://onedrive.live.com/redir?resid=ABC";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::OneDrive);
    }

    #[test]
    fn test_detect_sharepoint_s_path() {
        let text = "https://contoso.sharepoint.com/s/Finance/Report.xlsx?e=abc";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::OneDrive);
    }

    #[test]
    fn test_detect_sharepoint_share_param() {
        let text = "https://contoso.sharepoint.com/?share=AaBbCcDdEe";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::OneDrive);
    }

    #[test]
    fn test_detect_google_drive_file() {
        let text = "https://drive.google.com/file/d/1abc2DEF/view?usp=sharing";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::GoogleDrive);
    }

    #[test]
    fn test_detect_google_drive_folders() {
        let text = "https://drive.google.com/drive/folders/0Abc123?usp=sharing";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::GoogleDrive);
    }

    #[test]
    fn test_detect_google_docs() {
        let text = "https://docs.google.com/document/d/1XyZ/edit?usp=sharing";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::GoogleDrive);
    }

    #[test]
    fn test_detect_dropbox_s() {
        let text = "https://www.dropbox.com/s/abc123/report.pdf?dl=0";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::Dropbox);
    }

    #[test]
    fn test_detect_dropbox_sh() {
        let text = "https://www.dropbox.com/sh/abc/shared-folder?dl=0";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::Dropbox);
    }

    #[test]
    fn test_detect_dropbox_scl() {
        let text = "https://www.dropbox.com/scl/fo/abc123/def";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::Dropbox);
    }

    #[test]
    fn test_detect_box_s() {
        let text = "https://app.box.com/s/xyzABC123";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, CloudProvider::Box);
    }

    #[test]
    fn test_detect_multi_provider_paste() {
        let text = "OneDrive: https://1drv.ms/u/s!AaBb  Google: https://drive.google.com/file/d/1xyz \
                    Dropbox: https://www.dropbox.com/s/foo/bar Box: https://app.box.com/s/qqq";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 4, "expected one result per provider");
        let providers: Vec<&CloudProvider> = links.iter().map(|l| &l.provider).collect();
        assert!(providers.contains(&&CloudProvider::OneDrive));
        assert!(providers.contains(&&CloudProvider::GoogleDrive));
        assert!(providers.contains(&&CloudProvider::Dropbox));
        assert!(providers.contains(&&CloudProvider::Box));
    }

    #[test]
    fn test_detect_duplicate_provider_emits_only_first() {
        // Two OneDrive URLs: only one entry should appear.
        let text =
            "https://1drv.ms/u/s!First https://1drv.ms/u/s!Second";
        let links = detect_share_links(text);
        let onedrive_count = links
            .iter()
            .filter(|l| l.provider == CloudProvider::OneDrive)
            .count();
        assert_eq!(onedrive_count, 1, "must emit at most one entry per provider");
        assert!(links[0].url.contains("First"), "should capture the FIRST match");
    }

    /// Bare domain without a recognised share path must NOT trigger a match.
    #[test]
    fn test_detect_bare_domain_no_false_positive() {
        let text = "Visit dropbox.com for more info. Also box.com is good.";
        let links = detect_share_links(text);
        assert!(
            links.is_empty(),
            "bare domain without share path must not match; got: {links:?}"
        );
    }

    #[test]
    fn test_detect_preserves_original_case_in_url() {
        let text = "https://1drv.ms/u/s!AaBbCcDd";
        let links = detect_share_links(text);
        assert_eq!(links.len(), 1);
        // The URL in the result should preserve original casing.
        assert!(
            links[0].url.contains("AaBbCcDd"),
            "original case must be preserved; got: {}",
            links[0].url
        );
    }

    // -----------------------------------------------------------------------
    // ShareLinkEnforcer::check
    // -----------------------------------------------------------------------

    fn make_link(provider: CloudProvider, url: &str) -> DetectedShareLink {
        DetectedShareLink {
            provider,
            url: url.to_string(),
        }
    }

    #[test]
    fn test_t1_no_alert() {
        let links = vec![make_link(CloudProvider::OneDrive, "https://1drv.ms/u/s!test")];
        let result = ShareLinkEnforcer::check(&links, Classification::T1);
        assert!(result.is_none(), "T1 must not trigger an alert");
    }

    #[test]
    fn test_t2_no_alert() {
        let links = vec![make_link(CloudProvider::Dropbox, "https://www.dropbox.com/s/foo")];
        let result = ShareLinkEnforcer::check(&links, Classification::T2);
        assert!(result.is_none(), "T2 must not trigger an alert");
    }

    #[test]
    fn test_t3_alert() {
        let links = vec![make_link(
            CloudProvider::GoogleDrive,
            "https://drive.google.com/file/d/1xyz",
        )];
        let result = ShareLinkEnforcer::check(&links, Classification::T3);
        let alerts = result.expect("T3 must produce alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].decision, Decision::DENY);
        assert_eq!(alerts[0].provider, "Google Drive");
    }

    #[test]
    fn test_t4_alert() {
        let links = vec![make_link(CloudProvider::Box, "https://app.box.com/s/abc")];
        let result = ShareLinkEnforcer::check(&links, Classification::T4);
        let alerts = result.expect("T4 must produce alerts");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].decision, Decision::DENY);
        assert_eq!(alerts[0].provider, "Box");
    }

    #[test]
    fn test_multi_provider_t3_all_denied() {
        let links = vec![
            make_link(CloudProvider::OneDrive, "https://1drv.ms/u/s!A"),
            make_link(CloudProvider::Dropbox, "https://www.dropbox.com/s/b"),
        ];
        let result = ShareLinkEnforcer::check(&links, Classification::T3);
        let alerts = result.expect("T3 multi-provider must produce alerts");
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().all(|a| a.decision == Decision::DENY));
    }

    #[test]
    fn test_empty_links_returns_none_even_at_t4() {
        let result = ShareLinkEnforcer::check(&[], Classification::T4);
        assert!(result.is_none(), "empty link list must return None");
    }

    #[test]
    fn test_alert_result_contains_url() {
        let url = "https://1drv.ms/u/s!SomeToken";
        let links = vec![make_link(CloudProvider::OneDrive, url)];
        let result = ShareLinkEnforcer::check(&links, Classification::T3);
        let alerts = result.unwrap();
        assert_eq!(alerts[0].url, url);
    }
}
