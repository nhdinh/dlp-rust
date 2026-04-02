//! Clipboard text content classifier (T-20).
//!
//! Assigns a provisional [`Classification`] tier to clipboard text based on
//! pattern matching.  Patterns detect common sensitive data formats:
//!
//! - **T4 (Restricted)**: Social Security numbers, credit card numbers
//! - **T3 (Confidential)**: keywords like "CONFIDENTIAL", "SECRET", internal
//!   project code names
//! - **T2 (Internal)**: keywords like "INTERNAL", "DO NOT DISTRIBUTE"
//! - **T1 (Public)**: anything that does not match a higher tier
//!
//! ## Limitations
//!
//! This is a heuristic classifier — it is not a replacement for the Policy
//! Engine's authoritative classification.  False positives are acceptable
//! (fail-safe); false negatives are minimised by matching common patterns.

use dlp_common::Classification;
use tracing::debug;

/// A pattern rule: regex pattern string + the classification it triggers.
#[derive(Debug, Clone)]
struct PatternRule {
    /// Human-readable name for logging.
    name: &'static str,
    /// The classification tier this pattern triggers.
    tier: Classification,
    /// A simple substring or pattern to match (case-insensitive).
    /// For this implementation we use substring matching to avoid a regex
    /// dependency; a production system would use `regex`.
    pattern: &'static str,
}

/// Default pattern rules ordered from highest to lowest sensitivity.
/// Evaluation stops at the first (highest) match.
const DEFAULT_RULES: &[PatternRule] = &[
    // T4 — Social Security numbers (XXX-XX-XXXX pattern)
    PatternRule {
        name: "SSN",
        tier: Classification::T4,
        pattern: "SSN_PATTERN", // handled by custom check
    },
    // T4 — Credit card numbers (16 digits with optional separators)
    PatternRule {
        name: "CreditCard",
        tier: Classification::T4,
        pattern: "CC_PATTERN", // handled by custom check
    },
    // T3 — Confidential keywords
    PatternRule {
        name: "Confidential keyword",
        tier: Classification::T3,
        pattern: "confidential",
    },
    PatternRule {
        name: "Secret keyword",
        tier: Classification::T3,
        pattern: "secret",
    },
    PatternRule {
        name: "Top Secret keyword",
        tier: Classification::T3,
        pattern: "top secret",
    },
    // T2 — Internal keywords
    PatternRule {
        name: "Internal keyword",
        tier: Classification::T2,
        pattern: "internal only",
    },
    PatternRule {
        name: "Do not distribute",
        tier: Classification::T2,
        pattern: "do not distribute",
    },
    PatternRule {
        name: "Internal use",
        tier: Classification::T2,
        pattern: "internal use",
    },
];

/// Classifies clipboard text content into a sensitivity tier.
#[derive(Debug)]
pub struct ClipboardClassifier;

impl ClipboardClassifier {
    /// Classifies the given text and returns the highest matching tier.
    ///
    /// Returns `Classification::T1` (Public) if no sensitive patterns match.
    #[must_use]
    pub fn classify(text: &str) -> Classification {
        let lower = text.to_lowercase();

        // Check structured data patterns first (highest sensitivity).
        if contains_ssn_pattern(text) {
            debug!("clipboard classified as T4: SSN pattern detected");
            return Classification::T4;
        }
        if contains_credit_card_pattern(text) {
            debug!("clipboard classified as T4: credit card pattern detected");
            return Classification::T4;
        }

        // Check keyword rules in priority order.
        for rule in DEFAULT_RULES {
            // Skip the structured-data sentinel patterns.
            if rule.pattern == "SSN_PATTERN" || rule.pattern == "CC_PATTERN" {
                continue;
            }
            if lower.contains(rule.pattern) {
                debug!(
                    rule = rule.name,
                    tier = ?rule.tier,
                    "clipboard classified by keyword match"
                );
                return rule.tier;
            }
        }

        Classification::T1
    }
}

/// Returns `true` if the text contains a pattern matching SSN format
/// (3 digits, separator, 2 digits, separator, 4 digits).
fn contains_ssn_pattern(text: &str) -> bool {
    // Simple state machine: look for XXX-XX-XXXX or XXX XX XXXX patterns.
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < 11 {
        return false;
    }
    for window in chars.windows(11) {
        let sep = window[3];
        if (sep == '-' || sep == ' ')
            && window[6] == sep
            && window[0..3].iter().all(|c| c.is_ascii_digit())
            && window[4..6].iter().all(|c| c.is_ascii_digit())
            && window[7..11].iter().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

/// Returns `true` if the text contains a pattern resembling a credit card
/// number (16 digits, optionally separated by dashes or spaces in groups of 4).
fn contains_credit_card_pattern(text: &str) -> bool {
    // Extract only digits from the text and check for 16-digit sequences.
    // Also check for formatted patterns: XXXX-XXXX-XXXX-XXXX
    let chars: Vec<char> = text.chars().collect();

    // Check formatted pattern: 4 digits, sep, 4 digits, sep, 4 digits, sep, 4 digits
    if chars.len() >= 19 {
        for window in chars.windows(19) {
            let sep = window[4];
            if (sep == '-' || sep == ' ')
                && window[9] == sep
                && window[14] == sep
                && window[0..4].iter().all(|c| c.is_ascii_digit())
                && window[5..9].iter().all(|c| c.is_ascii_digit())
                && window[10..14].iter().all(|c| c.is_ascii_digit())
                && window[15..19].iter().all(|c| c.is_ascii_digit())
            {
                return true;
            }
        }
    }

    // Check raw 16-digit sequence.
    let mut consecutive_digits = 0u32;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            consecutive_digits += 1;
            if consecutive_digits >= 16 {
                return true;
            }
        } else {
            consecutive_digits = 0;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_ssn() {
        assert_eq!(
            ClipboardClassifier::classify("My SSN is 123-45-6789"),
            Classification::T4,
        );
    }

    #[test]
    fn test_classify_ssn_spaces() {
        assert_eq!(
            ClipboardClassifier::classify("SSN: 123 45 6789"),
            Classification::T4,
        );
    }

    #[test]
    fn test_classify_credit_card_dashes() {
        assert_eq!(
            ClipboardClassifier::classify("Card: 4111-1111-1111-1111"),
            Classification::T4,
        );
    }

    #[test]
    fn test_classify_credit_card_spaces() {
        assert_eq!(
            ClipboardClassifier::classify("Card: 4111 1111 1111 1111"),
            Classification::T4,
        );
    }

    #[test]
    fn test_classify_credit_card_raw() {
        assert_eq!(
            ClipboardClassifier::classify("4111111111111111"),
            Classification::T4,
        );
    }

    #[test]
    fn test_classify_confidential_keyword() {
        assert_eq!(
            ClipboardClassifier::classify("This document is CONFIDENTIAL"),
            Classification::T3,
        );
    }

    #[test]
    fn test_classify_secret_keyword() {
        assert_eq!(
            ClipboardClassifier::classify("Project secret plans"),
            Classification::T3,
        );
    }

    #[test]
    fn test_classify_internal_only() {
        assert_eq!(
            ClipboardClassifier::classify("For internal only distribution"),
            Classification::T2,
        );
    }

    #[test]
    fn test_classify_do_not_distribute() {
        assert_eq!(
            ClipboardClassifier::classify("DO NOT DISTRIBUTE this memo"),
            Classification::T2,
        );
    }

    #[test]
    fn test_classify_public() {
        assert_eq!(
            ClipboardClassifier::classify("Hello, world!"),
            Classification::T1,
        );
    }

    #[test]
    fn test_classify_empty() {
        assert_eq!(ClipboardClassifier::classify(""), Classification::T1,);
    }

    #[test]
    fn test_highest_tier_wins() {
        // Contains both SSN (T4) and "confidential" (T3) — T4 should win.
        assert_eq!(
            ClipboardClassifier::classify("Confidential SSN: 123-45-6789"),
            Classification::T4,
        );
    }

    #[test]
    fn test_ssn_pattern_not_false_positive() {
        // Should not match: too few digits.
        assert!(!contains_ssn_pattern("12-34-5678"));
        // Should not match: no separator pattern.
        assert!(!contains_ssn_pattern("123456789"));
    }

    #[test]
    fn test_cc_pattern_not_false_positive() {
        // 15 digits should not trigger.
        assert!(!contains_credit_card_pattern("123456789012345"));
    }
}
