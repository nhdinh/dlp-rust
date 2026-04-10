//! Text content classifier.
//!
//! Assigns a provisional [`Classification`] tier to text content based on
//! pattern matching.  Patterns detect common sensitive data formats:
//!
//! - **T4 (Restricted)**: Social Security numbers, credit card numbers
//! - **T3 (Confidential)**: keywords like "CONFIDENTIAL", "SECRET"
//! - **T2 (Internal)**: keywords like "INTERNAL", "DO NOT DISTRIBUTE"
//! - **T1 (Public)**: anything that does not match a higher tier
//!
//! This classifier is shared between `dlp-agent` and `dlp-user-ui` so
//! both can classify content locally without a network round-trip.

use crate::Classification;

/// Keyword rules ordered from highest to lowest sensitivity.
const KEYWORD_RULES: &[(&str, Classification)] = &[
    ("confidential", Classification::T3),
    ("secret", Classification::T3),
    ("top secret", Classification::T3),
    ("internal only", Classification::T2),
    ("do not distribute", Classification::T2),
    ("internal use", Classification::T2),
];

/// Classifies text content into a sensitivity tier.
///
/// Returns the highest matching tier, or `Classification::T1` (Public)
/// if no sensitive patterns match.
///
/// # Examples
///
/// ```
/// use dlp_common::{Classification, classify_text};
///
/// assert_eq!(classify_text("My SSN is 123-45-6789"), Classification::T4);
/// assert_eq!(classify_text("CONFIDENTIAL memo"), Classification::T3);
/// assert_eq!(classify_text("Hello world"), Classification::T1);
/// ```
#[must_use]
pub fn classify_text(text: &str) -> Classification {
    // Structured data patterns first (highest sensitivity).
    if contains_ssn_pattern(text) {
        return Classification::T4;
    }
    if contains_credit_card_pattern(text) {
        return Classification::T4;
    }

    // Keyword rules in priority order.
    let lower = text.to_lowercase();
    for &(keyword, tier) in KEYWORD_RULES {
        if lower.contains(keyword) {
            return tier;
        }
    }

    Classification::T1
}

/// Returns `true` if the text contains a pattern matching SSN format
/// (3 digits, separator, 2 digits, separator, 4 digits).
fn contains_ssn_pattern(text: &str) -> bool {
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
    let chars: Vec<char> = text.chars().collect();

    // Formatted: XXXX-XXXX-XXXX-XXXX or XXXX XXXX XXXX XXXX
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

    // Raw 16-digit sequence.
    let mut consecutive = 0u32;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            consecutive += 1;
            if consecutive >= 16 {
                return true;
            }
        } else {
            consecutive = 0;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_ssn() {
        assert_eq!(classify_text("My SSN is 123-45-6789"), Classification::T4);
    }

    #[test]
    fn test_classify_ssn_spaces() {
        assert_eq!(classify_text("SSN: 123 45 6789"), Classification::T4);
    }

    #[test]
    fn test_classify_credit_card_dashes() {
        assert_eq!(
            classify_text("Card: 4111-1111-1111-1111"),
            Classification::T4
        );
    }

    #[test]
    fn test_classify_credit_card_raw() {
        assert_eq!(classify_text("4111111111111111"), Classification::T4);
    }

    #[test]
    fn test_classify_confidential() {
        assert_eq!(classify_text("This is CONFIDENTIAL"), Classification::T3);
    }

    #[test]
    fn test_classify_internal() {
        assert_eq!(classify_text("For internal only use"), Classification::T2);
    }

    #[test]
    fn test_classify_public() {
        assert_eq!(classify_text("Hello world"), Classification::T1);
    }

    #[test]
    fn test_classify_empty() {
        assert_eq!(classify_text(""), Classification::T1);
    }

    #[test]
    fn test_highest_tier_wins() {
        assert_eq!(
            classify_text("Confidential SSN: 123-45-6789"),
            Classification::T4,
        );
    }
}
