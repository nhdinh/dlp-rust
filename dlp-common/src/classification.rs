//! Data classification types — the four-tier sensitivity model.
//!
//! | Tier | Name         | Description                    |
//! | ---- | ------------ | ------------------------------ |
//! | T4   | Restricted   | Highest sensitivity            |
//! | T3   | Confidential | High sensitivity               |
//! | T2   | Internal     | Moderate sensitivity           |
//! | T1   | Public       | Low sensitivity               |

use serde::{Deserialize, Serialize};

/// Four-tier data sensitivity classification.
///
/// T4 (Restricted) represents the highest sensitivity — catastrophic impact if disclosed.
/// T1 (Public) represents the lowest sensitivity — no harm if disclosed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Classification {
    /// Low sensitivity — no harm if disclosed.
    #[default]
    T1,
    /// Moderate sensitivity — internal use only.
    T2,
    /// High sensitivity — serious impact if disclosed.
    T3,
    /// Highest sensitivity — catastrophic impact if disclosed.
    T4,
}

impl Classification {
    /// Returns `true` if this classification level requires fail-closed behavior
    /// (deny on cache miss in offline mode).
    #[must_use]
    pub fn is_sensitive(self) -> bool {
        matches!(self, Self::T3 | Self::T4)
    }

    /// Returns the human-readable label for this classification.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::T1 => "Public",
            Self::T2 => "Internal",
            Self::T3 => "Confidential",
            Self::T4 => "Restricted",
        }
    }
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification_order() {
        assert!(Classification::T1 < Classification::T2);
        assert!(Classification::T2 < Classification::T3);
        assert!(Classification::T3 < Classification::T4);
    }

    #[test]
    fn test_is_sensitive() {
        assert!(!Classification::T1.is_sensitive());
        assert!(!Classification::T2.is_sensitive());
        assert!(Classification::T3.is_sensitive());
        assert!(Classification::T4.is_sensitive());
    }

    #[test]
    fn test_labels() {
        assert_eq!(Classification::T1.label(), "Public");
        assert_eq!(Classification::T2.label(), "Internal");
        assert_eq!(Classification::T3.label(), "Confidential");
        assert_eq!(Classification::T4.label(), "Restricted");
    }

    #[test]
    fn test_default_is_t1() {
        assert_eq!(Classification::default(), Classification::T1);
    }

    #[test]
    fn test_serde_round_trip() {
        for cls in [
            Classification::T1,
            Classification::T2,
            Classification::T3,
            Classification::T4,
        ] {
            let json = serde_json::to_string(&cls).unwrap();
            let round_trip: Classification = serde_json::from_str(&json).unwrap();
            assert_eq!(cls, round_trip);
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(Classification::T1.to_string(), "Public");
        assert_eq!(Classification::T4.to_string(), "Restricted");
    }
}
