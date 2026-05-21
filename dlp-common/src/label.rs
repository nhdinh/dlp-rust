//! Label types for the DLP Label Service.
//!
//! Defines the core data model for file/folder labels including:
//! - `LabelState` — lifecycle state of a label (temporary, confirmed, rejected, expired)
//! - `ObjectType` — kind of filesystem object (file, folder, archive)
//! - `Tier` — data sensitivity tier with an unclassified-blocked fallback
//! - `Label` — the full label record struct
//!
//! These types are shared between the server (API, service layer) and
//! any consumers that need to reason about labeled data.

use serde::{Deserialize, Serialize};

use crate::Classification;

/// Lifecycle state of a label.
///
/// A label starts as `Temporary` (e.g. auto-assigned by scanner),
/// and transitions to `Confirmed` or `Rejected` via Data Owner review.
/// `Expired` is set when a time-bounded approval lapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LabelState {
    /// Auto-assigned or pending Data Owner review.
    Temporary,
    /// Data Owner has accepted the label.
    Confirmed,
    /// Data Owner has rejected the label.
    Rejected,
    /// Time-bounded approval has lapsed.
    Expired,
}

impl std::fmt::Display for LabelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Temporary => "temporary",
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        };
        write!(f, "{s}")
    }
}

/// Error returned when parsing an invalid `LabelState` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid label state: {0}")]
pub struct LabelStateError(pub String);

impl TryFrom<&str> for LabelState {
    type Error = LabelStateError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "temporary" => Ok(Self::Temporary),
            "confirmed" => Ok(Self::Confirmed),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            other => Err(LabelStateError(other.to_string())),
        }
    }
}

/// Kind of filesystem object being labeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectType {
    /// Regular file.
    File,
    /// Directory / folder.
    Folder,
    /// Compressed archive (zip, 7z, etc.).
    Archive,
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::File => "file",
            Self::Folder => "folder",
            Self::Archive => "archive",
        };
        write!(f, "{s}")
    }
}

/// Error returned when parsing an invalid `ObjectType` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid object type: {0}")]
pub struct ObjectTypeError(pub String);

impl TryFrom<&str> for ObjectType {
    type Error = ObjectTypeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "file" => Ok(Self::File),
            "folder" => Ok(Self::Folder),
            "archive" => Ok(Self::Archive),
            other => Err(ObjectTypeError(other.to_string())),
        }
    }
}

/// Data sensitivity tier including an unclassified-blocked fallback.
///
/// T1..T4 map directly to [`Classification`]. `UnclassifiedBlocked`
/// is the default-deny fallback when no label is found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Public — lowest sensitivity.
    T1,
    /// Internal — moderate sensitivity.
    T2,
    /// Confidential — high sensitivity.
    T3,
    /// Restricted — highest sensitivity.
    T4,
    /// Default-deny fallback when no label matches.
    #[serde(rename = "Unclassified-Blocked")]
    UnclassifiedBlocked,
}

impl Tier {
    /// Constructs a `Tier` from a [`Classification`].
    #[must_use]
    pub fn from_classification(c: Classification) -> Self {
        match c {
            Classification::T1 => Self::T1,
            Classification::T2 => Self::T2,
            Classification::T3 => Self::T3,
            Classification::T4 => Self::T4,
        }
    }

    /// Converts this tier back to a [`Classification`], if applicable.
    ///
    /// Returns `None` for `UnclassifiedBlocked`.
    #[must_use]
    pub fn to_classification(self) -> Option<Classification> {
        match self {
            Self::T1 => Some(Classification::T1),
            Self::T2 => Some(Classification::T2),
            Self::T3 => Some(Classification::T3),
            Self::T4 => Some(Classification::T4),
            Self::UnclassifiedBlocked => None,
        }
    }

    /// Returns `true` if this tier is considered sensitive.
    ///
    /// T3, T4, and `UnclassifiedBlocked` are all treated as sensitive
    /// for enforcement purposes (fail-closed semantics).
    #[must_use]
    pub fn is_sensitive(self) -> bool {
        matches!(self, Self::T3 | Self::T4 | Self::UnclassifiedBlocked)
    }

    /// Returns a numeric rank where higher values indicate stricter tiers.
    ///
    /// The ordering is: T1 (1) < T2 (2) < T3 (3) < T4 (4) < UnclassifiedBlocked (5).
    /// This rank is used for strictness comparison during folder inheritance
    /// resolution (explicit child tier vs. inherited parent tier).
    #[must_use]
    pub fn strictness_rank(self) -> u8 {
        match self {
            Self::T1 => 1,
            Self::T2 => 2,
            Self::T3 => 3,
            Self::T4 => 4,
            Self::UnclassifiedBlocked => 5,
        }
    }

    /// Returns `true` if this tier is strictly stricter than `other`.
    ///
    /// Uses [`strictness_rank`](Self::strictness_rank) for comparison.
    #[must_use]
    pub fn is_stricter_than(self, other: &Self) -> bool {
        self.strictness_rank() > other.strictness_rank()
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::T1 => "T1",
            Self::T2 => "T2",
            Self::T3 => "T3",
            Self::T4 => "T4",
            Self::UnclassifiedBlocked => "Unclassified-Blocked",
        };
        write!(f, "{s}")
    }
}

/// Error returned when parsing an invalid `Tier` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid tier: {0}")]
pub struct TierError(pub String);

impl TryFrom<&str> for Tier {
    type Error = TierError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "t1" => Ok(Self::T1),
            "t2" => Ok(Self::T2),
            "t3" => Ok(Self::T3),
            "t4" => Ok(Self::T4),
            "unclassified-blocked" => Ok(Self::UnclassifiedBlocked),
            other => Err(TierError(other.to_string())),
        }
    }
}

/// A label record assigned to a file, folder, or archive.
///
/// Labels are stored in the central SQLite database and resolved at
/// enforcement time via [`LabelService`](dlp_server::label_service::LabelService).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Label {
    /// UUID string identifying the label.
    pub id: String,
    /// Filesystem or SMB path of the labeled object.
    pub path: String,
    /// Kind of object being labeled.
    pub object_type: ObjectType,
    /// Data sensitivity tier.
    pub tier: Tier,
    /// Lifecycle state of the label.
    pub label_state: LabelState,
    /// SID of the Data Owner (from AD Manager attribute).
    pub owner_sid: Option<String>,
    /// FK to parent folder label for inheritance.
    pub parent_label_id: Option<String>,
    /// Reference to ACL snapshot at label time.
    pub acl_snapshot_id: Option<String>,
    /// SHA-256 hash of file content when labeled.
    pub hash: Option<String>,
    /// Scanner confidence score (0.0-1.0), nullable.
    pub scanner_confidence: Option<f32>,
    /// ISO-8601 timestamp of creation.
    pub created_at: String,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_state_serde_round_trip() {
        let state = LabelState::Temporary;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"temporary\"");
        let round_trip: LabelState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, round_trip);
    }

    #[test]
    fn test_object_type_display_and_parse() {
        assert_eq!(ObjectType::Folder.to_string(), "folder");
        let parsed: ObjectType = "folder".try_into().unwrap();
        assert_eq!(parsed, ObjectType::Folder);
    }

    #[test]
    fn test_tier_classification_conversion() {
        assert_eq!(Tier::T3.to_classification(), Some(Classification::T3));
        assert_eq!(Tier::UnclassifiedBlocked.to_classification(), None);
    }

    #[test]
    fn test_label_serde_round_trip() {
        let label = Label {
            id: "label-001".to_string(),
            path: r"C:\Data\file.txt".to_string(),
            object_type: ObjectType::File,
            tier: Tier::T3,
            label_state: LabelState::Confirmed,
            owner_sid: Some("S-1-5-21-1".to_string()),
            parent_label_id: Some("parent-001".to_string()),
            acl_snapshot_id: Some("acl-001".to_string()),
            hash: Some("sha256-abc".to_string()),
            scanner_confidence: Some(0.85),
            created_at: "2026-05-12T00:00:00Z".to_string(),
            updated_at: "2026-05-12T01:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&label).unwrap();
        let round_trip: Label = serde_json::from_str(&json).unwrap();
        assert_eq!(label, round_trip);
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(Tier::T1.to_string(), "T1");
        assert_eq!(Tier::T2.to_string(), "T2");
        assert_eq!(Tier::T3.to_string(), "T3");
        assert_eq!(Tier::T4.to_string(), "T4");
        assert_eq!(
            Tier::UnclassifiedBlocked.to_string(),
            "Unclassified-Blocked"
        );
    }

    #[test]
    fn test_label_state_invalid_try_from() {
        let result: Result<LabelState, _> = "invalid".try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_tier_from_classification() {
        assert_eq!(Tier::from_classification(Classification::T1), Tier::T1);
        assert_eq!(Tier::from_classification(Classification::T2), Tier::T2);
        assert_eq!(Tier::from_classification(Classification::T3), Tier::T3);
        assert_eq!(Tier::from_classification(Classification::T4), Tier::T4);
    }

    #[test]
    fn test_tier_is_sensitive() {
        assert!(!Tier::T1.is_sensitive());
        assert!(!Tier::T2.is_sensitive());
        assert!(Tier::T3.is_sensitive());
        assert!(Tier::T4.is_sensitive());
        assert!(Tier::UnclassifiedBlocked.is_sensitive());
    }

    #[test]
    fn test_object_type_try_from_case_insensitive() {
        let upper: ObjectType = "FOLDER".try_into().unwrap();
        assert_eq!(upper, ObjectType::Folder);
        let mixed: ObjectType = "FiLe".try_into().unwrap();
        assert_eq!(mixed, ObjectType::File);
    }

    #[test]
    fn test_tier_try_from_case_insensitive() {
        let upper: Tier = "T3".try_into().unwrap();
        assert_eq!(upper, Tier::T3);
        let lower: Tier = "unclassified-blocked".try_into().unwrap();
        assert_eq!(lower, Tier::UnclassifiedBlocked);
    }

    #[test]
    fn test_tier_strictness_rank() {
        assert_eq!(Tier::T1.strictness_rank(), 1);
        assert_eq!(Tier::T2.strictness_rank(), 2);
        assert_eq!(Tier::T3.strictness_rank(), 3);
        assert_eq!(Tier::T4.strictness_rank(), 4);
        assert_eq!(Tier::UnclassifiedBlocked.strictness_rank(), 5);
    }

    #[test]
    fn test_tier_is_stricter_than() {
        assert!(Tier::T4.is_stricter_than(&Tier::T2));
        assert!(Tier::T3.is_stricter_than(&Tier::T1));
        assert!(Tier::UnclassifiedBlocked.is_stricter_than(&Tier::T4));
        assert!(!Tier::T1.is_stricter_than(&Tier::T2));
        assert!(!Tier::T2.is_stricter_than(&Tier::T2));
        assert!(!Tier::T4.is_stricter_than(&Tier::UnclassifiedBlocked));
    }
}
