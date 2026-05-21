//! Label resolution service with TTL caching and folder inheritance.
//!
//! [`LabelService`] resolves the data sensitivity [`Tier`] for any filesystem
//! path using three strategies in order:
//!
//! 1. **Exact match** — the path itself has a label in the database.
//! 2. **Parent folder walk** — walk up the directory tree until a labeled
//!    folder is found.
//! 3. **Fallback** — return [`Tier::UnclassifiedBlocked`] (default-deny).
//!
//! Results are cached with a 30-second TTL to avoid repeated DB queries
//! during high-frequency enforcement. The cache is invalidated on all
//! CRUD operations (admin endpoints call [`LabelService::invalidate_cache`]).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dlp_common::Tier;

use crate::db::repositories::labels::LabelRepository;
use crate::db::Pool;

/// Source of a label resolution result.
///
/// Tracks whether the tier came from an exact path match, inherited from
/// a parent folder, fell back to the default, or failed to resolve.
/// Used for audit logging and cache metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionSource {
    /// The path itself has an explicit label in the database.
    Exact,
    /// The tier was inherited from a parent folder label.
    Inherited,
    /// No label found; defaulted to [`Tier::UnclassifiedBlocked`].
    Fallback,
    /// Database query failed; fail-closed to [`Tier::UnclassifiedBlocked`].
    LookupFailed,
}

/// A resolved tier with source metadata.
///
/// Unlike a bare [`Tier`], `ResolvedTier` preserves the provenance of the
/// resolution decision. This is critical for:
/// - Audit trails (was this exact or inherited?)
/// - Folder inheritance (stricter parent wins over explicit child)
/// - Fail-closed semantics (distinguish fallback from lookup failure)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTier {
    /// Exact path match — the path itself has a label.
    Exact(Tier),
    /// Inherited from a parent folder.
    Inherited {
        /// The effective tier (the stricter of explicit or parent).
        tier: Tier,
        /// Path of the parent folder that provided the inherited label.
        parent_path: String,
    },
    /// No label found; default-deny fallback.
    Fallback,
    /// Database error; fail-closed.
    LookupFailed,
}

impl ResolvedTier {
    /// Returns the effective [`Tier`] regardless of source.
    ///
    /// For [`Fallback`](Self::Fallback) and [`LookupFailed`](Self::LookupFailed),
    /// returns [`Tier::UnclassifiedBlocked`].
    #[must_use]
    pub fn tier(&self) -> Tier {
        match self {
            Self::Exact(t) | Self::Inherited { tier: t, .. } => *t,
            Self::Fallback | Self::LookupFailed => Tier::UnclassifiedBlocked,
        }
    }

    /// Returns the source category as a static string for logging/audit.
    #[must_use]
    pub fn source(&self) -> &'static str {
        match self {
            Self::Exact(_) => "exact",
            Self::Inherited { .. } => "inherited",
            Self::Fallback => "fallback",
            Self::LookupFailed => "lookup_failed",
        }
    }

    /// Returns `true` if the resolution came from inheritance.
    #[must_use]
    pub fn is_inherited(&self) -> bool {
        matches!(self, Self::Inherited { .. })
    }
}

/// A single cache entry storing resolution metadata.
///
/// Stores the effective tier, how it was resolved, and optionally the
/// parent path (for inherited results). The `inserted` timestamp drives
/// TTL eviction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// The effective data sensitivity tier.
    pub tier: Tier,
    /// How this tier was resolved.
    pub source: ResolutionSource,
    /// Parent folder path, if the tier was inherited.
    pub parent_path: Option<String>,
    /// When this entry was inserted (for TTL calculation).
    pub inserted: Instant,
}

/// In-memory cache for label resolution results.
///
/// Stores `(path -> CacheEntry)` with a configurable TTL.
/// Uses `std::sync::RwLock` for concurrent read-heavy access.
pub struct LabelCache {
    inner: std::sync::RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl LabelCache {
    /// Creates a new cache with the given TTL.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: std::sync::RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Returns the cached [`CacheEntry`] for `path` if present and not expired.
    pub fn get(&self, path: &str) -> Option<CacheEntry> {
        let read_guard = self.inner.read().ok()?;
        let entry = read_guard.get(path)?;
        if entry.inserted.elapsed() < self.ttl {
            Some(entry.clone())
        } else {
            None
        }
    }

    /// Returns just the effective [`Tier`] for `path` if cached and not expired.
    pub fn get_tier(&self, path: &str) -> Option<Tier> {
        self.get(path).map(|e| e.tier)
    }

    /// Stores a [`CacheEntry`] for `path`.
    pub fn insert(&self, path: String, entry: CacheEntry) {
        if let Ok(mut write_guard) = self.inner.write() {
            write_guard.insert(path, entry);
        }
    }

    /// Clears all cached entries.
    pub fn invalidate(&self) {
        if let Ok(mut write_guard) = self.inner.write() {
            write_guard.clear();
        }
    }
}

/// Resolves the data sensitivity tier for filesystem paths.
///
/// Resolution order (per D-07):
/// 1. Check cache for exact path match.
/// 2. Query DB for exact path match.
/// 3. Query DB for nearest parent folder label.
/// 4. Return [`Tier::UnclassifiedBlocked`] if nothing found.
pub struct LabelService {
    pool: Arc<Pool>,
    cache: LabelCache,
}

impl LabelService {
    /// Creates a new `LabelService` with a 30-second TTL cache.
    #[must_use]
    pub fn new(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            cache: LabelCache::new(Duration::from_secs(30)),
        }
    }

    /// Resolves the tier for `path`.
    ///
    /// # Errors
    ///
    /// Returns `rusqlite::Error` on database failure.
    pub fn resolve_tier(&self, path: &str) -> rusqlite::Result<Tier> {
        // 1. Cache hit?
        if let Some(tier) = self.cache.get_tier(path) {
            return Ok(tier);
        }

        // 2. Exact match in DB.
        if let Some(row) = LabelRepository::get_by_path(&self.pool, path)? {
            let tier = parse_tier(&row.tier);
            self.cache.insert(
                path.to_string(),
                CacheEntry {
                    tier,
                    source: ResolutionSource::Exact,
                    parent_path: None,
                    inserted: Instant::now(),
                },
            );
            return Ok(tier);
        }

        // 3. Parent folder walk.
        if let Some(parent) = LabelRepository::find_parent_label(&self.pool, path)? {
            let tier = parse_tier(&parent.tier);
            self.cache.insert(
                path.to_string(),
                CacheEntry {
                    tier,
                    source: ResolutionSource::Inherited,
                    parent_path: Some(parent.path),
                    inserted: Instant::now(),
                },
            );
            return Ok(tier);
        }

        // 4. Fallback.
        Ok(Tier::UnclassifiedBlocked)
    }

    /// Invalidates the entire resolution cache.
    ///
    /// Call this after any label CRUD operation.
    pub fn invalidate_cache(&self) {
        self.cache.invalidate();
    }
}

/// Parses a tier string from the database into a [`Tier`].
///
/// Falls back to `UnclassifiedBlocked` on unrecognized values
/// (defense-in-depth: never panic on bad DB data).
fn parse_tier(s: &str) -> Tier {
    <Tier as std::convert::TryFrom<&str>>::try_from(s).unwrap_or(Tier::UnclassifiedBlocked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;
    use crate::db::repositories::labels::{LabelRepository, LabelUpsertRow};
    use crate::db::UnitOfWork;

    #[test]
    fn test_resolved_tier_exact() {
        let rt = ResolvedTier::Exact(Tier::T3);
        assert_eq!(rt.tier(), Tier::T3);
        assert_eq!(rt.source(), "exact");
        assert!(!rt.is_inherited());
    }

    #[test]
    fn test_resolved_tier_inherited() {
        let rt = ResolvedTier::Inherited {
            tier: Tier::T4,
            parent_path: r"C:\Data".to_string(),
        };
        assert_eq!(rt.tier(), Tier::T4);
        assert_eq!(rt.source(), "inherited");
        assert!(rt.is_inherited());
    }

    #[test]
    fn test_resolved_tier_fallback() {
        let rt = ResolvedTier::Fallback;
        assert_eq!(rt.tier(), Tier::UnclassifiedBlocked);
        assert_eq!(rt.source(), "fallback");
        assert!(!rt.is_inherited());
    }

    #[test]
    fn test_resolved_tier_lookup_failed() {
        let rt = ResolvedTier::LookupFailed;
        assert_eq!(rt.tier(), Tier::UnclassifiedBlocked);
        assert_eq!(rt.source(), "lookup_failed");
        assert!(!rt.is_inherited());
    }

    #[test]
    fn test_cache_entry_round_trip() {
        let entry = CacheEntry {
            tier: Tier::T3,
            source: ResolutionSource::Exact,
            parent_path: None,
            inserted: Instant::now(),
        };
        assert_eq!(entry.tier, Tier::T3);
        assert_eq!(entry.source, ResolutionSource::Exact);
        assert!(entry.parent_path.is_none());
    }

    #[test]
    fn test_label_cache_get_tier() {
        let cache = LabelCache::new(Duration::from_secs(30));
        let entry = CacheEntry {
            tier: Tier::T2,
            source: ResolutionSource::Inherited,
            parent_path: Some(r"C:\Data".to_string()),
            inserted: Instant::now(),
        };
        cache.insert(r"C:\Data\file.txt".to_string(), entry);

        assert_eq!(cache.get_tier(r"C:\Data\file.txt"), Some(Tier::T2));

        let full = cache.get(r"C:\Data\file.txt").expect("cache hit");
        assert_eq!(full.source, ResolutionSource::Inherited);
        assert_eq!(full.parent_path, Some(r"C:\Data".to_string()));
    }

    #[test]
    fn test_label_cache_entry_expires() {
        let cache = LabelCache::new(Duration::from_secs(0));
        let entry = CacheEntry {
            tier: Tier::T4,
            source: ResolutionSource::Exact,
            parent_path: None,
            inserted: Instant::now(),
        };
        cache.insert(r"C:\Data\file.txt".to_string(), entry);

        // Zero TTL means entry expires immediately
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get(r"C:\Data\file.txt").is_none());
    }

    #[test]
    fn test_resolve_tier_exact_match() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        // Insert a file label
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "file-001",
                    path: r"C:\Data\file.txt",
                    object_type: "file",
                    tier: "T3",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        let tier = svc.resolve_tier(r"C:\Data\file.txt").expect("resolve");
        assert_eq!(tier, Tier::T3);
    }

    #[test]
    fn test_resolve_tier_parent_folder() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        // Insert a folder label
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "folder-001",
                    path: r"C:\Data\HR",
                    object_type: "folder",
                    tier: "T4",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        // Child file has no exact label, should inherit from parent folder
        let tier = svc
            .resolve_tier(r"C:\Data\HR\salary.xlsx")
            .expect("resolve");
        assert_eq!(tier, Tier::T4);
    }

    #[test]
    fn test_resolve_tier_unclassified_blocked_fallback() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        // No labels at all
        let tier = svc.resolve_tier(r"C:\Unknown\file.txt").expect("resolve");
        assert_eq!(tier, Tier::UnclassifiedBlocked);
    }

    #[test]
    fn test_cache_hit_avoids_db_query() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        // Insert a label
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "file-001",
                    path: r"C:\Data\file.txt",
                    object_type: "file",
                    tier: "T2",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        // First call hits DB and populates cache
        let tier1 = svc
            .resolve_tier(r"C:\Data\file.txt")
            .expect("resolve first");
        assert_eq!(tier1, Tier::T2);

        // Second call should hit cache
        let tier2 = svc
            .resolve_tier(r"C:\Data\file.txt")
            .expect("resolve second");
        assert_eq!(tier2, Tier::T2);
    }

    #[test]
    fn test_invalidate_cache_clears_entries() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        // Insert and resolve to populate cache
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "file-001",
                    path: r"C:\Data\file.txt",
                    object_type: "file",
                    tier: "T1",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        svc.resolve_tier(r"C:\Data\file.txt").expect("resolve");

        // Invalidate cache
        svc.invalidate_cache();

        // Cache is empty; next resolve still works (re-queries DB)
        let tier = svc
            .resolve_tier(r"C:\Data\file.txt")
            .expect("resolve after invalidate");
        assert_eq!(tier, Tier::T1);
    }

    #[test]
    fn test_cache_entry_expires_after_ttl() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        // Use a zero TTL so entries expire immediately
        let svc = LabelService {
            pool: Arc::clone(&pool),
            cache: LabelCache::new(Duration::from_secs(0)),
        };

        // Insert a label
        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "file-001",
                    path: r"C:\Data\file.txt",
                    object_type: "file",
                    tier: "T3",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: None,
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert");
            uow.commit().expect("commit");
        }

        // First call
        let tier1 = svc
            .resolve_tier(r"C:\Data\file.txt")
            .expect("resolve first");
        assert_eq!(tier1, Tier::T3);

        // Wait a tiny bit for the zero-TTL entry to expire
        std::thread::sleep(Duration::from_millis(10));

        // Second call should miss cache (expired) and re-query DB
        let tier2 = svc
            .resolve_tier(r"C:\Data\file.txt")
            .expect("resolve second");
        assert_eq!(tier2, Tier::T3);
    }
}
