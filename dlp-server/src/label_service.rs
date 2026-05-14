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

/// In-memory cache for label resolution results.
///
/// Stores `(path -> (tier, inserted_at))` with a configurable TTL.
/// Uses `std::sync::RwLock` for concurrent read-heavy access.
pub struct LabelCache {
    inner: std::sync::RwLock<HashMap<String, (Tier, Instant)>>,
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

    /// Returns the cached tier for `path` if present and not expired.
    pub fn get(&self, path: &str) -> Option<Tier> {
        let read_guard = self.inner.read().ok()?;
        let (tier, inserted) = read_guard.get(path)?;
        if inserted.elapsed() < self.ttl {
            Some(*tier)
        } else {
            None
        }
    }

    /// Stores `tier` for `path` with the current timestamp.
    pub fn insert(&self, path: String, tier: Tier) {
        if let Ok(mut write_guard) = self.inner.write() {
            write_guard.insert(path, (tier, Instant::now()));
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
        if let Some(tier) = self.cache.get(path) {
            return Ok(tier);
        }

        // 2. Exact match in DB.
        if let Some(row) = LabelRepository::get_by_path(&self.pool, path)? {
            let tier = parse_tier(&row.tier);
            self.cache.insert(path.to_string(), tier);
            return Ok(tier);
        }

        // 3. Parent folder walk.
        if let Some(parent) = LabelRepository::find_parent_label(&self.pool, path)? {
            let tier = parse_tier(&parent.tier);
            self.cache.insert(path.to_string(), tier);
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
