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

use crate::audit_store;
use crate::db::repositories::labels::LabelRepository;
use crate::db::{Pool, UnitOfWork};
use crate::AppError;

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

    /// Resolves the tier for `path` with strictness-aware inheritance.
    ///
    /// Resolution logic (per D-07b):
    /// 1. Check cache for a [`CacheEntry`]. If hit and not expired, convert to
    ///    [`ResolvedTier`] and return.
    /// 2. Query DB for exact path match AND parent folder label (both queries
    ///    always run, not conditionally).
    /// 3. If both exist: compare strictness using [`Tier::strictness_rank`].
    ///    - If explicit tier is stricter or equal: [`ResolvedTier::Exact`]
    ///    - If parent tier is stricter: [`ResolvedTier::Inherited`]
    /// 4. If only exact exists: [`ResolvedTier::Exact`]
    /// 5. If only parent exists: [`ResolvedTier::Inherited`]
    /// 6. If neither: [`ResolvedTier::Fallback`]
    /// 7. On DB error: [`ResolvedTier::LookupFailed`] (fail-closed, no panic)
    ///
    /// The result is cached as a [`CacheEntry`] with correct [`ResolutionSource`]
    /// and `parent_path` metadata.
    pub fn resolve_tier(&self, path: &str) -> ResolvedTier {
        // 1. Cache hit?
        if let Some(entry) = self.cache.get(path) {
            return cache_entry_to_resolved(entry);
        }

        // 2. Query DB for both exact and parent labels.
        let exact = match LabelRepository::get_by_path(&self.pool, path) {
            Ok(row) => row,
            Err(_e) => {
                // Fail-closed: DB error -> LookupFailed (UnclassifiedBlocked)
                return ResolvedTier::LookupFailed;
            }
        };
        let parent = match LabelRepository::find_parent_label(&self.pool, path) {
            Ok(row) => row,
            Err(_e) => {
                return ResolvedTier::LookupFailed;
            }
        };

        // 3. Both exist -> strictness comparison (D-07b)
        let result = match (&exact, &parent) {
            (Some(ex), Some(par)) => {
                let explicit_tier = parse_tier(&ex.tier);
                let parent_tier = parse_tier(&par.tier);
                if explicit_tier.is_stricter_than(&parent_tier)
                    || explicit_tier.strictness_rank() == parent_tier.strictness_rank()
                {
                    ResolvedTier::Exact(explicit_tier)
                } else {
                    ResolvedTier::Inherited {
                        tier: parent_tier,
                        parent_path: par.path.clone(),
                    }
                }
            }
            (Some(ex), None) => ResolvedTier::Exact(parse_tier(&ex.tier)),
            (None, Some(par)) => ResolvedTier::Inherited {
                tier: parse_tier(&par.tier),
                parent_path: par.path.clone(),
            },
            (None, None) => ResolvedTier::Fallback,
        };

        // 4. Cache the result with full metadata.
        let cache_entry = resolved_to_cache_entry(&result);
        self.cache.insert(path.to_string(), cache_entry);

        result
    }

    /// Invalidates the entire resolution cache.
    ///
    /// Call this after any label CRUD operation.
    pub fn invalidate_cache(&self) {
        self.cache.invalidate();
    }

    /// Executes a label mutation with transactional audit and cache invalidation.
    ///
    /// This is the **mandatory** path for all label-mutating admin operations.
    /// It guarantees:
    /// 1. The mutation closure runs inside a single SQLite transaction.
    /// 2. An audit event is emitted inside the **same** transaction — if audit
    ///    insertion fails, the entire transaction rolls back (fail-closed per D-14).
    /// 3. The cache is invalidated **after** successful commit.
    ///
    /// # Type Parameters
    ///
    /// * `T` — The return type of the mutation closure.
    /// * `F` — The mutation closure type.
    ///
    /// # Arguments
    ///
    /// * `ctx` — [`MutationContext`] carrying audit metadata.
    /// * `mutation` — Closure that receives a [`UnitOfWork`] and performs the DB mutation.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Database` if the transaction fails to commit.
    /// Returns `AppError::Internal` if audit event serialization fails.
    pub fn with_mutation<T, F>(&self, ctx: MutationContext, mutation: F) -> Result<T, AppError>
    where
        F: FnOnce(&UnitOfWork) -> Result<T, AppError>,
    {
        let mut conn = self.pool.get().map_err(AppError::from)?;
        let uow = UnitOfWork::new(&mut conn).map_err(AppError::Database)?;

        // Run the mutation first
        let result = mutation(&uow)?;

        // Build and emit audit event inside the same transaction
        let audit_event = ctx.to_audit_event();
        audit_store::store_events_sync(&uow, &[audit_event])?;

        // Commit — both mutation and audit atomically
        uow.commit().map_err(AppError::Database)?;

        // Invalidate cache after successful commit
        self.invalidate_cache();

        Ok(result)
    }
}

/// Context for a label mutation, used to construct the mandatory audit event.
///
/// Carries all metadata needed to build an [`AuditEvent`] inside the same
/// transaction as the mutation. All fields are required per D-14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationContext {
    /// The label ID being mutated.
    pub label_id: String,
    /// The action name (maps to [`dlp_common::Action`] variant).
    pub action: String,
    /// Previous label state, if applicable.
    pub old_state: Option<String>,
    /// New label state, if applicable.
    pub new_state: Option<String>,
    /// The filesystem path of the labeled resource.
    pub path: String,
    /// The classification tier string (e.g., "T3").
    pub tier: String,
    /// The username performing the action (from JWT or "admin").
    pub user_name: String,
}

impl MutationContext {
    /// Converts this context into an [`AuditEvent`] for storage.
    ///
    /// The action string is matched against known [`Action`] variants.
    /// Unrecognized actions fall back to [`Action::LabelUpdate`] (defense-in-depth).
    fn to_audit_event(&self) -> dlp_common::AuditEvent {
        let action = match self.action.as_str() {
            "label_create" => dlp_common::Action::LabelCreate,
            "label_update" => dlp_common::Action::LabelUpdate,
            "label_confirm" => dlp_common::Action::LabelConfirm,
            "label_reject" => dlp_common::Action::LabelReject,
            "label_delete" => dlp_common::Action::LabelDelete,
            "label_expire" => dlp_common::Action::LabelExpire,
            _ => dlp_common::Action::LabelUpdate,
        };

        let classification = <Tier as std::convert::TryFrom<&str>>::try_from(&self.tier)
            .unwrap_or(Tier::UnclassifiedBlocked)
            .to_classification()
            .unwrap_or(dlp_common::Classification::T3);

        let resource = if let (Some(ref old), Some(ref new)) = (&self.old_state, &self.new_state) {
            format!(
                "label:{} at {} ({} -> {})",
                self.label_id, self.path, old, new
            )
        } else if let Some(ref new) = self.new_state {
            format!("label:{} at {} ({})", self.label_id, self.path, new)
        } else if let Some(ref old) = self.old_state {
            format!("label:{} at {} (was {})", self.label_id, self.path, old)
        } else {
            format!("label:{} at {}", self.label_id, self.path)
        };

        dlp_common::AuditEvent::new(
            dlp_common::EventType::AdminAction,
            String::new(),
            self.user_name.clone(),
            resource,
            classification,
            action,
            dlp_common::Decision::ALLOW,
            "server".to_string(),
            0,
        )
    }
}

/// Parses a tier string from the database into a [`Tier`].
///
/// Falls back to `UnclassifiedBlocked` on unrecognized values
/// (defense-in-depth: never panic on bad DB data).
fn parse_tier(s: &str) -> Tier {
    <Tier as std::convert::TryFrom<&str>>::try_from(s).unwrap_or(Tier::UnclassifiedBlocked)
}

/// Converts a [`CacheEntry`] back to a [`ResolvedTier`].
///
/// This is used on cache hits to reconstruct the full resolution result
/// from the cached metadata.
fn cache_entry_to_resolved(entry: CacheEntry) -> ResolvedTier {
    match entry.source {
        ResolutionSource::Exact => ResolvedTier::Exact(entry.tier),
        ResolutionSource::Inherited => ResolvedTier::Inherited {
            tier: entry.tier,
            parent_path: entry.parent_path.unwrap_or_default(),
        },
        ResolutionSource::Fallback => ResolvedTier::Fallback,
        ResolutionSource::LookupFailed => ResolvedTier::LookupFailed,
    }
}

/// Converts a [`ResolvedTier`] into a [`CacheEntry`] for storage.
fn resolved_to_cache_entry(resolved: &ResolvedTier) -> CacheEntry {
    match resolved {
        ResolvedTier::Exact(tier) => CacheEntry {
            tier: *tier,
            source: ResolutionSource::Exact,
            parent_path: None,
            inserted: Instant::now(),
        },
        ResolvedTier::Inherited { tier, parent_path } => CacheEntry {
            tier: *tier,
            source: ResolutionSource::Inherited,
            parent_path: Some(parent_path.clone()),
            inserted: Instant::now(),
        },
        ResolvedTier::Fallback => CacheEntry {
            tier: Tier::UnclassifiedBlocked,
            source: ResolutionSource::Fallback,
            parent_path: None,
            inserted: Instant::now(),
        },
        ResolvedTier::LookupFailed => CacheEntry {
            tier: Tier::UnclassifiedBlocked,
            source: ResolutionSource::LookupFailed,
            parent_path: None,
            inserted: Instant::now(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::new_pool;
    use crate::db::repositories::labels::{LabelRepository, LabelUpsertRow};
    use crate::db::UnitOfWork;
    use crate::AppError;

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

        let resolved = svc.resolve_tier(r"C:\Data\file.txt");
        assert_eq!(resolved.tier(), Tier::T3);
        assert_eq!(resolved.source(), "exact");
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
        let resolved = svc.resolve_tier(r"C:\Data\HR\salary.xlsx");
        assert_eq!(resolved.tier(), Tier::T4);
        assert_eq!(resolved.source(), "inherited");
    }

    #[test]
    fn test_resolve_tier_unclassified_blocked_fallback() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        // No labels at all
        let resolved = svc.resolve_tier(r"C:\Unknown\file.txt");
        assert_eq!(resolved.tier(), Tier::UnclassifiedBlocked);
        assert_eq!(resolved.source(), "fallback");
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
        let resolved1 = svc.resolve_tier(r"C:\Data\file.txt");
        assert_eq!(resolved1.tier(), Tier::T2);
        assert_eq!(resolved1.source(), "exact");

        // Second call should hit cache
        let resolved2 = svc.resolve_tier(r"C:\Data\file.txt");
        assert_eq!(resolved2.tier(), Tier::T2);
        assert_eq!(resolved2.source(), "exact");
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

        svc.resolve_tier(r"C:\Data\file.txt");

        // Invalidate cache
        svc.invalidate_cache();

        // Cache is empty; next resolve still works (re-queries DB)
        let resolved = svc.resolve_tier(r"C:\Data\file.txt");
        assert_eq!(resolved.tier(), Tier::T1);
        assert_eq!(resolved.source(), "exact");
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
        let resolved1 = svc.resolve_tier(r"C:\Data\file.txt");
        assert_eq!(resolved1.tier(), Tier::T3);
        assert_eq!(resolved1.source(), "exact");

        // Wait a tiny bit for the zero-TTL entry to expire
        std::thread::sleep(Duration::from_millis(10));

        // Second call should miss cache (expired) and re-query DB
        let resolved2 = svc.resolve_tier(r"C:\Data\file.txt");
        assert_eq!(resolved2.tier(), Tier::T3);
        assert_eq!(resolved2.source(), "exact");
    }

    // --- Strictness comparison tests (D-07b) ---

    #[test]
    fn test_resolve_tier_explicit_lower_under_stricter_parent() {
        // T2 child under T4 parent -> Inherited T4 (stricter parent wins)
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            // Parent folder: T4
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
            .expect("insert parent");
            // Child file: T2 (less strict than parent)
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "file-001",
                    path: r"C:\Data\HR\salary.xlsx",
                    object_type: "file",
                    tier: "T2",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: Some("folder-001"),
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert child");
            uow.commit().expect("commit");
        }

        let resolved = svc.resolve_tier(r"C:\Data\HR\salary.xlsx");
        assert_eq!(
            resolved.tier(),
            Tier::T4,
            "stricter parent T4 must win over explicit T2 child"
        );
        assert_eq!(
            resolved.source(),
            "inherited",
            "must be inherited since parent is stricter"
        );
        assert!(resolved.is_inherited());
    }

    #[test]
    fn test_resolve_tier_explicit_stricter_under_lower_parent() {
        // T4 child under T2 parent -> Exact T4 (explicit stricter wins)
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            // Parent folder: T2
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "folder-001",
                    path: r"C:\Data\Public",
                    object_type: "folder",
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
            .expect("insert parent");
            // Child file: T4 (stricter than parent)
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "file-001",
                    path: r"C:\Data\Public\secret.docx",
                    object_type: "file",
                    tier: "T4",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: Some("folder-001"),
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert child");
            uow.commit().expect("commit");
        }

        let resolved = svc.resolve_tier(r"C:\Data\Public\secret.docx");
        assert_eq!(
            resolved.tier(),
            Tier::T4,
            "explicit T4 child must win over lower T2 parent"
        );
        assert_eq!(
            resolved.source(),
            "exact",
            "must be exact since explicit is stricter"
        );
        assert!(!resolved.is_inherited());
    }

    #[test]
    fn test_resolve_tier_equal_strictness() {
        // T3 child under T3 parent -> Exact T3 (equal, explicit wins)
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            // Parent folder: T3
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "folder-001",
                    path: r"C:\Data\HR",
                    object_type: "folder",
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
            .expect("insert parent");
            // Child file: T3 (same strictness as parent)
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "file-001",
                    path: r"C:\Data\HR\doc.txt",
                    object_type: "file",
                    tier: "T3",
                    label_state: "confirmed",
                    owner_sid: None,
                    parent_label_id: Some("folder-001"),
                    acl_snapshot_id: None,
                    hash: None,
                    scanner_confidence: None,
                    department: None,
                    created_at: "2026-05-12T00:00:00Z",
                    updated_at: "2026-05-12T00:00:00Z",
                },
            )
            .expect("insert child");
            uow.commit().expect("commit");
        }

        let resolved = svc.resolve_tier(r"C:\Data\HR\doc.txt");
        assert_eq!(
            resolved.tier(),
            Tier::T3,
            "equal strictness: explicit T3 wins"
        );
        assert_eq!(
            resolved.source(),
            "exact",
            "must be exact when equal strictness"
        );
    }

    #[test]
    fn test_resolve_tier_no_explicit_inherited_only() {
        // No explicit label, T3 parent folder -> Inherited T3
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        {
            let mut conn = pool.get().expect("acquire connection");
            let uow = UnitOfWork::new(&mut conn).expect("create uow");
            LabelRepository::insert(
                &uow,
                &LabelUpsertRow {
                    id: "folder-001",
                    path: r"C:\Data\HR",
                    object_type: "folder",
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

        // Child path has no explicit label
        let resolved = svc.resolve_tier(r"C:\Data\HR\unlabeled.txt");
        assert_eq!(resolved.tier(), Tier::T3);
        assert_eq!(resolved.source(), "inherited");
        assert!(resolved.is_inherited());
    }

    #[test]
    fn test_resolve_tier_cache_preserves_source_metadata() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

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

        // First call: DB miss, parent walk hit
        let resolved1 = svc.resolve_tier(r"C:\Data\HR\file.txt");
        assert_eq!(resolved1.source(), "inherited");

        // Second call: cache hit should preserve source
        let resolved2 = svc.resolve_tier(r"C:\Data\HR\file.txt");
        assert_eq!(resolved2.source(), "inherited");
        assert_eq!(resolved2.tier(), Tier::T4);
    }

    // --- with_mutation tests (transactional audit) ---

    #[test]
    fn test_with_mutation_commits_and_emits_audit() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        let ctx = MutationContext {
            label_id: "lbl-001".to_string(),
            action: "label_create".to_string(),
            old_state: None,
            new_state: Some("confirmed".to_string()),
            path: r"C:\Data\file.txt".to_string(),
            tier: "T3".to_string(),
            user_name: "admin".to_string(),
        };

        let result = svc.with_mutation(ctx, |uow| {
            LabelRepository::insert(
                uow,
                &LabelUpsertRow {
                    id: "lbl-001",
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
            .map_err(AppError::Database)?;
            Ok(42u32)
        });

        assert_eq!(result.expect("mutation ok"), 42);
    }

    #[test]
    fn test_with_mutation_rolls_back_when_mutation_fails() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        let ctx = MutationContext {
            label_id: "lbl-002".to_string(),
            action: "label_create".to_string(),
            old_state: None,
            new_state: Some("confirmed".to_string()),
            path: r"C:\Data\file.txt".to_string(),
            tier: "T3".to_string(),
            user_name: "admin".to_string(),
        };

        let result: Result<(), AppError> = svc.with_mutation(ctx, |_uow| {
            Err(AppError::BadRequest(
                "simulated mutation failure".to_string(),
            ))
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_with_mutation_invalidates_cache() {
        let pool = Arc::new(new_pool(":memory:").expect("create pool"));
        let svc = LabelService::new(Arc::clone(&pool));

        svc.cache.insert(
            r"C:\Data\file.txt".to_string(),
            CacheEntry {
                tier: Tier::T1,
                source: ResolutionSource::Exact,
                parent_path: None,
                inserted: Instant::now(),
            },
        );

        let ctx = MutationContext {
            label_id: "lbl-003".to_string(),
            action: "label_create".to_string(),
            old_state: None,
            new_state: Some("confirmed".to_string()),
            path: r"C:\Data\file.txt".to_string(),
            tier: "T3".to_string(),
            user_name: "admin".to_string(),
        };

        svc.with_mutation(ctx, |uow| {
            LabelRepository::insert(
                uow,
                &LabelUpsertRow {
                    id: "lbl-003",
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
            .map_err(AppError::Database)?;
            Ok(())
        })
        .expect("mutation ok");

        assert!(svc.cache.get(r"C:\Data\file.txt").is_none());
    }
}
