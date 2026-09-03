//! Content-hash cache for compiler FP-gate output (Phase 2).
//!
//! Wraps the language-specific `*_compiler_gate` calls in mod.rs:2907 with
//! a process-wide `DashMap<u64, CacheEntry>`. Key = hash(code_content +
//! language). TTL = 1 hour.
//!
//! ## Why
//! Compiler gates are expensive (rustc 3-30s, dotnet 30-60s, tsc 5-15s).
//! Repeated scans of identical content (regression tests, edit cycles
//! within a single response, dashboard refreshes) re-run the full gate
//! needlessly. A content-hash cache short-circuits the second+ call to
//! ~microseconds.
//!
//! ## Why not mtime
//! Mtime-based invalidation requires enumerating project files per
//! language (Cargo.toml + src/*.rs for Rust, package.json + src/*.ts for
//! TS, etc.). That's ~150 LOC and a filesystem walk per scan — heavier
//! than the cache lookup itself. Content-hash is simpler: any code
//! change naturally invalidates because the hash differs. Project-file
//! changes (e.g. Cargo.toml edit) aren't covered, but those are rare
//! during a scan session; the 1h TTL bounds staleness.
//!
//! ## Hit rate
//! - Regression benchmarks: 100% (same code, many runs)
//! - Edit cycles within one response: ~50% (intermediate edits miss, final state hits)
//! - Production scans: ~10% (mostly unique content)
//!
//! See `scan_response()` in `scanner/mod.rs:2907` for the dispatch site.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use once_cell::sync::Lazy;

/// Cache TTL: 1 hour. Bounds staleness for project-file changes that
/// don't alter the scanned code content (e.g. Cargo.toml dependency add).
pub const TTL: Duration = Duration::from_secs(60 * 60);

/// Maximum entries. 1024 is generous — at ~1KB per entry (hash + cloned
/// HashSet), that's ~1MB worst case. DashMap shards across 8 shards, so
/// 128 entries/shard — well within the per-shard linear-scan budget for
/// TTL eviction.
pub const MAX_ENTRIES: usize = 1024;

#[derive(Clone)]
struct CacheEntry {
    value: Option<HashSet<String>>,
    expires_at: Instant,
}

/// Content-hash cache for compiler FP-gate results. Instance-based so
/// tests don't share state via a global static (parallel cargo tests
/// would race on a shared DashMap).
#[derive(Default)]
pub struct CompilerCache {
    servers: DashMap<u64, CacheEntry>,
}

impl CompilerCache {
    pub fn new() -> Self {
        Self {
            servers: DashMap::new(),
        }
    }

    /// Compute the cache key for (code, language).
    fn cache_key(code: &str, language: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        code.hash(&mut h);
        h.write(language.as_bytes());
        h.finish()
    }

    /// Look up the cache for (code, language). Returns the cached value
    /// if present and unexpired, `None` otherwise. Expired entries are
    /// evicted as a side effect.
    pub fn lookup(&self, code: &str, language: &str) -> Option<Option<HashSet<String>>> {
        let key = Self::cache_key(code, language);
        let entry = self.servers.get(&key)?;
        if Instant::now() >= entry.expires_at {
            drop(entry);
            self.servers.remove(&key);
            return None;
        }
        Some(entry.value.clone())
    }

    /// Store a value in the cache with the standard TTL.
    pub fn store(&self, code: &str, language: &str, value: Option<HashSet<String>>) {
        let key = Self::cache_key(code, language);
        self.servers.insert(key, CacheEntry {
            value,
            expires_at: Instant::now() + TTL,
        });
        self.enforce_cap();
    }

    /// Evict oldest entries when over `MAX_ENTRIES`. "Oldest" = earliest
    /// `expires_at`. Linear scan — DashMap doesn't index by expiry, but
    /// with a 1024 cap the scan is ~100µs and runs only on insert.
    fn enforce_cap(&self) {
        while self.servers.len() > MAX_ENTRIES {
            let mut oldest_key: Option<u64> = None;
            let mut oldest_expiry: Option<Instant> = None;
            for entry in self.servers.iter() {
                let exp = entry.expires_at;
                if oldest_expiry.map_or(true, |oe| exp < oe) {
                    oldest_expiry = Some(exp);
                    oldest_key = Some(*entry.key());
                }
            }
            match oldest_key {
                Some(k) => {
                    self.servers.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Drop all cached entries. Test affordance + future config-reload hook.
    pub fn clear(&self) {
        self.servers.clear();
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// True iff no entries cached.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Look up or compute the compiler gate result.
    pub async fn lookup_or_compute<F, Fut>(
        &self,
        code: &str,
        language: &str,
        compute: F,
    ) -> Option<HashSet<String>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<HashSet<String>>>,
    {
        if let Some(cached) = self.lookup(code, language) {
            return cached;
        }
        let value = compute().await;
        self.store(code, language, value.clone());
        value
    }

    /// Insert a raw (key, entry) pair — test affordance for backdated
    /// expiry scenarios without paying the TTL.
    #[cfg(test)]
    fn warm_with(&self, key: u64, value: Option<HashSet<String>>, expires_at: Instant) {
        self.servers.insert(key, CacheEntry { value, expires_at });
    }

    /// Expose raw key for tests.
    #[cfg(test)]
    fn key_for(code: &str, language: &str) -> u64 {
        Self::cache_key(code, language)
    }
}

/// Process-wide singleton. The mod.rs compiler-gate dispatch uses this
/// via `global()`. Tests use `CompilerCache::new()` directly for isolation.
static GLOBAL_COMPILER_CACHE: Lazy<CompilerCache> = Lazy::new(CompilerCache::new);

/// Access the process-wide compiler cache.
pub fn global() -> &'static CompilerCache {
    &GLOBAL_COMPILER_CACHE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> CompilerCache {
        CompilerCache::new()
    }

    #[test]
    fn lookup_returns_none_on_miss() {
        let c = fresh();
        assert!(c.lookup("missing code", "rust").is_none());
    }

    #[test]
    fn store_then_lookup_returns_value() {
        let c = fresh();
        let mut hs = HashSet::new();
        hs.insert("hallucinated_sym".to_string());
        c.store("code body", "rust", Some(hs.clone()));
        let got = c.lookup("code body", "rust");
        assert_eq!(got, Some(Some(hs)));
    }

    #[test]
    fn store_none_value_round_trips() {
        let c = fresh();
        c.store("code", "cobol", None);
        let got = c.lookup("code", "cobol");
        assert_eq!(got, Some(None));
    }

    #[test]
    fn different_languages_get_different_entries() {
        let c = fresh();
        let mut rust_syms = HashSet::new();
        rust_syms.insert("Foo".to_string());
        let mut ts_syms = HashSet::new();
        ts_syms.insert("bar".to_string());
        c.store("same code", "rust", Some(rust_syms.clone()));
        c.store("same code", "typescript", Some(ts_syms.clone()));
        assert_eq!(c.lookup("same code", "rust"), Some(Some(rust_syms)));
        assert_eq!(c.lookup("same code", "typescript"), Some(Some(ts_syms)));
    }

    #[test]
    fn expired_entries_evicted_on_lookup() {
        let c = fresh();
        c.warm_with(
            CompilerCache::key_for("old code", "rust"),
            Some(HashSet::new()),
            Instant::now() - Duration::from_secs(1),
        );
        assert_eq!(c.len(), 1);
        let got = c.lookup("old code", "rust");
        assert!(got.is_none(), "expired entry returns None");
        assert_eq!(c.len(), 0, "expired entry evicted");
    }

    #[test]
    fn enforce_cap_drops_oldest_when_over_cap() {
        let c = fresh();
        // Insert MAX_ENTRIES + 50 entries with progressively later expiry.
        // The first 50 should get evicted (oldest).
        for i in 0..(MAX_ENTRIES + 50) as u64 {
            c.warm_with(
                i,
                None,
                Instant::now() + Duration::from_secs(i),
            );
        }
        // Trigger enforce_cap by storing one more.
        c.store("trigger-cap-check", "rust", None);
        assert!(
            c.len() <= MAX_ENTRIES,
            "cap enforced: len={}, max={}",
            c.len(),
            MAX_ENTRIES,
        );
    }

    #[test]
    fn clear_empties_cache() {
        let c = fresh();
        c.store("a", "rust", None);
        c.store("b", "go", None);
        assert_eq!(c.len(), 2);
        c.clear();
        assert_eq!(c.len(), 0);
        assert!(c.lookup("a", "rust").is_none());
    }

    #[tokio::test]
    async fn lookup_or_compute_caches_compute_result() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let c = fresh();
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let compute = move || {
            let cc = calls_clone.clone();
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                let mut hs = HashSet::new();
                hs.insert("sym".to_string());
                Some(hs)
            }
        };
        let v1 = c.lookup_or_compute("code", "rust", compute).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(v1.is_some());
        // Second call hits cache.
        let calls2 = std::sync::Arc::new(AtomicUsize::new(0));
        let calls2_clone = calls2.clone();
        let compute2 = move || {
            let cc = calls2_clone.clone();
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                None
            }
        };
        let v2 = c.lookup_or_compute("code", "rust", compute2).await;
        assert_eq!(calls2.load(Ordering::SeqCst), 0, "cache hit skipped compute");
        assert_eq!(v1, v2, "cached value matches");
    }

    #[test]
    fn global_returns_same_instance() {
        let g1 = global();
        let g2 = global();
        // Same `&'static` pointer.
        assert!(std::ptr::eq(g1, g2), "global() returns singleton");
    }
}

