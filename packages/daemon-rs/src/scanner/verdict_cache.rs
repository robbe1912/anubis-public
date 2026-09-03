//! Verdict cache — content-hash → ScanResultData, 24h TTL, 500 cap.
//!
//! Extracted from scanner/mod.rs for code health.

use std::collections::HashMap;
use parking_lot::Mutex;

use super::ScanContext;
pub(crate) const VERDICT_CACHE_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub(crate) const VERDICT_CACHE_MAX: usize = 500;

pub(crate) struct CachedVerdict {
    pub(crate) result_json: String, // serialized ScanResultData
    pub(crate) expires_at: u64,
    /// Insertion time (ms since epoch). Used for FIFO eviction when the cache
    /// exceeds `VERDICT_CACHE_MAX`. Replaces the previous `keys().next()`
    /// approach which picked an ARBITRARY entry and could evict a just-inserted
    /// hot entry on the very next put.
    pub(crate) inserted_at: u64,
}

pub(crate) static VERDICT_CACHE: Mutex<Option<HashMap<u64, CachedVerdict>>> = Mutex::new(None);
pub(crate) static VERDICT_HITS: Mutex<u64> = Mutex::new(0);
pub(crate) static VERDICT_MISSES: Mutex<u64> = Mutex::new(0);

pub fn verdict_cache_stats() -> (u64, u64, usize) {
    let hits = *VERDICT_HITS.lock();
    let misses = *VERDICT_MISSES.lock();
    let size = VERDICT_CACHE
        .lock()
        .as_ref()
        .map(|m| m.len())
        .unwrap_or(0);
    (hits, misses, size)
}

pub fn clear_verdict_cache() {
    {
        let mut guard = VERDICT_CACHE.lock();
        *guard = None;
    }
    {
        let mut h = VERDICT_HITS.lock();
        *h = 0;
    }
    {
        let mut m = VERDICT_MISSES.lock();
        *m = 0;
    }
}

pub(crate) fn evict_expired_cache(cache: &mut HashMap<u64, CachedVerdict>) {
    let now = current_time_ms();
    // Drop anything past its TTL.
    cache.retain(|_, v| v.expires_at > now);

    // If still over cap, evict the OLDEST entries first (FIFO order, not
    // arbitrary). The previous impl used `cache.keys().next()` which returns
    // an unspecified key in `HashMap` and could evict a hot entry.
    while cache.len() > VERDICT_CACHE_MAX {
        let oldest_key = cache
            .iter()
            .min_by_key(|(_, v)| v.inserted_at)
            .map(|(k, _)| *k);
        if let Some(key) = oldest_key {
            cache.remove(&key);
        } else {
            break;
        }
    }
}

pub(crate) fn build_cache_key(content: &str, ctx: &ScanContext) -> u64 {
    let input = format!("{}::{}::{}", ctx.project_root, ctx.logic_model, content);
    let mut hash: u64 = 5381;
    for b in input.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(b as u64);
    }
    hash
}

pub(crate) fn current_time_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Lookup a cached verdict by key. On a fresh (non-expired) hit, increments
/// VERDICT_HITS and returns the serialized result JSON. On miss/expired,
/// returns `None` (caller increments VERDICT_MISSES after the deserialization
/// attempt, so corrupt hits still count as both hit and miss — matching the
/// pre-extraction behavior).
pub(crate) fn verdict_cache_get(cache_key: u64) -> Option<String> {
    let mut guard = VERDICT_CACHE.lock();
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some(cached) = cache.get(&cache_key) {
        if cached.expires_at > current_time_ms() {
            {
                let mut h = VERDICT_HITS.lock();
                *h += 1;
            }
            tracing::info!(target: "scanner", "verdict cache HIT (key={})", cache_key);
            return Some(cached.result_json.clone());
        } else {
            cache.remove(&cache_key);
        }
    }
    None
}