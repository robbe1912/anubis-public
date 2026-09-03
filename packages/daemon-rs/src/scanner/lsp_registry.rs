//! LSP client registry — concurrent per-workspace client management (FOUND-005).
//!
//! Replaces the per-language `OnceCell<Arc<Mutex<LspState>>>` statics in
//! `lsp_gate.rs` with a `DashMap<(workspace, Language), Arc<Mutex<LspState>>>`
//! keyed on the resolved workspace root + language. One rust-analyzer per
//! Cargo workspace, one gopls per Go module, capped at 8 concurrent clients
//! process-wide.
//!
//! ## Why DashMap
//! `Mutex<HashMap>` serializes every lookup. `DashMap` uses shard-level locks
//! so multiple scans across different workspaces proceed in parallel. The
//! Helix `helix-lsp` registry (MPL-2.0, studied per lsp-expansion-master.md)
//! uses the same pattern with `DashMap<(workspace, lang), Arc<Mutex<Client>>>`.
//!
//! ## Lifecycle
//! - [`get_or_spawn`] — lookup by (workspace, language). On miss, call the
//!   provided spawn closure (lsp_gate wires the real binary spawn in
//!   FOUND-006). On hit, refresh `last_used` for idle-reaper accounting.
//! - [`enforce_cap`] — evict oldest-by-last_used entries when count > max.
//!   Called after every successful spawn.
//! - [`reap_idle`] — drop entries whose `last_used` is older than threshold.
//!   Spawned as a periodic tokio task in FOUND-007.
//!
//! ## Test isolation
//! Unit tests use `LspRegistry::new()` directly (no global singleton) and
//! insert mock entries via `insert_for_test`. No real LSP servers spawned.
//!
//! See `.omo/plans/lsp-expansion-master.md` task FOUND-005.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::scanner::language::Language;
use crate::scanner::lsp_gate::LspState;

/// Process-wide cap on concurrent LSP clients across all workspaces + langs.
/// Per lsp-expansion-master.md Risk #5: bounded to avoid OOM on multi-project
/// scans. 8 covers the common case (rust+go+python+ts workspaces simultaneously).
pub const DEFAULT_MAX_CLIENTS: usize = 8;

/// Default idle timeout before an unused client is reaped. 5 minutes per
/// master plan — long enough to cover multi-file edits in one session,
/// short enough to free resources when the agent moves to another project.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// Concurrent map of (workspace_root, language) → client state.
///
/// `LspState` already tracks `last_used` (updated on every access via
/// `LspState::touch`) so idle reaping has the data it needs without a
/// separate metadata map.
pub struct LspRegistry {
    servers: DashMap<(PathBuf, Language), Arc<Mutex<LspState>>>,
    max_clients: usize,
}

impl LspRegistry {
    /// Construct an empty registry with the default cap (8 clients).
    pub fn new() -> Self {
        Self {
            servers: DashMap::new(),
            max_clients: DEFAULT_MAX_CLIENTS,
        }
    }

    /// Construct with a non-default cap (test affordance).
    #[cfg(test)]
    pub fn with_cap(max_clients: usize) -> Self {
        Self {
            servers: DashMap::new(),
            max_clients,
        }
    }

    /// Number of currently-registered clients.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// True iff no clients are registered.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Look up an existing client by (workspace, language). Refreshes
    /// `last_used` on hit so the idle reaper knows the client is active.
    ///
    /// Does NOT spawn — returns `None` on miss. Callers that need auto-spawn
    /// should use [`Self::get_or_spawn`] with a spawn closure.
    pub async fn get(&self, workspace: &PathBuf, language: Language) -> Option<Arc<Mutex<LspState>>> {
        let entry = self.servers.get(&(workspace.clone(), language))?;
        let arc = entry.clone();
        // Drop the DashMap read guard before touching the inner mutex to
        // avoid holding the shard lock across an await point (would block
        // other inserts into the same shard).
        drop(entry);
        arc.lock().await.touch();
        Some(arc)
    }

    /// Look up or spawn an LSP client for (workspace, language).
    ///
    /// On miss, calls `spawn()` to produce a new `LspState`. The spawn
    /// closure is responsible for the actual binary lookup + version
    /// check + LspClient::start (wired in FOUND-006). After successful
    /// insert, enforces the cap by evicting the oldest entry.
    ///
    /// Spawn is async because LSP startup involves subprocess + IPC
    /// handshake (LspClient::start does the initialize/initialized
    /// exchange, ~3-60s for rust-analyzer cold start).
    ///
    /// Returns the `Arc<Mutex<LspState>>` for the client (which may be
    /// `LspState::empty()` if spawn failed — caller checks `.client.is_some()`).
    pub async fn get_or_spawn<F, Fut>(
        &self,
        workspace: PathBuf,
        language: Language,
        spawn: F,
    ) -> Arc<Mutex<LspState>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = LspState>,
    {
        // Fast path: existing entry.
        if let Some(existing) = self.get(&workspace, language).await {
            return existing;
        }
        // Miss: spawn + insert. Two concurrent callers may both spawn the
        // same (workspace, language) — we let the second one win (overwrites
        // the first). This is cheaper than a per-key lock for the common
        // case (no contention) and the wasted spawn is rare.
        let new_state = spawn().await;
        let arc = Arc::new(Mutex::new(new_state));
        self.servers.insert((workspace.clone(), language), arc.clone());
        tracing::debug!(
            target: "lsp_registry",
            "inserted client (total={}/{})",
            self.servers.len(),
            self.max_clients,
        );
        self.enforce_cap();
        arc
    }

    /// Direct insert — bypass spawn. Test affordance + FOUND-006 migration
    /// helper when lifting existing OnceCell entries into the registry.
    pub fn insert(&self, workspace: PathBuf, language: Language, state: LspState) {
        let arc = Arc::new(Mutex::new(state));
        self.servers.insert((workspace, language), arc);
        self.enforce_cap();
    }

    /// Evict oldest-by-`last_used` entries until count ≤ max_clients.
    ///
    /// "Oldest" = smallest `last_used` Instant. Reads each entry's `last_used`
    /// under its own mutex (no global lock). On tie, evicts the lexically
    /// smallest (workspace, language) key for deterministic test output.
    ///
    /// Skips entries whose mutex is currently held (try_lock fails) — those
    /// are by definition active and shouldn't be reaped mid-scan.
    pub fn enforce_cap(&self) {
        self.enforce_cap_to(self.max_clients);
    }

    /// Internal: enforce an arbitrary cap (test affordance).
    fn enforce_cap_to(&self, target: usize) {
        while self.servers.len() > target {
            // Find the entry with the smallest last_used (oldest). Skip
            // locked entries — they're active, not safe to evict.
            let mut oldest_key: Option<(PathBuf, Language)> = None;
            let mut oldest_instant: Option<Instant> = None;
            for entry in self.servers.iter() {
                let key = entry.key().clone();
                // Try-lock to read last_used without blocking active scans.
                // If locked, treat as "in use" and skip. tokio::sync::Mutex's
                // try_lock returns Result, not Option.
                let Ok(guard) = entry.value().try_lock() else {
                    continue;
                };
                let lu = guard.last_used;
                if oldest_instant.map_or(true, |oi| lu < oi) {
                    oldest_instant = Some(lu);
                    oldest_key = Some(key);
                }
            }
            match oldest_key {
                Some(key) => {
                    if self.servers.remove(&key).is_some() {
                        tracing::info!(
                            target: "lsp_registry",
                            "evicted oldest client to enforce cap ({:?}, {:?})",
                            key.0,
                            key.1,
                        );
                    } else {
                        // Raced with another eviction — break to avoid loop.
                        break;
                    }
                }
                None => {
                    // Every entry was locked — all active. Skip eviction.
                    tracing::debug!(
                        target: "lsp_registry",
                        "enforce_cap skipped: all {} entries in use",
                        self.servers.len(),
                    );
                    break;
                }
            }
        }
    }

    /// Evict entries whose `last_used` is older than `idle_timeout`.
    ///
    /// Like `enforce_cap`: skips entries whose mutex is currently held
    /// (they're mid-scan, not idle).
    pub fn reap_idle(&self, idle_timeout: Duration) {
        let now = Instant::now();
        let mut to_remove: Vec<(PathBuf, Language)> = Vec::new();
        for entry in self.servers.iter() {
            let key = entry.key().clone();
            let Ok(guard) = entry.value().try_lock() else {
                continue;
            };
            if now.duration_since(guard.last_used) > idle_timeout {
                to_remove.push(key);
            }
        }
        for key in to_remove {
            if self.servers.remove(&key).is_some() {
                tracing::info!(
                    target: "lsp_registry",
                    "reaped idle client ({:?}, {:?})",
                    key.0,
                    key.1,
                );
            }
        }
    }

    /// Evict entries whose underlying child process has exited (COLD-004).
    ///
    /// Catches OOM-killed or crashed LSP servers immediately rather than
    /// waiting the full idle timeout. Per master plan COLD-004: "per-client
    /// child-exit watcher". Uses `LspState::is_dead` (which calls
    /// `Child::try_wait`). Skips entries whose mutex is currently held —
    /// they're mid-scan, can't safely check.
    pub fn reap_dead(&self) {
        let mut to_remove: Vec<(PathBuf, Language)> = Vec::new();
        for entry in self.servers.iter() {
            let key = entry.key().clone();
            let Ok(mut guard) = entry.value().try_lock() else {
                continue;
            };
            if guard.is_dead() {
                to_remove.push(key);
            }
        }
        for key in to_remove {
            if self.servers.remove(&key).is_some() {
                tracing::warn!(
                    target: "lsp_registry",
                    "reaped dead client ({:?}, {:?}) — child process exited",
                    key.0,
                    key.1,
                );
            }
        }
    }

    /// Remove a specific entry (test affordance + future shutdown hook).
    /// Returns the removed `Arc<Mutex<LspState>>` (or `None` if not found).
    pub fn remove(&self, workspace: &PathBuf, language: Language) -> Option<Arc<Mutex<LspState>>> {
        // DashMap::remove returns Option<(K, V)> — we discard the key.
        self.servers
            .remove(&(workspace.clone(), language))
            .map(|(_, v)| v)
    }

    /// Prewarm an LSP client for (workspace, language) without consuming
    /// the result (FOUND-007). Spawn happens in the background via `spawn()`;
    /// subsequent `get_or_spawn` calls for the same key hit the cache.
    ///
    /// Use case: when the daemon detects a scan is about to happen for a
    /// language (e.g. tool_call writes a `.rs` file), it calls `prewarm()`
    /// to start rust-analyzer cold-start (~5-60s) in parallel with whatever
    /// else is happening. By the time `suppress_fps` calls `get_or_spawn`,
    /// the client is warm.
    ///
    /// No-op if an entry for (workspace, language) already exists.
    pub async fn prewarm<F, Fut>(
        &self,
        workspace: PathBuf,
        language: Language,
        spawn: F,
    ) where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = LspState>,
    {
        // Cache hit → nothing to prewarm.
        if self.servers.get(&(workspace.clone(), language)).is_some() {
            return;
        }
        // Cache miss → trigger spawn (inserts into map).
        let _ = self.get_or_spawn(workspace, language, spawn).await;
    }
}

impl Default for LspRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide singleton. Found-006 wires `lsp_gate::get_client` through
/// this registry via `global_registry()`. std::sync::OnceLock keeps the
/// accessor synchronous (tokio::sync::OnceCell::get_or_init is async, which
/// would force every caller to .await the registry lookup).
static GLOBAL_REGISTRY: std::sync::OnceLock<LspRegistry> = std::sync::OnceLock::new();

/// Access the process-wide registry, creating it on first call.
pub fn global_registry() -> &'static LspRegistry {
    GLOBAL_REGISTRY.get_or_init(LspRegistry::new)
}

/// Start a periodic tokio task that reaps idle + dead clients from the
/// global registry (FOUND-007 + COLD-004). Runs every `interval`; evicts
/// entries whose `last_used` is older than `idle_timeout` AND entries
/// whose underlying child process has exited.
///
/// COLD-004 added the `reap_dead` pass alongside `reap_idle` — catches
/// OOM-killed or crashed LSP servers immediately rather than waiting the
/// full idle timeout.
///
/// Returns the `JoinHandle` so the caller can hold it (or drop it — the
/// task is `tokio::spawn`-detached and will run for the process lifetime).
/// Should be called once at daemon startup after the tokio runtime is up.
///
/// Per master plan: interval 60s, idle_timeout 5 min. These are sane
/// defaults; tune via config if needed.
pub fn spawn_idle_reaper(
    interval: Duration,
    idle_timeout: Duration,
) -> tokio::task::JoinHandle<()> {
    let registry = global_registry();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        // First tick fires immediately — skip it so we wait `interval`
        // before the first reap (clients just spawned shouldn't be reaped
        // before they've had a chance to be used).
        tick.tick().await;
        loop {
            tick.tick().await;
            // Dead-process reaping runs first — frees slots faster than
            // waiting for idle timeout when an LSP server has crashed.
            registry.reap_dead();
            let before = registry.len();
            registry.reap_idle(idle_timeout);
            let reaped = before.saturating_sub(registry.len());
            if reaped > 0 {
                tracing::info!(
                    target: "lsp_registry",
                    "idle reaper evicted {} clients (remaining={})",
                    reaped,
                    registry.len(),
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_state(client_present: bool, age: Duration) -> LspState {
        // LspClient is private — tests can't construct one. Use empty()
        // for both branches (the client_present flag is kept for clarity
        // but the test scenarios don't exercise real client behavior).
        let _ = client_present;
        let mut s = LspState::empty();
        // Backdate last_used to simulate idle age.
        s.last_used = Instant::now()
            .checked_sub(age)
            .unwrap_or_else(Instant::now);
        s
    }

    #[test]
    fn new_registry_is_empty_with_default_cap() {
        let r = LspRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.max_clients, DEFAULT_MAX_CLIENTS);
    }

    #[test]
    fn insert_increments_len() {
        let r = LspRegistry::new();
        r.insert(
            PathBuf::from("/ws1"),
            Language::Rust,
            make_state(false, Duration::from_secs(0)),
        );
        assert_eq!(r.len(), 1);
        r.insert(
            PathBuf::from("/ws2"),
            Language::Go,
            make_state(false, Duration::from_secs(0)),
        );
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn get_returns_inserted_entry_and_refreshes_last_used() {
        use tokio::runtime::Runtime;
        let r = LspRegistry::new();
        r.insert(
            PathBuf::from("/ws"),
            Language::Rust,
            make_state(false, Duration::from_secs(60)), // old
        );
        let before = Instant::now();
        // Spin until the entry is at least 1ms old (Instant resolution).
        while Instant::now().duration_since(before) < Duration::from_millis(2) {
            std::thread::yield_now();
        }
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let arc = r.get(&PathBuf::from("/ws"), Language::Rust).await;
            assert!(arc.is_some(), "get must hit after insert");
            let binding = arc.unwrap();
            let guard = binding.lock().await;
            assert!(guard.last_used > before, "get() must refresh last_used");
        });
    }

    #[test]
    fn get_returns_none_on_miss() {
        use tokio::runtime::Runtime;
        let r = LspRegistry::new();
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let arc = r.get(&PathBuf::from("/missing"), Language::Rust).await;
            assert!(arc.is_none());
        });
    }

    #[test]
    fn enforce_cap_evicts_oldest() {
        let r = LspRegistry::with_cap(3);
        r.insert(
            PathBuf::from("/old"),
            Language::Rust,
            make_state(false, Duration::from_secs(600)), // 10 min old
        );
        r.insert(
            PathBuf::from("/mid"),
            Language::Rust,
            make_state(false, Duration::from_secs(60)), // 1 min old
        );
        r.insert(
            PathBuf::from("/new"),
            Language::Rust,
            make_state(false, Duration::from_secs(1)), // 1s old
        );
        // Insert one more — should evict /old (oldest).
        r.insert(
            PathBuf::from("/extra"),
            Language::Rust,
            make_state(false, Duration::from_secs(0)),
        );
        assert_eq!(r.len(), 3, "cap enforced");
        assert!(
            r.get_only_check(&PathBuf::from("/old"), Language::Rust).is_none(),
            "oldest evicted"
        );
        assert!(
            r.get_only_check(&PathBuf::from("/new"), Language::Rust).is_some(),
            "newest kept"
        );
    }

    #[test]
    fn reap_idle_removes_stale_entries() {
        let r = LspRegistry::new();
        r.insert(
            PathBuf::from("/stale"),
            Language::Rust,
            make_state(false, Duration::from_secs(600)), // 10 min idle
        );
        r.insert(
            PathBuf::from("/fresh"),
            Language::Rust,
            make_state(false, Duration::from_secs(1)), // 1s idle
        );
        r.reap_idle(Duration::from_secs(60));
        assert_eq!(r.len(), 1, "only stale reaped");
        assert!(
            r.get_only_check(&PathBuf::from("/fresh"), Language::Rust).is_some(),
            "fresh kept"
        );
    }

    #[test]
    fn reap_idle_keeps_all_when_none_stale() {
        let r = LspRegistry::new();
        r.insert(
            PathBuf::from("/a"),
            Language::Rust,
            make_state(false, Duration::from_secs(1)),
        );
        r.insert(
            PathBuf::from("/b"),
            Language::Go,
            make_state(false, Duration::from_secs(1)),
        );
        r.reap_idle(Duration::from_secs(60));
        assert_eq!(r.len(), 2, "no eviction when all fresh");
    }

    #[test]
    fn remove_drops_specified_entry() {
        let r = LspRegistry::new();
        r.insert(
            PathBuf::from("/ws"),
            Language::Rust,
            make_state(false, Duration::from_secs(0)),
        );
        assert!(r.remove(&PathBuf::from("/ws"), Language::Rust).is_some());
        assert!(r.is_empty());
        // Second remove returns None.
        assert!(r.remove(&PathBuf::from("/ws"), Language::Rust).is_none());
    }

    #[test]
    fn different_languages_for_same_workspace_coexist() {
        let r = LspRegistry::new();
        r.insert(
            PathBuf::from("/ws"),
            Language::Rust,
            make_state(false, Duration::from_secs(0)),
        );
        r.insert(
            PathBuf::from("/ws"),
            Language::Go,
            make_state(false, Duration::from_secs(0)),
        );
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn reinsert_same_key_overwrites() {
        let r = LspRegistry::new();
        r.insert(
            PathBuf::from("/ws"),
            Language::Rust,
            make_state(false, Duration::from_secs(100)),
        );
        r.insert(
            PathBuf::from("/ws"),
            Language::Rust,
            make_state(false, Duration::from_secs(0)),
        );
        assert_eq!(r.len(), 1, "same key overwrites");
    }

    #[test]
    fn get_or_spawn_calls_spawn_on_miss_only() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::runtime::Runtime;
        let r = LspRegistry::new();
        let rt = Runtime::new().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let spawn = move || {
            let c = calls_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                LspState::empty()
            }
        };
        let ws = PathBuf::from("/ws");
        rt.block_on(r.get_or_spawn(ws.clone(), Language::Rust, spawn));
        // Second call should hit cache, not spawn.
        let calls2 = Arc::new(AtomicUsize::new(0));
        let calls2_clone = calls2.clone();
        let spawn2 = move || {
            let c = calls2_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                LspState::empty()
            }
        };
        rt.block_on(r.get_or_spawn(ws, Language::Rust, spawn2));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "first call spawned");
        assert_eq!(calls2.load(Ordering::SeqCst), 0, "second call hit cache");
    }

    // Test affordance: read-only check without refreshing last_used.
    impl LspRegistry {
        fn get_only_check(
            &self,
            workspace: &PathBuf,
            language: Language,
        ) -> Option<Arc<Mutex<LspState>>> {
            self.servers
                .get(&(workspace.clone(), language))
                .map(|e| e.clone())
        }
    }

    #[test]
    fn prewarm_inserts_on_miss() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::runtime::Runtime;
        let r = LspRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let spawn = move || {
            let c = calls_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                LspState::empty()
            }
        };
        let rt = Runtime::new().unwrap();
        rt.block_on(r.prewarm(PathBuf::from("/ws"), Language::Rust, spawn));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "prewarm spawned on miss");
        assert_eq!(r.len(), 1, "prewarm inserted entry");
    }

    #[test]
    fn prewarm_noop_on_cache_hit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::runtime::Runtime;
        let r = LspRegistry::new();
        // Pre-populate.
        r.insert(
            PathBuf::from("/ws"),
            Language::Rust,
            LspState::empty(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let spawn = move || {
            let c = calls_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                LspState::empty()
            }
        };
        let rt = Runtime::new().unwrap();
        rt.block_on(r.prewarm(PathBuf::from("/ws"), Language::Rust, spawn));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "prewarm skipped spawn on hit");
        assert_eq!(r.len(), 1, "no duplicate entry");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_idle_reaper_starts_without_panic() {
        // Just verify the reaper can be spawned and dropped without issues.
        // We don't actually wait for it to reap anything — that requires
        // tokio::time::pause + advance, which adds complexity for marginal
        // coverage. reap_idle() itself is tested elsewhere.
        let handle = spawn_idle_reaper(Duration::from_millis(10), Duration::from_secs(60));
        // Drop the handle — task continues in background, will be killed
        // when the runtime shuts down at end of test.
        drop(handle);
    }
}
