//! Cache warming — pre-populate the symbol cache before scans need it.
//!
//! The daemon's scanner reads from the SQLite symbol cache (`~/.anubis/symbols.db`).
//! On a cold cache, the first scan after switching projects sees an empty cache
//! and may surface false positives for project-defined types (Prisma models,
//! protobuf messages, user-defined structs). It also misses the chance to
//! pre-fetch docs.rs / unpkg / Godot XML docs for project dependencies until
//! the scanner hits them on the slow path.
//!
//! This module fixes both problems by firing a background warming task the
//! first time the daemon sees a new project root. The task:
//!
//!   1. Scans the user's source tree (`run_sync`) — extracts every function,
//!      struct, enum, type alias, interface, and import defined in the
//!      project, inserts them as a per-project library in the cache.
//!   2. Pre-fetches dependency bundles (`run_add_auto_at`) — reads
//!      Cargo.toml / package.json / project.godot / go.mod and fetches the
//!      public symbol surface for every declared dependency.
//!
//! Both steps already existed as CLI entry points (`anubis symbols sync`,
//! `anubis symbols add auto`). This module just wires them into the daemon's
//! request path so they fire automatically on first sight of a project,
//! without requiring the user to run a manual sync.
//!
//! ## Why fire-and-forget, not blocking
//!
//! Warming takes 1-30s depending on project size and dependency count. The
//! first scan after warming starts will simply see whatever's landed in the
//! cache so far — partially-warmed is strictly better than cold. We don't
//! block the scan because a 30s delay on the first response would be worse
//! UX than a slightly less complete first scan.
//!
//! ## Deduplication
//!
//! Each project root is warmed exactly once per process lifetime. The
//! `WARMED_ROOTS` set is keyed by canonical root path. Subsequent requests
//! to the same project are no-ops. Use `reset_for_test()` in tests.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use once_cell::sync::Lazy;

/// Process-wide record of project roots that have already been warmed
/// (or are currently being warmed — the entry is inserted before the
/// background task starts, so a concurrent call cannot double-spawn).
static WARMED_ROOTS: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

/// True while any background warming task is actively fetching/inserting
/// symbols. Used by the `/cache-status` endpoint to distinguish
/// "cold + warming in progress" from "cold + nothing happening".
static CURRENTLY_WARMING: AtomicBool = AtomicBool::new(false);

/// Returns true if any background warming task is currently in progress.
pub fn is_warming() -> bool {
    CURRENTLY_WARMING.load(Ordering::Relaxed)
}

/// Mark a project root as seen and warm its symbol cache if this is the
/// first time we've seen it in this process.
///
/// Fire-and-forget: spawns a background task and returns immediately. Safe
/// to call on every proxied request — the dedup set makes the per-request
/// cost a single `HashSet::contains`.
///
/// `root` should be an absolute filesystem path to the project root, as
/// returned by `project_root::detect_project_root`. Empty strings and
/// non-directory paths are silently ignored.
pub fn maybe_warm_for_project(root: String) {
    let root = root.trim();
    if root.is_empty() {
        return;
    }

    // Dedup: insert returns false if already present. First-write-wins —
    // a concurrent call cannot enter a duplicate, and the warming task is
    // spawned exactly once per root per process.
    {
        let mut set = WARMED_ROOTS
            .lock()
            .expect("WARMED_ROOTS mutex poisoned — daemon logic bug");
        if !set.insert(root.to_string()) {
            return;
        }
    }

    tracing::info!(
        target: "cache_warming",
        root = %root,
        "scheduling cache warming (first sight of this project)"
    );

    let root_owned = root.to_string();
    tokio::spawn(async move {
        run_warming(&root_owned).await;
    });
}

/// The actual warming sequence, extracted so tests can run it inline
/// (without the dedup set / spawn).
async fn run_warming(root: &str) {
    let root_path = Path::new(root);
    if !root_path.is_dir() {
        tracing::warn!(
            target: "cache_warming",
            root = %root,
            "skipped: not a directory (or unreadable)"
        );
        return;
    }

    CURRENTLY_WARMING.store(true, Ordering::Relaxed);
    let started = std::time::Instant::now();

    // Step 1: scan project source for local symbols (functions, types,
    // struct fields, imports). This is the chicken-and-egg fix — without
    // it, project-defined symbols (Prisma models, protobuf messages,
    // user-defined types) appear as "undefined variable" FPs.
    match crate::symbols_cli::run_sync(Some(root)).await {
        Ok(summary) => tracing::info!(
            target: "cache_warming",
            root = %root,
            step = "project_source_scan",
            elapsed_ms = started.elapsed().as_millis() as u64,
            summary = %summary,
            "step complete"
        ),
        Err(e) => tracing::warn!(
            target: "cache_warming",
            root = %root,
            step = "project_source_scan",
            error = %e,
            "step failed (continuing to dependency prefetch)"
        ),
    }

    // Step 2: pre-fetch dependency bundles. Reads Cargo.toml / package.json /
    // project.godot / go.mod and fetches the public API surface for each
    // declared dep from docs.rs / unpkg / GitHub (Godot XML). Also handles
    // the GDScript case from Task #1: when project.godot is detected, this
    // fetches the ~1500 Godot class XML docs and parses them into the cache.
    let dep_start = std::time::Instant::now();
    match crate::symbols_cli::run_add_auto_at(root_path).await {
        Ok(summary) => tracing::info!(
            target: "cache_warming",
            root = %root,
            step = "dependency_prefetch",
            elapsed_ms = dep_start.elapsed().as_millis() as u64,
            summary = %summary,
            "step complete"
        ),
        Err(e) => tracing::warn!(
            target: "cache_warming",
            root = %root,
            step = "dependency_prefetch",
            error = %e,
            "step failed (non-fatal — deps will be fetched on-demand during scan)"
        ),
    }

    tracing::info!(
        target: "cache_warming",
        root = %root,
        total_elapsed_ms = started.elapsed().as_millis() as u64,
        "cache warming complete"
    );

    CURRENTLY_WARMING.store(false, Ordering::Relaxed);
}

/// Manually mark a root as warmed without running the warming sequence.
///
/// Used by tests that need to verify the dedup logic without actually
/// performing a real cache warm (which would hit the network).
#[cfg(test)]
pub fn mark_warmed_for_test(root: &str) {
    WARMED_ROOTS
        .lock()
        .expect("WARMED_ROOTS mutex poisoned")
        .insert(root.to_string());
}

/// Returns true if `root` has been marked as warmed in this process.
#[cfg(test)]
pub fn is_warmed(root: &str) -> bool {
    WARMED_ROOTS
        .lock()
        .expect("WARMED_ROOTS mutex poisoned")
        .contains(root)
}

/// Clear the warmed-roots set. Test-only — never call from production code,
/// doing so would cause re-warming on every request.
#[cfg(test)]
pub fn reset_for_test() {
    WARMED_ROOTS
        .lock()
        .expect("WARMED_ROOTS mutex poisoned")
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_blocks_second_call() {
        reset_for_test();
        assert!(!is_warmed("/tmp/anubis-test-dedup"));
        mark_warmed_for_test("/tmp/anubis-test-dedup");
        assert!(is_warmed("/tmp/anubis-test-dedup"));
        // Second mark is a no-op (set semantics).
        mark_warmed_for_test("/tmp/anubis-test-dedup");
        assert!(is_warmed("/tmp/anubis-test-dedup"));
        reset_for_test();
        assert!(!is_warmed("/tmp/anubis-test-dedup"));
    }

    #[test]
    fn empty_root_is_noop() {
        reset_for_test();
        // maybe_warm_for_project with empty string must not insert into the
        // set (otherwise we'd waste a spawn on a non-project).
        maybe_warm_for_project(String::new());
        maybe_warm_for_project("   ".to_string());
        assert!(WARMED_ROOTS.lock().unwrap().is_empty());
        reset_for_test();
    }

    #[test]
    fn whitespace_only_root_is_noop() {
        reset_for_test();
        maybe_warm_for_project("\t\n ".to_string());
        assert!(WARMED_ROOTS.lock().unwrap().is_empty());
        reset_for_test();
    }

    #[tokio::test]
    async fn run_warming_skips_nonexistent_dir() {
        // Should log a warning and return without panicking — the warming
        // task must be resilient to race conditions where the project was
        // deleted between detection and warming.
        run_warming("/nonexistent/anubis-test-12345-deleted").await;
    }
}
