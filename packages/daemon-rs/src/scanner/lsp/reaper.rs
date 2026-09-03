//! Idle reaper (COLD-001 façade for FOUND-007 spawn_idle_reaper).
//!
//! Periodic tokio task that evicts LSP clients unused for > idle_timeout.
//! Default cadence: 60s. Default idle timeout: 5 min. Both tunable.

use std::time::Duration;

/// Default interval between reaper passes. 60s per master plan —
/// balances "notice idle client reasonably soon" vs "don't burn CPU on
/// reaps that find nothing to do".
pub const DEFAULT_REAPER_INTERVAL_MS: u64 = 60_000;

/// Inherited from `lsp_registry::DEFAULT_IDLE_TIMEOUT_MS` (5 min) —
/// clients unused for this duration are candidates for eviction.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = crate::scanner::lsp_registry::DEFAULT_IDLE_TIMEOUT_MS;

/// Start the idle reaper with default cadence (60s) + timeout (5 min).
///
/// Convenience wrapper around [`spawn_idle_reaper_with`] for the common
/// case. Returns the JoinHandle so the caller can hold it (or drop it —
/// task is detached).
pub fn spawn_idle_reaper() -> tokio::task::JoinHandle<()> {
    spawn_idle_reaper_with(
        Duration::from_millis(DEFAULT_REAPER_INTERVAL_MS),
        Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS),
    )
}

/// Start the reaper with custom cadence + timeout (test affordance).
///
/// Skips the first tick so freshly-spawned clients have at least one
/// `interval` cycle before being considered idle.
pub fn spawn_idle_reaper_with(
    interval: Duration,
    idle_timeout: Duration,
) -> tokio::task::JoinHandle<()> {
    crate::scanner::lsp_registry::spawn_idle_reaper(interval, idle_timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_master_plan() {
        assert_eq!(DEFAULT_REAPER_INTERVAL_MS, 60_000, "60s interval");
        assert_eq!(DEFAULT_IDLE_TIMEOUT_MS, 5 * 60 * 1000, "5min timeout");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_idle_reaper_default_does_not_panic() {
        let handle = spawn_idle_reaper();
        drop(handle);
    }
}
