//! Registry cap enforcement helpers (COLD-001 façade).
//!
//! The process-wide cap (`DEFAULT_MAX_CLIENTS = 8`) is enforced inside
//! `LspRegistry::enforce_cap` (called automatically after every spawn).
//! This module exposes helpers for callers that need to inspect or
//! manually trigger cap enforcement (e.g. config-reload hooks).

use crate::scanner::lsp_registry::{global_registry, DEFAULT_MAX_CLIENTS};

/// Current client count in the global registry.
pub fn active_client_count() -> usize {
    global_registry().len()
}

/// True iff the registry is at or above the configured cap.
pub fn at_cap() -> bool {
    active_client_count() >= DEFAULT_MAX_CLIENTS
}

/// Synchronously invoke cap enforcement. Usually unnecessary — the
/// registry auto-enforces on insert — but exposed for callers that
/// lower the cap at runtime and want immediate eviction.
pub fn enforce_now() {
    global_registry().enforce_cap();
}

/// The process-wide cap (8 by default per master plan).
pub const MAX_CLIENTS: usize = DEFAULT_MAX_CLIENTS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_client_count_does_not_panic() {
        let _ = active_client_count();
    }

    #[test]
    fn max_clients_is_8_per_master_plan() {
        assert_eq!(MAX_CLIENTS, 8);
    }
}
