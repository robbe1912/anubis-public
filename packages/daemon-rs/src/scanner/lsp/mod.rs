//! LSP subsystem — unified façade for spawn config, registry, prewarm, reaper.
//!
//! This module groups the previously-flat `scanner::lsp_config` +
//! `scanner::lsp_registry` into one logical subsystem per the master plan
//! (COLD-001). Submodules:
//!
//! - [`config`] — per-language [`LspSpawnConfig`] entries + workspace detection
//! - [`prewarm`] — prewarm API (trigger spawn before first scan)
//! - [`reaper`] — idle reaper (evict unused clients)
//! - [`cap`] — registry cap enforcement helpers
//! - [`fallback`] — unified fallback chain (COLD-005 placeholder)
//! - [`sidecar`] — binary bundle path resolution (COLD-007..009 placeholder)
//!
//! ## Public API
//! Per master plan "Interface Contract (LOCKED)":
//! ```ignore
//! pub async fn get_or_spawn(language: Language, project_root: &Path) -> Option<Arc<Mutex<LspState>>>;
//! pub async fn prewarm(language: Language, project_root: &Path);
//! pub fn register_language(language: Language, config: LspSpawnConfig);
//! ```
//! Re-exported at module root for ergonomic callers (`scanner::lsp::prewarm(...)`).

// Façade re-exports — preserve canonical interface per master plan.
pub mod config;
pub mod prewarm;
pub mod reaper;
pub mod cap;
pub mod fallback;
pub mod sidecar;

// Direct re-exports for ergonomic callers (avoid `scanner::lsp::config::config`).
pub use config::{detect_workspace_root, CsharpSdkStatus, LspSpawnConfig};
pub use prewarm::prewarm;
pub use reaper::{spawn_idle_reaper, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_REAPER_INTERVAL_MS};

// Pass-through from lsp_registry for callers that need the raw registry.
pub use crate::scanner::lsp_registry::{
    global_registry, LspRegistry, DEFAULT_MAX_CLIENTS,
};

// Pass-through from lsp_config for static config entries (FOUND-008).
pub use crate::scanner::lsp_config::{
    CSHARP, CPP, C, GO, JAVASCRIPT, PYTHON, RUST, TYPESCRIPT,
};
