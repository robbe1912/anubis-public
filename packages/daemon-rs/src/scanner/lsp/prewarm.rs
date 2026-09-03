//! Prewarm API (COLD-001 façade for FOUND-007 prewarm hook).
//!
//! Prewarming starts an LSP server ahead of first scan so the cold-start
//! latency (rust-analyzer 5-60s, csharp-ls 30-45s) overlaps with whatever
//! else the daemon is doing. By the time `suppress_fps` calls
//! `get_or_spawn`, the client is warm.
//!
//! Per master plan COLD-003: prewarm is invoked from `proxy::rs` tool_call
//! extraction (no file watcher). The proxy sees the agent write a `.rs`
//! file → calls `scanner::lsp::prewarm(Language::Rust, project_root)` →
//! spawn happens in background.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::scanner::language::Language;
use crate::scanner::lsp_gate::LspState;
use crate::scanner::lsp_registry::{global_registry, LspRegistry};

/// Prewarm an LSP client for (workspace, language) without consuming the
/// result. No-op if the language has no spawn config (Java/Godot langs).
///
/// Spawns happen on the SAME tokio runtime as the caller. The prewarm
/// `.await` returns once the client is registered (not necessarily
/// fully indexed — LSP initialize handshake completes, indexing may
/// continue in background per `warmup_ms` in `LspSpawnConfig`).
///
/// # Example
/// ```ignore
/// use anubis_daemon::scanner::lsp;
/// use anubis_daemon::scanner::language::Language;
///
/// // On observing a tool_call that wrote /repo/crates/foo/src/lib.rs:
/// lsp::prewarm(Language::Rust, std::path::Path::new("/repo")).await;
/// ```
pub async fn prewarm(language: Language, project_root: &Path) {
    // Skip prewarm for languages without a spawn config — they'd just
    // spawn an empty LspState that gets immediately reaped.
    if language.lsp_config().is_none() {
        return;
    }
    let workspace = project_root.to_path_buf();
    let lang_for_spawn = language;
    let root_for_spawn = project_root.to_path_buf();
    let _ = global_registry()
        .prewarm(workspace, language, || {
            let lang = lang_for_spawn;
            let root = root_for_spawn.clone();
            async move { spawn_state_for(lang, &root).await }
        })
        .await;
}

/// Spawn an `LspState` for (language, project_root). Internal helper used
/// by both `prewarm` and the registry's `get_or_spawn` (via the closure
/// wired in FOUND-006's `lsp_gate::get_client`).
///
/// Extracted here so the spawn recipe lives in ONE place — the `lsp/`
/// subsystem — rather than being duplicated in `lsp_gate::get_client`.
/// FOUND-006's closure calls this; future COLD tasks can swap the impl
/// (e.g. sidecar binary path resolution in COLD-008) without touching
/// the registry API.
async fn spawn_state_for(language: Language, project_root: &Path) -> LspState {
    let cfg = match language.lsp_config() {
        Some(c) => c,
        None => return LspState::empty(),
    };
    let binary = cfg.cmd.as_str();
    let version_arg = cfg.version_check_arg;
    let root_str = project_root.to_string_lossy().to_string();

    // Check if the LSP server is on PATH before spawning.
    let mut check = crate::scanner::command_hidden_tokio(binary);
    check
        .arg(version_arg)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match check.status().await {
        Ok(s) if s.success() => {}
        Ok(_) => {
            tracing::info!(
                target: "lsp",
                "{} {} check failed — LSP gate disabled for {:?}",
                binary,
                version_arg,
                language,
            );
            return LspState::empty();
        }
        Err(_) => {
            tracing::info!(
                target: "lsp",
                "{} not found on PATH — LSP gate disabled for {:?}",
                binary,
                language,
            );
            return LspState::empty();
        }
    }

    match crate::scanner::lsp_gate::LspClient::start(binary, project_root).await {
        Some(client) => {
            tracing::info!(
                target: "lsp",
                "{} started for {:?}",
                binary,
                project_root,
            );
            LspState {
                client: Some(client),
                root: root_str,
                last_used: std::time::Instant::now(),
            }
        }
        None => {
            tracing::warn!(
                target: "lsp",
                "{} failed to start — LSP gate disabled for {:?}",
                binary,
                language,
            );
            LspState::empty()
        }
    }
}

// Prevent unused-import warnings if the call sites shrink — these types
// are part of the documented public surface even when not directly named.
#[allow(dead_code)]
fn _type_assertions() -> (
    Arc<Mutex<LspState>>,
    &'static LspRegistry,
    PathBuf,
) {
    (
        Arc::new(Mutex::new(LspState::empty())),
        global_registry(),
        PathBuf::new(),
    )
}
