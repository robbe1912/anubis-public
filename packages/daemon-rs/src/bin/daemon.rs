// anubis-daemon — background proxy daemon.
// Compiled with windows_subsystem = "windows" to prevent console window.
// Scheduled task launches this — runs completely hidden.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anubis_daemon::{license, proxy, trial};

#[tokio::main]
async fn main() {
    anubis_daemon::init_logging();

    // License gate — daemon refuses to start without active license or trial.
    // Scheduled task may fire on boot before user activates; exit silently.
    let has_paid = license::has_license();
    let trial_state = trial::check_trial();
    let is_activated = has_paid || matches!(trial_state, trial::TrialState::Active { .. });
    if !is_activated {
        tracing::warn!(
            "daemon refusing to start — no active license or trial (paid={}, trial={:?})",
            has_paid,
            trial_state
        );
        std::process::exit(1);
    }

    let args: Vec<String> = std::env::args().collect();
    let opts = proxy::DaemonOpts {
        port: parse_flag(&args, "--port").and_then(|v| v.parse().ok()),
        host: parse_flag(&args, "--host"),
    };

    // Seed symbol cache from bundle file(s) in ~/.anubis/.
    // Loads symbol_bundle.jsonl (primary) and any symbol_bundle_*.jsonl
    // (e.g. symbol_bundle_spring.jsonl for Spring Boot, symbol_bulk.jsonl
    // for Godot). Each file is idempotent (INSERT OR REPLACE on
    // (library, version, path)).
    {
        let anubis_dir = anubis_daemon::dirs_home().join(".anubis");
        if let Ok(cache) = anubis_daemon::symbols::cache::SymbolCache::open() {
            let primary = anubis_dir.join("symbol_bundle.jsonl");
            if primary.exists() {
                match cache.seed_from_jsonl(&primary) {
                    Ok(n) => tracing::info!("Seeded {} symbols from primary bundle", n),
                    Err(e) => tracing::warn!("Primary bundle seed failed: {}", e),
                }
            }
            // Load auxiliary bundles (symbol_bundle_*.jsonl) — covers
            // Spring Boot, npm extensions, Rust extended, Godot bulk, etc.
            if let Ok(entries) = std::fs::read_dir(&anubis_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = match name.to_str() { Some(s) => s, None => continue };
                    if !name_str.starts_with("symbol_bundle_")
                        || !name_str.ends_with(".jsonl") {
                        continue;
                    }
                    let path = entry.path();
                    match cache.seed_from_jsonl(&path) {
                        Ok(n) => tracing::info!(
                            "Seeded {} symbols from {}",
                            n, name_str
                        ),
                        Err(e) => tracing::warn!(
                            "Auxiliary bundle {} seed failed: {}",
                            name_str, e
                        ),
                    }
                }
            }
        }
    }

    // Refresh models.dev registry in the background (non-blocking). Used by the
    // harness layer to resolve provider → upstream URLs when agent configs are
    // hijacked (Anubis→Anubis circular detection). Cache lives at
    // ~/.anubis/registry-cache.json with 24h TTL — daemon boot is a good time
    // to refresh since it doesn't block startup and the cache will be warm by
    // the time the dashboard is opened.
    tokio::spawn(async {
        if let Err(e) = anubis_daemon::registry::refresh().await {
            tracing::warn!("models.dev registry refresh failed: {e:#}");
        }
    });

    // FOUND-009: probe .NET SDK once at startup. Cached in OnceCell for the
    // process lifetime; read by C# LSP spawn decision later (CS-001..007).
    // Non-blocking on success (~10ms typical); failure path logs + caches
    // NotFound so csharp-ls spawn gates off cleanly.
    anubis_daemon::scanner::lsp_config::probe_csharp_sdk();

    if let Err(e) = proxy::start_daemon(opts).await {
        tracing::error!("daemon fatal error: {}", e);
        // Also write to a crash file for debugging (stderr invisible on windows_subsystem)
        let crash_path = anubis_daemon::dirs_home()
            .join(".anubis")
            .join("daemon-crash.log");
        let _ = std::fs::write(&crash_path, format!("{}: {}\n", chrono::Utc::now(), e));
        std::process::exit(1);
    }
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    let flag_eq = format!("{}=", flag);
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).cloned();
        }
        if arg.starts_with(&flag_eq) {
            return Some(arg[flag_eq.len()..].to_string());
        }
    }
    None
}
