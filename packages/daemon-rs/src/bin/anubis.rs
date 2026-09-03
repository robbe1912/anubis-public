// anubis-dashboard — CLI + dashboard client.
// Console app for license activation, status checks, harness management, and
// launching the ratatui dashboard. Connects to anubis-daemon via HTTP.

use anubis_daemon::{
    api, config, dashboard, docs_cli, docs_fetcher, harness, license, proxy, setup, symbols_cli,
    trial, VERSION,
};
use std::io::{self, BufRead, Write};
use std::process;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

fn print_help() {
    println!(
        "anubis {} — hallucination detection proxy\n\n\
         USAGE:\n    anubis <COMMAND> [OPTIONS]\n\n\
         COMMANDS:\n    \
         auth [token] [--trial|--license|--remove]\n    \
                             Activate license/trial token (no-op in this build — enforcement disabled).\n    \
         status     Check if daemon is alive\n    \
         dashboard  Open TUI dashboard\n    \
         daemon     Run daemon in foreground\n    \
         setup      Register daemon for auto-start on system boot\n    \
         harness    Manage harness routing (list/enable/disable)\n    \
         docs       Manage local doc cache (~/.anubis/docs/) for scanner Layer 2\n    \
                   docs add <source>         Install docs (npm, owner/repo, URL, path)\n    \
          symbols    Manage local symbol cache (~/.anubis/symbols/) for scanner Layer 1.5\n    \
                    symbols add <library>    Fetch + parse + cache (godot, rust:<crate>, ts:<pkg>)\n    \
                    symbols sync [path]      Scan project, cache YOUR symbols (.ts/.rs)\n    \
                    symbols list             Show cached libraries\n    \
         update     Check for new version and self-update\n    \
         uninstall  Remove anubis (binaries, shortcuts, config, boot entries)\n    \
         handle-url Handle anubis:// deep links (called by OS)\n    \
         help       Show this message\n\n\
         NOTE:\n    \
         License enforcement is disabled in this build — all commands\n    \
         run without a license or trial. See license.rs for details.\n\n\
         OPTIONS:\n    \
         --port <N>     Override config port (default: 7878)\n    \
         --host <ADDR>  Override config host (default: 127.0.0.1)\n    \
         --version, -v  Print version\n    \
         --help, -h     Show this message",
        VERSION
    );
}

/// License gate — refuses entry to subcommands that require an active license or trial.
///
/// Used by: `dashboard`, `daemon`, `setup`. Auth/trial-activation paths skip this
/// (they ARE the activation). The internal anubis-daemon binary has its own
/// copy of this check at the top of main() — scheduled-task boot won't spawn
/// the daemon process unless license is valid.
fn require_license_or_exit() {
    let has_paid = license::has_license();
    let trial_state = trial::check_trial();
    let is_activated = has_paid || matches!(trial_state, trial::TrialState::Active { .. });
    if !is_activated {
        match trial_state {
            trial::TrialState::Expired { exp } => {
                let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(exp as i64, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or("unknown".to_string());
                eprintln!("[anubis] Trial expired on {}.", dt);
            }
            trial::TrialState::Invalid => {
                eprintln!("[anubis] Trial token invalid.");
            }
            trial::TrialState::NotActivated => {
                eprintln!("[anubis] No license or trial activated.");
            }
            _ => {}
        }
        eprintln!("[anubis] Activate with: anubis auth");
        eprintln!("[anubis] (License enforcement is disabled in this build — nothing to activate.)");
        process::exit(1);
    }
}

/// Parse `--port N` and `--host H` flags for the `anubis daemon` subcommand.
fn parse_daemon_opts(args: &[String]) -> proxy::DaemonOpts {
    let mut port = None;
    let mut host = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if let Some(v) = args.get(i + 1) {
                    port = v.parse().ok();
                    i += 2;
                    continue;
                }
            }
            "--host" => {
                if let Some(v) = args.get(i + 1) {
                    host = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    proxy::DaemonOpts { port, host }
}

/// Auto-register daemon for system boot after successful license/trial activation.
///
/// Called from every activation success path. Silent on success, logs warning
/// on failure (activation itself still succeeded — boot registration is a bonus).
/// Idempotent: setup_daemon overwrites existing scheduled task / launch agent.
fn try_register_for_boot() {
    let cfg = config::load_config();
    let exe = daemon_exe_path();
    match setup::setup_daemon(&exe, cfg.proxy.port, &cfg.proxy.host) {
        Ok(()) => {
            println!(
                "[anubis] daemon registered for auto-start on boot (port {})",
                cfg.proxy.port
            );
        }
        Err(e) => {
            // Don't fail activation just because boot registration failed.
            // User can run `anubis setup` manually later.
            println!("[anubis] warning: could not register daemon for boot: {}", e);
            println!("[anubis] run 'anubis setup' manually to enable auto-start");
        }
    }
}

#[tokio::main]
async fn main() {
    anubis_daemon::init_logging();

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match cmd {
        "" => {
            // No args — print help, require explicit subcommand
            print_help();
        }
        "--version" | "-v" => {
            println!("{}", VERSION);
        }
        "--help" | "-h" | "help" => {
            print_help();
        }
        "auth" | "activate" => {
            run_auth(&args[2..]).await;
        }
        "status" => {
            api::run_status().await;
        }
        "dashboard" => {
            require_license_or_exit();
            ensure_daemon_running().await;
            if let Err(e) = dashboard::run().await {
                println!("[anubis] dashboard error: {}", e);
                process::exit(1);
            }
        }
        "daemon" => {
            require_license_or_exit();
            let opts = parse_daemon_opts(&args[2..]);
            if let Err(e) = proxy::start_daemon(opts).await {
                tracing::error!("daemon fatal error: {}", e);
                let crash_path = anubis_daemon::dirs_home()
                    .join(".anubis")
                    .join("daemon-crash.log");
                let _ = std::fs::write(&crash_path, format!("{}: {}\n", chrono::Utc::now(), e));
                process::exit(1);
            }
        }
        "handle-url" => {
            if let Some(url) = args.get(2) {
                handle_deep_link(url);
            } else {
                println!("[anubis] no URL provided to handle-url");
                process::exit(1);
            }
        }
        "setup" => {
            require_license_or_exit();
            let opts = parse_opts(&args[2..]);
            let cfg = config::load_config();
            let port = opts.0.unwrap_or(cfg.proxy.port);
            let host = opts.1.unwrap_or_else(|| cfg.proxy.host.clone());
            let exe = daemon_exe_path();
            match setup::setup_daemon(&exe, port, &host) {
                Ok(()) => {
                    println!("[anubis] daemon registered for auto-start on boot");
                    println!("[anubis] port: {} host: {}", port, host);
                }
                Err(e) => {
                    println!("[anubis] setup failed: {}", e);
                    process::exit(1);
                }
            }
        }
        "harness" => {
            run_harness(&args[2..]);
        }
        "docs" => {
            run_docs(&args[2..]).await;
        }
        "symbols" => {
            run_symbols(&args[2..]).await;
        }
        "update" => {
            run_update().await;
        }
        "uninstall" => {
            run_uninstall();
        }
        _ => {
            println!("unknown command: {}\n", cmd);
            print_help();
            process::exit(1);
        }
    }
}

/// Default flow when no subcommand given.
async fn run_default(_args: &[String]) {
    let has_paid = license::has_license();
    let trial_state = trial::check_trial();
    let is_activated = has_paid || matches!(trial_state, trial::TrialState::Active { .. });

    if !is_activated {
        match trial_state {
            trial::TrialState::Expired { exp } => {
                let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(exp as i64, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or("unknown".to_string());
                println!("[anubis] Trial expired on {}.", dt);
                println!("[anubis] (License enforcement is disabled in this build.)");
                process::exit(1);
            }
            trial::TrialState::Invalid => {
                println!(
                    "[anubis] Trial token invalid. Re-activate with 'anubis auth --trial <token>'."
                );
                process::exit(1);
            }
            trial::TrialState::NotActivated => {
                println!("[anubis] No trial or license found.");
                println!("[anubis] (License enforcement is disabled in this build — all features unlocked.)\n");
                print!("Enter license key or trial token (or press Enter to skip): ");
                let _ = io::stdout().flush();
                let line = tokio::task::spawn_blocking(|| {
                    let mut buf = String::new();
                    let _ = io::stdin().read_line(&mut buf);
                    buf
                })
                .await
                .unwrap_or_default();
                let token = line.trim();
                if !token.is_empty() {
                    // Auto-detect: JWT starts with eyJ, Keygen key doesn't
                    if token.starts_with("eyJ") && token.matches('.').count() >= 2 {
                        match trial::activate_trial(token) {
                            Ok(claims) => {
                                let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(
                                    claims.exp as i64,
                                    0,
                                )
                                .map(|d| d.format("%Y-%m-%d").to_string())
                                .unwrap_or_else(|| "unknown".into());
                                println!(
                                    "[anubis] Trial active for {}. Expires {}.",
                                    claims.sub, dt
                                );
                            }
                            Err(e) => {
                                println!("[anubis] Trial activation failed: {}", e);
                            }
                        }
                    } else {
                        match license::activate_license(token).await {
                            Ok(state) => {
                                println!("[anubis] License activated — tier: {:?}", state.tier);
                            }
                            Err(e) => {
                                println!("[anubis] License activation failed: {}", e);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Ensure daemon running
    ensure_daemon_running().await;

    // Launch dashboard
    if let Err(e) = dashboard::run().await {
        println!("[anubis] dashboard error: {}", e);
        process::exit(1);
    }
}

/// Check if daemon is running. If not, spawn anubis-daemon as detached process.
async fn ensure_daemon_running() {
    let cfg = config::load_config();
    let port = cfg.proxy.port;
    let url = format!("http://127.0.0.1:{}/__anubis/ping", port);

    // Try to reach existing daemon
    if let Ok(res) = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        if res.status().is_success() {
            return;
        }
    }

    // Daemon not running — spawn anubis-daemon
    println!("[anubis] starting daemon...");
    let exe = daemon_exe_path();

    #[cfg(target_os = "windows")]
    let spawn_result = process::Command::new(&exe)
        .args(["--port", &port.to_string()])
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .creation_flags(0x00000008) // DETACHED_PROCESS
        .spawn();

    #[cfg(not(target_os = "windows"))]
    let spawn_result = process::Command::new(&exe)
        .args(["--port", &port.to_string()])
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .spawn();

    match spawn_result {
        Ok(child) => {
            std::mem::forget(child);
            // Wait for daemon to be ready
            for _ in 0..50 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                if let Ok(res) = reqwest::Client::new()
                    .get(&url)
                    .timeout(std::time::Duration::from_millis(500))
                    .send()
                    .await
                {
                    if res.status().is_success() {
                        println!("[anubis] daemon ready on port {}", port);
                        return;
                    }
                }
            }
            println!("[anubis] warning: daemon did not become ready within 10s");
        }
        Err(e) => {
            println!("[anubis] failed to spawn daemon: {}", e);
        }
    }
}

/// Find anubis-daemon binary path.
/// Looks next to current exe, then in PATH.
fn daemon_exe_path() -> String {
    let daemon_name = if cfg!(windows) {
        "anubis-daemon.exe"
    } else {
        "anubis-daemon"
    };

    // Try next to current exe (same directory)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(daemon_name);
            if sibling.exists() {
                return sibling.to_string_lossy().to_string();
            }
        }
    }

    // Fallback: assume it's on PATH
    daemon_name.to_string()
}

/// Unified license/trial activation.
async fn run_auth(args: &[String]) {
    if args.first().map(|s| s.as_str()) == Some("--remove") {
        // Always remove local credentials regardless of API success
        if trial::has_active_trial() {
            trial::deactivate_trial();
            println!("[anubis] trial deactivated.");
        }
        // Try Keygen deactivation but don't fail if it errors
        match license::deactivate().await {
            Ok(()) => println!("[anubis] license deactivated."),
            Err(e) => {
                // API may fail (key already revoked, network down, auth expired)
                // Still remove local keychain entry so user can re-auth
                license::delete_local_credentials();
                println!("[anubis] license removed locally (API: {})", e);
            }
        }
        // Unregister daemon from system boot — no license, no auto-start
        match setup::uninstall_daemon() {
            Ok(()) => println!("[anubis] daemon unregistered from system boot."),
            Err(e) => println!("[anubis] warning: could not unregister boot entry: {}", e),
        }
        return;
    }

    let mut force_trial = false;
    let mut force_license = false;
    let mut token_arg: Option<String> = None;

    for arg in args {
        match arg.as_str() {
            "--trial" => force_trial = true,
            "--license" => force_license = true,
            s if !s.starts_with("--") => token_arg = Some(s.to_string()),
            _ => {}
        }
    }

    // If user provided a token explicitly, always re-activate.
    // Remove any existing credentials first.
    if token_arg.is_some() {
        if trial::has_active_trial() {
            trial::deactivate_trial();
        }
        license::delete_local_credentials();
    } else if license::has_license() || trial::has_active_trial() {
        // No token provided + already authenticated → nothing to do
        println!("[anubis] license already active. Use 'anubis auth --remove' to deactivate.");
        return;
    }

    let token = if let Some(t) = token_arg {
        t
    } else {
        print!("Enter license key or trial token: ");
        let _ = io::stdout().flush();
        let line = tokio::task::spawn_blocking(|| {
            let mut buf = String::new();
            let _ = io::stdin().read_line(&mut buf);
            buf
        })
        .await
        .unwrap_or_default();
        line.trim().to_string()
    };

    if token.is_empty() {
        println!("[anubis] no token entered");
        process::exit(1);
    }

    let is_trial = if force_trial {
        true
    } else if force_license {
        false
    } else {
        token.starts_with("eyJ") && token.matches('.').count() == 2
    };

    if is_trial {
        println!("[anubis] activating trial...");
        match trial::activate_trial(&token) {
            Ok(claims) => {
                let dt = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                println!("[anubis] Trial active for {}. Expires {}.", claims.sub, dt);
                try_register_for_boot();
            }
            Err(e) => {
                println!("[anubis] trial activation failed: {}", e);
                process::exit(1);
            }
        }
    } else {
        println!("[anubis] validating license...");
        match license::activate_license(&token).await {
            Ok(state) => {
                println!("[anubis] License activated — tier: {:?}", state.tier);
                try_register_for_boot();
            }
            Err(e) => {
                println!("[anubis] License validation failed: {}", e);
                process::exit(1);
            }
        }
    }
}

/// Handle anubis:// deep link.
fn handle_deep_link(url: &str) {
    if !url.starts_with("anubis://") {
        println!("[anubis] not an anubis:// URL: {}", url);
        process::exit(1);
    }

    let path = &url["anubis://".len()..];
    let token = if let Some(qm) = path.find('?') {
        let query = &path[qm + 1..];
        let mut found: Option<String> = None;
        for pair in query.split('&') {
            if let Some(eq) = pair.find('=') {
                let key = &pair[..eq];
                let value = &pair[eq + 1..];
                if key == "token" {
                    found = Some(
                        value
                            .replace("%2E", ".")
                            .replace("%2d", "-")
                            .replace("%2D", "-")
                            .replace("%5f", "_")
                            .replace("%5F", "_"),
                    );
                    break;
                }
            }
        }
        found
    } else {
        None
    };

    let token = match token {
        Some(t) => t,
        None => {
            println!("[anubis] no token in URL: {}", url);
            process::exit(1);
        }
    };

    println!("[anubis] activating trial from deep link...");
    match trial::activate_trial(&token) {
        Ok(claims) => {
            let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(claims.exp as i64, 0)
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "unknown".into());
            println!("[anubis] Trial active for {}. Expires {}.", claims.sub, dt);
            try_register_for_boot();
        }
        Err(e) => {
            println!("[anubis] Trial activation failed: {}", e);
            process::exit(1);
        }
    }
}

/// Harness management.
fn run_harness(args: &[String]) {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");
    let cfg = config::load_config();
    let url = cfg.proxy_url();

    match sub {
        "list" => {
            for h in harness::list_harnesses(&url) {
                let routed = h.providers.iter().filter(|p| p.routed).count();
                println!(
                    "  {}  ({}/{})  {}",
                    h.id,
                    routed,
                    h.providers.len(),
                    h.config_path
                );
                for p in &h.providers {
                    let mark = if p.routed { "✓" } else { " " };
                    println!(
                        "    {} {} → {}",
                        mark,
                        p.id,
                        if p.routed {
                            &p.original_url
                        } else {
                            "[not routed]"
                        }
                    );
                }
            }
        }
        "enable" => {
            let hid = args.get(1).map(|s| s.as_str());
            let pid = args.get(2).map(|s| s.as_str());
            match (hid, pid) {
                (Some(hid), Some(pid)) => match harness::enable_provider(hid, pid, &url) {
                    Ok(()) => println!("[anubis] enabled {}::{}", hid, pid),
                    Err(e) => println!("[anubis] error: {}", e),
                },
                (Some(hid), None) => {
                    let harnesses = harness::list_harnesses(&url);
                    if let Some(h) = harnesses.iter().find(|h| h.id == hid) {
                        for p in &h.providers {
                            if !p.routed {
                                let _ = harness::enable_provider(hid, &p.id, &url);
                            }
                        }
                        println!("[anubis] enabled all providers in {}", hid);
                    }
                }
                _ => println!("usage: anubis harness enable <harness> [provider]"),
            }
        }
        "disable" => {
            let hid = args.get(1).map(|s| s.as_str());
            let pid = args.get(2).map(|s| s.as_str());
            match (hid, pid) {
                (Some(hid), Some(pid)) => match harness::disable_provider(hid, pid) {
                    Ok(()) => println!("[anubis] disabled {}::{}", hid, pid),
                    Err(e) => println!("[anubis] error: {}", e),
                },
                (Some(hid), None) => {
                    let harnesses = harness::list_harnesses(&url);
                    if let Some(h) = harnesses.iter().find(|h| h.id == hid) {
                        for p in &h.providers {
                            if p.routed {
                                let _ = harness::disable_provider(hid, &p.id);
                            }
                        }
                        println!("[anubis] disabled all providers in {}", hid);
                    }
                }
                _ => println!("usage: anubis harness disable <harness> [provider]"),
            }
        }
        _ => println!("usage: anubis harness <list|enable|disable> [args]"),
    }
}

/// Local docs cache management.
///
/// Subcommands:
///   `docs`                  Show usage
///   `docs list`             List installed doc sets
///   `docs add <source>`     Fetch from npm/GitHub/Context7/website/local path
///   `docs add <lib>`        Fetch latest npm version via Worker (fallback local)
///   `docs add <lib>@<ver>`  Fetch pinned npm version via Worker (fallback local)
///   `docs remove <name>`    Remove by slug or original source
///   `docs refresh [<name>]` Re-fetch one doc set (or all if omitted)
async fn run_docs(args: &[String]) {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("help");
    match sub {
        "list" => {
            let sets = docs_fetcher::list_doc_sets();
            if sets.is_empty() {
                println!("[anubis] no doc sets installed under ~/.anubis/docs/");
                println!("[anubis] try: anubis docs add react");
                return;
            }
            println!("Installed doc sets (~/.anubis/docs/):");
            for (slug, meta) in sets {
                match meta {
                    Some(m) => {
                        let version = m.version.map(|v| format!(" v{}", v)).unwrap_or_default();
                        let when = chrono::DateTime::parse_from_rfc3339(&m.fetched_at)
                            .ok()
                            .map(|d| d.format("%Y-%m-%d").to_string())
                            .unwrap_or_else(|| m.fetched_at.clone());
                        println!(
                            "  {} ({}, {}, {} file{})",
                            slug,
                            m.strategy,
                            when,
                            m.files.len(),
                            if m.files.len() == 1 { "" } else { "s" }
                        );
                        let _ = version; // suppressed from output for now
                    }
                    None => println!("  {} (no meta.json)", slug),
                }
            }
        }
        "add" => {
            let input = match args.get(1) {
                Some(s) if !s.is_empty() => s.clone(),
                _ => {
                    println!("usage: anubis docs add <source>");
                    println!("");
                    println!("Sources:");
                    println!("  npm package           react, @scope/name, react@18.2.0");
                    println!("  npm latest via Worker react, @scope/name (resolved remotely)");
                    println!("  GitHub repo           owner/repo");
                    println!("  Context7 lookup       any library name");
                    println!("  Website URL           https://example.com/docs");
                    println!("  Local path            ./docs, /abs/path, C:\\path");
                    println!("");
                    println!("Worker-fetched npm docs are cached locally and refreshed");
                    println!("automatically by the scanner.");
                    println!("");
                    println!("Env vars (optional):");
                    println!(
                        "  CONTEXT7_API_KEY      Higher Context7 quota (1K/mo vs 200/10d anon)"
                    );
                    println!("  GITHUB_TOKEN          Raises GitHub API limit (60→5K/hr)");
                    return;
                }
            };

            if docs_cli::is_remote_eligible(&input) {
                run_docs_add_remote(&input).await;
            } else {
                run_docs_add_local(&input).await;
            }
        }
        "remove" => {
            let target = match args.get(1) {
                Some(s) if !s.is_empty() => s.clone(),
                _ => {
                    println!("usage: anubis docs remove <name-or-source>");
                    return;
                }
            };
            // Accept either a raw slug or the original source string.
            let slug = docs_fetcher::slug_for_input(&target).unwrap_or_else(|_| target.clone());
            match docs_fetcher::remove_doc_set(&slug) {
                Ok(true) => println!("[anubis] removed {}", slug),
                Ok(false) => {
                    println!("[anubis] no doc set named: {}", slug);
                    std::process::exit(1);
                }
                Err(e) => {
                    println!("[anubis] remove failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "refresh" => {
            let target = args.get(1).cloned();
            match target {
                Some(name) => {
                    // Refresh one: try to read its meta.json to recover original source.
                    let slug = docs_fetcher::slug_for_input(&name).unwrap_or_else(|_| name.clone());
                    let meta = docs_fetcher::read_meta(&slug).ok().flatten();
                    let source = meta
                        .as_ref()
                        .map(|m| m.source.clone())
                        .unwrap_or_else(|| name.clone());
                    println!("[anubis] refreshing {} from {}...", slug, source);
                    match docs_fetcher::fetch_from_input(&source).await {
                        Ok(path) => println!("[anubis] refreshed at {}", path.display()),
                        Err(e) => {
                            println!("[anubis] refresh failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                None => {
                    // Refresh all
                    let sets = docs_fetcher::list_doc_sets();
                    if sets.is_empty() {
                        println!("[anubis] nothing to refresh");
                        return;
                    }
                    let mut ok = 0usize;
                    let mut fail = 0usize;
                    for (slug, meta) in sets {
                        let source = meta
                            .as_ref()
                            .map(|m| m.source.clone())
                            .unwrap_or_else(|| slug.clone());
                        println!("[anubis] refreshing {}...", slug);
                        match docs_fetcher::fetch_from_input(&source).await {
                            Ok(_) => ok += 1,
                            Err(e) => {
                                println!("[anubis] {} failed: {}", slug, e);
                                fail += 1;
                            }
                        }
                    }
                    println!("[anubis] refreshed {} ok, {} failed", ok, fail);
                }
            }
        }
        _ => {
            println!("usage: anubis docs <list|add|remove|refresh> [args]");
            println!("");
            println!("Manage local doc cache for hallucination scanner.");
            println!(
                "Fetched docs live under ~/.anubis/docs/<slug>/ and feed scanner::search_docs."
            );
            println!("");
            println!("Examples:");
            println!("  anubis docs add react");
            println!("  anubis docs add godotengine/godot");
            println!("  anubis docs add https://docs.python.org/3/");
            println!("  anubis docs list");
            println!("  anubis docs remove react");
        }
    }
}

/// `docs add <input>` path for npm-like inputs (no URL/path/owner-repo).
///
/// Prefers the remote Worker. On any Worker failure (unreachable, version
/// resolution miss, fetch miss) falls back to `docs_fetcher::fetch_from_input`
/// which owns the npm-registry → GitHub → Context7 → website → local chain.
async fn run_docs_add_remote(input: &str) {
    let (lib, ver_opt) = docs_cli::parse_lib_at_version(input);

    // Resolve version when not pinned. Worker miss → local fallback.
    let version = match ver_opt {
        Some(v) => v,
        None => {
            println!("[anubis] resolving latest version for {}...", lib);
            match docs_fetcher::resolve_remote_latest(&lib).await {
                Some(v) => {
                    println!("[anubis] latest: {}", v);
                    v
                }
                None => {
                    println!("[anubis] Worker unreachable, falling back to local strategy");
                    run_docs_add_local(input).await;
                    return;
                }
            }
        }
    };

    println!("[anubis] fetching {}@{}...", lib, version);
    match docs_fetcher::fetch_remote(&lib, &version).await {
        Some(markdown) => persist_remote_doc_set(&lib, &version, markdown),
        None => {
            println!("[anubis] remote fetch failed; falling back to local strategy");
            run_docs_add_local(input).await;
        }
    }
}

/// Write the Worker-fetched markdown to ~/.anubis/docs/<slug>/ and invalidate
/// the scanner cache so the new docs are visible immediately.
fn persist_remote_doc_set(lib: &str, version: &str, markdown: String) {
    let slug = docs_fetcher::slugify(lib);
    let filename = format!("{}.md", slug);
    let files = vec![(filename.clone(), markdown)];

    // `source` is the lib name so `docs refresh` can re-resolve via the same
    // remote path (detect_source("react") → Npm → fetch_from_input falls back
    // to Context7; the version field preserves the pinned release).
    let meta = docs_fetcher::DocMeta {
        source: lib.to_string(),
        strategy: "remote".to_string(),
        fetched_at: chrono::Utc::now().to_rfc3339(),
        version: Some(version.to_string()),
        files: files.iter().map(|(f, _)| f.clone()).collect(),
    };

    match docs_fetcher::write_doc_set(&slug, &files, &meta) {
        Ok(path) => {
            anubis_daemon::scanner::invalidate_docs_cache();
            println!("[anubis] installed at {}", path.display());
        }
        Err(e) => {
            println!("[anubis] cache write failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// `docs add <input>` path for URLs, paths, and owner/repo refs — and the
/// fallback when the remote Worker cannot satisfy an npm request.
async fn run_docs_add_local(input: &str) {
    println!("[anubis] fetching {}...", input);
    match docs_fetcher::fetch_from_input(input).await {
        Ok(path) => println!("[anubis] installed at {}", path.display()),
        Err(e) => {
            println!("[anubis] error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Parse --port/--host flags.
fn parse_opts(args: &[String]) -> (Option<u16>, Option<String>) {    let mut port: Option<u16> = None;
    let mut host: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if let Some(v) = args.get(i + 1) {
                    port = v.parse().ok();
                }
                i += 2;
            }
            "--host" => {
                if let Some(v) = args.get(i + 1) {
                    host = Some(v.clone());
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    (port, host)
}

// ── Self-update ────────────────────────────────────────────────────────────

const GITHUB_REPO: &str = "robbe1912/anubis-public";

/// `anubis symbols <subcommand>` — manage local symbol cache.
async fn run_symbols(args: &[String]) {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("help");
    match sub {
        "add" => {
            let input = match args.get(1) {
                Some(s) if !s.is_empty() => s,
                _ => {
                    // No argument — run auto-detect to streamline onboarding.
                    println!("[anubis] no library specified — running auto-detect...");
                    println!("[anubis] (pass a library to skip: 'godot', 'rust:serde', 'ts:react')");
                    match symbols_cli::run_add("auto").await {
                        Ok(summary) => {
                            println!("[anubis] {}", summary);
                            return;
                        }
                        Err(e) => {
                            println!("[anubis] auto-detect: {}", e);
                            println!("[anubis]");
                            println!("[anubis] usage: anubis symbols add <library>[@version]");
                            println!("[anubis] examples:");
                            println!("[anubis]   anubis symbols add godot");
                            println!("[anubis]   anubis symbols add godot@4.3-stable");
                            println!("[anubis]   anubis symbols add rust:serde");
                            println!("[anubis]   anubis symbols add rust:reqwest@0.12.8");
                            println!("[anubis]   anubis symbols add ts:react");
                            println!("[anubis]   anubis symbols add auto      # scan cwd");
                            process::exit(1);
                        }
                    }
                }
            };
            match symbols_cli::run_add(input).await {
                Ok(summary) => println!("[anubis] {}", summary),
                Err(e) => {
                    println!("[anubis] error: {}", e);
                    process::exit(1);
                }
            }
        }
        "list" => {
            let cache = match anubis_daemon::symbols::cache::SymbolCache::open() {
                Ok(c) => c,
                Err(e) => {
                    println!("[anubis] error opening symbol cache: {}", e);
                    process::exit(1);
                }
            };
            for (lib, ver, count) in cache.list_libraries() {
                println!("  {}@{} ({} symbols)", lib, ver, count);
            }
        }
        "sync" => {
            let path = args.get(1).map(|s| s.as_str());
            match symbols_cli::run_sync(path).await {
                Ok(summary) => println!("[anubis] {}", summary),
                Err(e) => {
                    println!("[anubis] error: {}", e);
                    process::exit(1);
                }
            }
        }
        "fetch" => {
            println!("[anubis] fetching dependency + project symbols...");
            match symbols_cli::run_fetch().await {
                Ok(summary) => println!("[anubis] {}", summary),
                Err(e) => {
                    println!("[anubis] error: {}", e);
                    process::exit(1);
                }
            }
        }
        "help" | "-h" | "--help" => {
            println!("anubis symbols — manage local symbol cache");
            println!();
            println!("USAGE:");
            println!("    anubis symbols add [library]   Fetch + parse + cache");
            println!("                                     (no arg = auto-detect project)");
            println!("    anubis symbols sync [path]     Scan project, cache local symbols");
            println!("    anubis symbols fetch           add auto + sync in one step");
            println!("    anubis symbols list            List cached libraries");
            println!();
            println!("SUPPORTED LIBRARIES (add):");
            println!("    auto                  Scan cwd for project markers");
            println!("    godot                 Godot engine classes (GitHub XML)");
            println!("    rust:<crate>          Rust crate via docs.rs rustdoc JSON");
            println!("    rust:auto             Read Cargo.toml, fetch all [dependencies]");
            println!("    ts:<package>          TypeScript package via unpkg .d.ts");
            println!("    ts:auto               Read package.json, fetch all deps");
            println!();
            println!("SYNC:");
            println!("    Walks your project (default: cwd), parses source files");
            println!("    (.ts/.tsx/.rs), and caches symbols as library=<project>.");
            println!("    Lets Layer 1.5 catch hallucinations on YOUR classes.");
            println!();
            println!("EXAMPLES:");
            println!("    anubis symbols add               # auto-detect cwd");
            println!("    anubis symbols add godot");
            println!("    anubis symbols add rust:serde");
            println!("    anubis symbols add rust:auto     # all Cargo.toml deps");
            println!("    anubis symbols add ts:react");
            println!("    anubis symbols add ts:auto       # all package.json deps");
            println!("    anubis symbols sync              # scan current dir");
            println!("    anubis symbols sync ../other-project      # scan specific dir");
            println!("    anubis symbols fetch             # add auto + sync in one step");
            println!("    anubis symbols list");
        }
        _ => {
            println!("unknown symbols subcommand: {}\n", sub);
            println!("available: add, sync, fetch, list, help");
            process::exit(1);
        }
    }
}

async fn run_update() {
    println!("[anubis] checking for updates...");

    let platform = detect_platform();
    let platform = match platform {
        Some(p) => p,
        None => {
            println!("[anubis] unsupported platform for auto-update");
            process::exit(1);
        }
    };

    // Fetch latest release from GitHub API
    let api_url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        GITHUB_REPO
    );
    let client = match reqwest::Client::builder()
        .user_agent("anubis-updater")
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            println!("[anubis] failed to create HTTP client: {}", e);
            process::exit(1);
        }
    };

    let resp = match client.get(&api_url).send().await {
        Ok(r) => r,
        Err(e) => {
            println!("[anubis] failed to check for updates: {}", e);
            println!(
                "[anubis] check your internet connection or visit https://github.com/{}/releases",
                GITHUB_REPO
            );
            process::exit(1);
        }
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            println!("[anubis] failed to parse release info: {}", e);
            process::exit(1);
        }
    };

    let latest_tag = body
        .pointer("/tag_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let current_tag = format!("v{}", VERSION);

    println!("[anubis] current: {} | latest: {}", current_tag, latest_tag);

    if latest_tag == current_tag {
        println!("[anubis] already up to date");
        return;
    }

    // Find asset for our platform
    let asset_name = format!("anubis-{}.zip", platform);
    #[cfg(not(target_os = "windows"))]
    let asset_name = format!("anubis-{}.tar.gz", platform);

    let download_url = body
        .pointer("/assets")
        .and_then(|v| v.as_array())
        .and_then(|assets| {
            assets.iter().find_map(|a| {
                let name = a.pointer("/name")?.as_str()?;
                if name == asset_name {
                    a.pointer("/browser_download_url")?
                        .as_str()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
        });

    let download_url = match download_url {
        Some(u) => u,
        None => {
            println!(
                "[anubis] no binary found for {} in latest release",
                platform
            );
            println!("[anubis] visit https://github.com/{}/releases", GITHUB_REPO);
            process::exit(1);
        }
    };

    // Determine install directory
    let install_dir = install_dir();
    let temp_file = std::env::temp_dir().join(&asset_name);

    // Download
    println!("[anubis] downloading {}...", asset_name);
    let resp = match client.get(&download_url).send().await {
        Ok(r) => r,
        Err(e) => {
            println!("[anubis] download failed: {}", e);
            process::exit(1);
        }
    };

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            println!("[anubis] download failed: {}", e);
            process::exit(1);
        }
    };

    match std::fs::write(&temp_file, &bytes) {
        Ok(()) => {}
        Err(e) => {
            println!("[anubis] failed to write download: {}", e);
            process::exit(1);
        }
    }

    // Stop daemon if running
    println!("[anubis] stopping daemon...");
    stop_daemon();

    // Extract / copy
    println!("[anubis] installing...");

    #[cfg(target_os = "windows")]
    {
        // Use PowerShell to extract zip
        let ps_cmd = format!(
            "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
            temp_file.display(),
            install_dir.display()
        );
        let _ = std::process::Command::new("powershell")
            .args(["-Command", &ps_cmd])
            .output();
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Use tar to extract
        let _ = std::process::Command::new("tar")
            .args([
                "xzf",
                temp_file.to_str().unwrap_or(""),
                "-C",
                install_dir.to_str().unwrap_or(""),
            ])
            .output();

        // Set permissions
        let daemon = install_dir.join("anubis-daemon");
        let dashboard = install_dir.join("anubis-dashboard");
        let _ =
            std::fs::set_permissions(&daemon, std::os::unix::fs::PermissionsExt::from_mode(0o755));
        let _ = std::fs::set_permissions(
            &dashboard,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );
    }

    // Clean up
    let _ = std::fs::remove_file(&temp_file);

    // Restart daemon
    println!("[anubis] restarting daemon...");
    start_daemon();

    println!("[anubis] updated to {} successfully!", latest_tag);
}

fn stop_daemon() {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", "anubis-daemon.exe", "/F"])
            .output();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::process::Command::new("pkill")
            .args(["-f", "anubis-daemon"])
            .output();
    }
}

fn start_daemon() {
    let dir = install_dir();
    #[cfg(target_os = "windows")]
    let exe = dir.join("anubis-daemon.exe");
    #[cfg(not(target_os = "windows"))]
    let exe = dir.join("anubis-daemon");

    if exe.exists() {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let _ = std::process::Command::new(&exe)
                .creation_flags(0x00000008) // DETACHED_PROCESS
                .spawn();
        }
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::process::CommandExt;
            let _ = std::process::Command::new(&exe).process_group(0).spawn();
        }
    }
}

fn install_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .map(|p| std::path::PathBuf::from(p).join("anubis"))
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                    .join(".anubis")
                    .join("bin")
            })
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(".anubis")
            .join("bin")
    }
}

fn detect_platform() -> Option<String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    match (os, arch) {
        ("windows", "x86_64") => Some("windows-x64".into()),
        ("windows", "aarch64") => Some("windows-arm64".into()),
        ("macos", "aarch64") => Some("darwin-arm64".into()),
        ("macos", "x86_64") => Some("darwin-x64".into()),
        ("linux", "x86_64") => Some("linux-x64".into()),
        ("linux", "aarch64") => Some("linux-arm64".into()),
        _ => None,
    }
}

// ── Uninstall ──────────────────────────────────────────────────────────────

fn run_uninstall() {
    println!("[anubis] uninstalling...");

    // Stop daemon
    println!("[anubis] stopping daemon...");
    stop_daemon();

    // Remove startup shortcut / launchd / systemd
    let _exe = daemon_exe_path();
    let _ = setup::uninstall_daemon();

    // Remove binaries
    let dir = install_dir();
    println!("[anubis] removing binaries from {}...", dir.display());
    let _ = std::fs::remove_dir_all(&dir);

    // Remove config + data
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    let config_dir = std::path::PathBuf::from(&home).join(".anubis");

    if config_dir.exists() {
        print!(
            "[anubis] remove config + data at {}? [y/N] ",
            config_dir.display()
        );
        let _ = io::stdout().flush();
        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input);
        if input.trim().eq_ignore_ascii_case("y") {
            let _ = std::fs::remove_dir_all(&config_dir);
            println!("[anubis] config removed");
        } else {
            println!("[anubis] config kept at {}", config_dir.display());
        }
    }

    // Remove from PATH (Windows)
    #[cfg(target_os = "windows")]
    {
        let path = std::env::var("Path").unwrap_or_default();
        let dir_str = dir.to_string_lossy().to_string();
        let new_path: Vec<&str> = path.split(';').filter(|p| *p != dir_str).collect();
        let joined = new_path.join(";");
        // Use PowerShell SetEnvironmentVariable with computed path — setx truncates at 1024 chars
        let _ = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "[Environment]::SetEnvironmentVariable('Path', '{}', 'User')",
                    joined.replace('\'', "''")
                ),
            ])
            .output();
    }

    println!("[anubis] uninstalled.");
}
