// anubis — hallucination detection proxy
// Shared library used by both anubis-daemon and anubis-dashboard binaries.

pub mod api;
pub mod audit;
pub mod cache_warming;
pub mod scan_log;
pub mod classify;
pub mod config;
pub mod dashboard;
pub mod docs_cli;
pub mod docs_fetcher;
pub mod error;
pub mod harness;
pub mod injection;
pub mod license;
pub mod project_root;
pub mod proxy;
pub mod registry;
pub mod remote_docs;
pub mod scanner;
pub mod setup;
pub mod stats;
pub mod symbols;
pub mod symbols_cli;
pub mod trial;
pub mod verification;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize file logging to ~/.anubis/anubis.log
pub fn init_logging() {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let log_path = dirs_home().join(".anubis").join("anubis.log");
    let _ = std::fs::create_dir_all(log_path.parent().unwrap());

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);

    if let Ok(file) = file {
        // Read RUST_LOG env var if set (allows runtime debug control via
        // RUST_LOG=scanner=debug,proxy=debug etc.). Falls back to "info"
        // when unset, preserving default behavior.
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));
        fmt()
            .with_writer(file)
            .with_ansi(false)
            .with_env_filter(filter)
            .try_init()
            .ok();
    }

    // ── Install panic hook ───────────────────────────────────────────────
    //
    // Default Rust panic behavior writes to stderr. For a daemon launched
    // via Windows Startup .lnk or `Start-Process -WindowStyle Hidden`,
    // stderr is not captured anywhere — panics die silently, leaving NO
    // trace in anubis.log. The user sees the daemon disappear mid-request
    // with no clue why.
    //
    // This hook writes the panic payload + location + backtrace to the
    // same file tracing uses, so the next startup can show what happened.
    //
    // Critical because the scanner paths touch many third-party libraries
    // (regex, quick-xml, serde_json, reqwest) where individual deserialization
    // or pattern-match panics are possible on adversarial inputs.
    let log_path_hook = log_path.clone();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let ts = chrono::Utc::now().to_rfc3339();
        let msg = format!(
            "\n{ts} PANIC anubis-daemon: {}\nlocation: {}\nbacktrace:\n{}\n",
            info.payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("<non-string panic payload>"),
            info.location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "<unknown>".to_string()),
            bt,
        );
        // Try the log file first (same one tracing uses).
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(&log_path_hook) {
            use std::io::Write;
            let _ = f.write_all(msg.as_bytes());
        }
        // Also try stderr in case someone is watching.
        eprintln!("{}", msg);
    }));
}

/// Cross-platform home directory
pub fn dirs_home() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
    }
}
pub mod anubis_probe;
pub mod doc_provider;
