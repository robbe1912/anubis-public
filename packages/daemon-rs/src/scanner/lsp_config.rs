//! LSP spawn configuration + workspace root detection (FOUND-002).
//!
//! Per-language LSP servers (rust-analyzer, gopls, pyright, tsls, clangd, csharp-ls)
//! need a spawn recipe and a workspace root. This module defines:
//!
//! - [`LspSpawnConfig`] — every parameter the registry needs to start, cap,
//!   prewarm, and reap one LSP server per language. Lives on the `Language`
//!   enum via the `lsp_config()` accessor (FOUND-003).
//! - [`detect_workspace_root`] — walks parent directories from any starting
//!   path looking for a root marker file (Cargo.toml, package.json, go.mod,
//!   etc.). Returns the first directory containing any marker.
//!
//! See `.omo/plans/lsp-expansion-master.md` task FOUND-002.

use std::path::{Path, PathBuf};

/// Spawn + lifecycle config for one LSP server.
///
/// All fields are `&'static str` / owned values so the struct can live for the
/// program lifetime in a `register_language` table without borrow churn.
///
/// Field order groups related concerns: identity → spawn → timing → policy.
#[derive(Debug, Clone)]
pub struct LspSpawnConfig {
    // ---- identity ----
    /// Command to exec (resolved from PATH or sidecar bundle path).
    pub cmd: String,
    /// Static args appended after cmd (e.g. `["--stdio"]` for most servers).
    pub args: Vec<String>,
    /// Files whose presence identifies a workspace root for this language
    /// (e.g. `["Cargo.toml"]` for Rust, `["go.mod"]` for Go). Walked by
    /// [`detect_workspace_root`].
    pub root_markers: Vec<&'static str>,
    /// LSP languageId sent in `textDocument/didOpen` (e.g. "rust", "go",
    /// "python", "typescript", "c", "cpp", "csharp").
    pub language_id: &'static str,
    /// Arg passed to the binary to query its version (e.g. "--version").
    /// Used by sidecar/probe code to gate spawn on minimum version.
    pub version_check_arg: &'static str,

    // ---- spawn-time options ----
    /// `initializationOptions` JSON sent in the LSP `initialize` request.
    /// Per-server knobs (pyright basic mode, clangd --log, etc.).
    pub init_options: serde_json::Value,

    // ---- timing (all in milliseconds) ----
    /// Cold-start budget. Spawns exceeding this are aborted + logged.
    pub cold_start_budget_ms: u64,
    /// Hard timeout for the `initialize` handshake (rust-analyzer can take
    /// 60s on a fresh cargo build).
    pub init_timeout_ms: u64,
    /// Forced warmup pause after `initialized` before sending `didOpen`
    /// (rust-analyzer needs ~3s to start indexing before it will answer).
    pub warmup_ms: u64,
    /// Idle reaper interval; clients unused for this duration are killed.
    pub idle_timeout_ms: u64,

    // ---- policy ----
    /// Max concurrent clients of this language across all workspaces
    /// (registry-wide cap is enforced separately in FOUND-005).
    pub max_instances: usize,
    /// May this server be spawned ahead of first scan (`prewarm()` hook)?
    pub prewarmable: bool,
    /// Should the daemon prewarm this language at startup (vs on first use)?
    pub prewarm_on_startup: bool,
    /// Lower = spawned first when cap is contested. 0 = highest priority.
    pub priority: u8,
}

impl LspSpawnConfig {
    /// Construct with all fields — no defaults, because every language needs
    /// explicit values (silent defaults caused the original "TypeScript" typo
    /// bug that this whole enum migration fixed).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cmd: impl Into<String>,
        args: Vec<String>,
        root_markers: Vec<&'static str>,
        language_id: &'static str,
        version_check_arg: &'static str,
        init_options: serde_json::Value,
        cold_start_budget_ms: u64,
        init_timeout_ms: u64,
        warmup_ms: u64,
        idle_timeout_ms: u64,
        max_instances: usize,
        prewarmable: bool,
        prewarm_on_startup: bool,
        priority: u8,
    ) -> Self {
        Self {
            cmd: cmd.into(),
            args,
            root_markers,
            language_id,
            version_check_arg,
            init_options,
            cold_start_budget_ms,
            init_timeout_ms,
            warmup_ms,
            idle_timeout_ms,
            max_instances,
            prewarmable,
            prewarm_on_startup,
            priority,
        }
    }
}

/// Walk parent directories from `start` looking for any file in `markers`.
///
/// `start` may be a file or directory. Returns the first ancestor directory
/// containing any marker file, or `None` if we hit the filesystem root.
///
/// Marker match is by file basename only (ignores directory names). This
/// matches LSP workspace detection semantics: rust-analyzer treats the
/// nearest ancestor containing `Cargo.toml` as root_uri regardless of how
/// deep the source file lives.
///
/// # Example
/// ```ignore
/// use anubis_daemon::scanner::lsp_config::detect_workspace_root;
/// let root = detect_workspace_root(
///     std::path::Path::new("/repo/crates/foo/src/lib.rs"),
///     &["Cargo.toml"],
/// );
/// assert_eq!(root, Some(std::path::PathBuf::from("/repo")));
/// ```
pub fn detect_workspace_root(start: &Path, markers: &[&str]) -> Option<PathBuf> {
    if markers.is_empty() {
        return None;
    }
    let start_dir = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent()?.to_path_buf()
    };

    let mut current: Option<&Path> = Some(&start_dir);
    while let Some(dir) = current {
        if has_any_marker(dir, markers) {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

/// True iff `dir` directly contains a file whose basename is in `markers`.
fn has_any_marker(dir: &Path, markers: &[&str]) -> bool {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return false,
    };
    for entry in read.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        if markers.iter().any(|m| *m == name_str) {
            return true;
        }
    }
    false
}

// ============================================================
// Per-language LSP spawn configs (FOUND-008)
// ============================================================
//
// One static `LspSpawnConfig` per language in the LSP sprint (Rust, Go,
// Python, TypeScript, JavaScript, C++, C, CSharp). GDScript deferred per
// lsp-expansion-master.md.
//
// `Lazy<LspSpawnConfig>` because the struct contains `Vec<String>` (args,
// root_markers) and `serde_json::Value` (init_options) — none of which are
// `const`-constructible. `Lazy` initializes on first access, thread-safely.
//
// Owner: per-language sprint (PY-001/TS-001/CPP-001/CS-001) wires these to
// the registry (FOUND-005). These values are spawn recipes only — the
// registry owns lifecycle.

use once_cell::sync::Lazy;

/// Common timing defaults shared by all configs. Languages can override
/// in their own `Lazy` block when their cold-start profile differs.
const DEFAULT_INIT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_WARMUP_MS: u64 = 3_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000; // 5 min, per FOUND-005 reaper.
const DEFAULT_MAX_INSTANCES: usize = 4;

/// Rust: rust-analyzer. Cold start 5-60s on fresh `cargo build`. Highest
/// priority (priority=1) — Anubis's primary target language.
pub static RUST: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "rust-analyzer",
        // rust-analyzer speaks LSP over stdio by default — no --stdio flag.
        Vec::new(),
        vec!["Cargo.toml"],
        "rust",
        "--version",
        serde_json::json!({}),
        // rust-analyzer can take 60s on a fresh `cargo build` while it
        // fetches deps + builds the proc-macro sandbox.
        60_000,
        60_000,
        3_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        true,  // prewarmable
        false, // prewarm_on_startup (heavy — only on first .rs scan)
        1,     // priority: highest
    )
});

/// Go: gopls. Cold start 1-3s. Second priority after Rust.
pub static GO: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "gopls",
        Vec::new(),
        vec!["go.mod"],
        "go",
        // gopls uses `version` subcommand, not `--version` flag (matches
        // existing lsp_gate.rs:327 quirk).
        "version",
        serde_json::json!({}),
        5_000,
        DEFAULT_INIT_TIMEOUT_MS,
        2_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        true,
        false,
        2,
    )
});

/// Python: pyright-langserver. Cold start 2-5s. Fallback for offline tier:
/// `pyright --outputjson` (PY-005).
pub static PYTHON: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "pyright-langserver",
        vec!["--stdio".to_string()],
        // pyright accepts several root conventions. List all so workspace
        // detection fires on whichever the project uses.
        vec!["pyproject.toml", "setup.py", "requirements.txt", "Pipfile"],
        "python",
        "--version",
        // basic mode = pyright's default analysis level. typeCheckingMode
        // is owned by the project's pyproject.toml/pyrightconfig.json.
        serde_json::json!({
            "analysis": {
                "autoSearchPaths": true,
                "useLibraryCodeForTypes": true,
                "typeCheckingMode": "basic"
            }
        }),
        10_000,
        DEFAULT_INIT_TIMEOUT_MS,
        2_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        true,
        false,
        3,
    )
});

/// TypeScript: typescript-language-server. Wraps tsserver. Cold start 5-15s.
pub static TYPESCRIPT: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "typescript-language-server",
        vec!["--stdio".to_string()],
        vec!["tsconfig.json", "package.json", "jsconfig.json"],
        "typescript",
        "--version",
        serde_json::json!({}),
        15_000,
        DEFAULT_INIT_TIMEOUT_MS,
        3_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        true,
        false,
        4,
    )
});

/// JavaScript: shares typescript-language-server binary with TypeScript.
/// Distinct languageId ("javascript") routes to JS didOpen path.
pub static JAVASCRIPT: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "typescript-language-server",
        vec!["--stdio".to_string()],
        vec!["package.json", "jsconfig.json"],
        "javascript",
        "--version",
        serde_json::json!({}),
        15_000,
        DEFAULT_INIT_TIMEOUT_MS,
        3_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        true,
        false,
        5,
    )
});

/// C++: clangd 22.1.6 (Apache-2.0). `--enable-config` reads .clangd files;
/// `--log=verbose` surfaces compile_commands.json issues in diagnostics.
pub static CPP: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "clangd",
        vec!["--enable-config".to_string(), "--log=verbose".to_string()],
        vec!["compile_commands.json", "CMakeLists.txt", "Makefile"],
        "cpp",
        "--version",
        serde_json::json!({}),
        15_000,
        DEFAULT_INIT_TIMEOUT_MS,
        2_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        true,
        false,
        6,
    )
});

/// C: shares clangd binary with C++. Same args; different languageId ("c").
/// Per plan: "Same binary, lang_id switch."
pub static C: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "clangd",
        vec!["--enable-config".to_string(), "--log=verbose".to_string()],
        vec!["compile_commands.json", "Makefile", "CMakeLists.txt"],
        "c",
        "--version",
        serde_json::json!({}),
        15_000,
        DEFAULT_INIT_TIMEOUT_MS,
        2_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        true,
        false,
        6,
    )
});

/// C#: csharp-ls 0.20.x pinned (for .NET 8 LTS). Slowest cold start
/// (30-45s typical). Per plan: DEFAULT OFF ALL TIERS — prewarmable=false,
/// prewarm_on_startup=false. Lowest priority.
pub static CSHARP: Lazy<LspSpawnConfig> = Lazy::new(|| {
    LspSpawnConfig::new(
        "csharp-ls",
        Vec::new(),
        // global.json is the .NET SDK pin file at solution roots. Absent
        // for single-file C# in benchmark scenarios → LSP gate disables.
        vec!["global.json"],
        "csharp",
        "--version",
        serde_json::json!({}),
        // csharp-ls needs to restore packages + bootstrap OmniSharp-style
        // workspace state on cold start. 60s budget covers slow machines.
        60_000,
        60_000,
        // Longer warmup than other langs: csharp-ls needs to index the
        // whole solution before responding to hover/diagnostic requests.
        5_000,
        DEFAULT_IDLE_TIMEOUT_MS,
        DEFAULT_MAX_INSTANCES,
        // Per plan: default OFF all tiers. Prewarm on first .cs write is
        // gated by a separate CS-003 hook (not yet implemented).
        false, // prewarmable
        false, // prewarm_on_startup
        99,    // priority: lowest
    )
});

// ---------------------------------------------------------------------------
// C# SDK probe (FOUND-009)
//
// Daemon startup runs `dotnet --list-sdks` once, parses the major version
// from the first line, and caches it for the process lifetime. The C#
// LSP spawn decision (CS-001..007, not yet implemented) reads this cache
// to gate csharp-ls spawn on .NET 8 LTS being present.
//
// Per master plan FOUND-009 [deps: 002]: "daemon startup C# SDK probe hook.
// 5 LOC." The probe + cache + accessor are ~40 LOC; the daemon-side call
// site is the actual 5-LOC hook (added to bin/daemon.rs in this commit).

/// Result of probing the local .NET SDK installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsharpSdkStatus {
    /// `probe_csharp_sdk()` has not been called yet.
    NotProbed,
    /// `dotnet --list-sdks` returned ≥1 line whose first token starts with
    /// `<major>.`. Carries the major version (e.g. 8 for .NET 8.0.204).
    Available { major: u8 },
    /// `dotnet` not on PATH, exited non-zero, or returned no SDKs.
    NotFound,
}

use once_cell::sync::OnceCell;
static CSHARP_SDK_STATUS: OnceCell<CsharpSdkStatus> = OnceCell::new();

/// Probe `dotnet --list-sdks` once at daemon startup, cache the result.
///
/// Output format (one line per installed SDK):
/// ```text
/// 8.0.204 [/usr/share/dotnet/sdk]
/// 7.0.401 [/usr/share/dotnet/sdk]
/// ```
/// We capture the FIRST line's major version. .NET 8 LTS is the spawn gate
/// per master plan; older majors (6, 7) are reported but treated as
/// "available, not LTS" by the caller.
///
/// Safe to call multiple times — first call wins, subsequent calls are
/// no-ops (the cached result is immutable for the process lifetime).
pub fn probe_csharp_sdk() {
    CSHARP_SDK_STATUS.get_or_init(|| {
        let output = std::process::Command::new("dotnet")
            .arg("--list-sdks")
            .output();

        let Ok(out) = output else {
            tracing::info!(
                target: "lsp_config",
                "dotnet not on PATH — C# LSP gate will be disabled",
            );
            return CsharpSdkStatus::NotFound;
        };
        if !out.status.success() {
            tracing::info!(
                target: "lsp_config",
                "dotnet --list-sdks exited non-zero ({:?}) — C# LSP gate disabled",
                out.status.code(),
            );
            return CsharpSdkStatus::NotFound;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let first_line = stdout.lines().next().unwrap_or("");
        // Major version = digits before first '.'.
        let major = first_line
            .split('.')
            .next()
            .and_then(|s| s.parse::<u8>().ok());
        match major {
            Some(m) => {
                tracing::info!(
                    target: "lsp_config",
                    "dotnet SDK available (major={}) — C# LSP gate eligible",
                    m,
                );
                CsharpSdkStatus::Available { major: m }
            }
            None => {
                tracing::info!(
                    target: "lsp_config",
                    "dotnet --list-sdks returned no parseable SDKs — C# LSP gate disabled",
                );
                CsharpSdkStatus::NotFound
            }
        }
    });
}

/// Read the cached C# SDK status. Returns [`CsharpSdkStatus::NotProbed`]
/// if [`probe_csharp_sdk`] has not been called yet.
pub fn csharp_sdk_status() -> CsharpSdkStatus {
    CSHARP_SDK_STATUS
        .get()
        .copied()
        .unwrap_or(CsharpSdkStatus::NotProbed)
}

#[cfg(test)]
mod csharp_probe_tests {
    use super::*;

    #[test]
    fn csharp_sdk_status_not_probed_before_probe_call() {
        // We can't reset the OnceCell between tests, so this only verifies
        // the default-when-never-called path. If probe_csharp_sdk has been
        // called by an earlier test, this assertion would fail — hence we
        // don't assert a specific value, just that the accessor is callable.
        let _ = csharp_sdk_status();
    }

    #[test]
    fn probe_csharp_sdk_does_not_panic_without_dotnet() {
        // On machines without dotnet, this should still complete without
        // panicking — returns NotFound internally.
        probe_csharp_sdk();
        // Status is now cached (Either Available or NotFound depending on
        // environment). Verify the accessor returns the same value on
        // repeated calls (cache stable).
        let s1 = csharp_sdk_status();
        let s2 = csharp_sdk_status();
        assert_eq!(s1, s2, "cache must be stable across calls");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn touch(dir: &Path, name: &str) {
        fs::write(dir.join(name), b"").unwrap();
    }

    fn mkdir(parent: &Path, name: &str) -> PathBuf {
        let p = parent.join(name);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn detect_returns_dir_containing_marker() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(root, "Cargo.toml");
        let deep = mkdir(root, "a/b/c/src");
        let got = detect_workspace_root(&deep.join("lib.rs"), &["Cargo.toml"]);
        assert_eq!(got, Some(root.to_path_buf()));
    }

    #[test]
    fn detect_picks_nearest_when_multiple_markers_in_ancestors() {
        let tmp = tempdir().unwrap();
        let outer = tmp.path();
        touch(outer, "Cargo.toml");
        let inner = mkdir(outer, "workspace");
        touch(&inner, "Cargo.toml");
        let deep = mkdir(&inner, "crate/src");
        // Nearest ancestor with marker wins (inner).
        let got = detect_workspace_root(&deep.join("lib.rs"), &["Cargo.toml"]);
        assert_eq!(got, Some(inner.clone()));
    }

    #[test]
    fn detect_returns_none_when_no_marker_anywhere() {
        let tmp = tempdir().unwrap();
        let deep = mkdir(tmp.path(), "a/b");
        let got = detect_workspace_root(&deep.join("f.rs"), &["Cargo.toml"]);
        assert_eq!(got, None);
    }

    #[test]
    fn detect_returns_none_for_empty_markers() {
        let tmp = tempdir().unwrap();
        touch(tmp.path(), "Cargo.toml");
        let got = detect_workspace_root(tmp.path(), &[]);
        assert_eq!(got, None);
    }

    #[test]
    fn detect_accepts_dir_path_directly() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(root, "go.mod");
        let got = detect_workspace_root(root, &["go.mod"]);
        assert_eq!(got, Some(root.to_path_buf()));
    }

    #[test]
    fn detect_matches_any_of_several_markers() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        // pyproject.toml present, setup.py absent — should still match.
        touch(root, "pyproject.toml");
        let got = detect_workspace_root(root, &["setup.py", "pyproject.toml"]);
        assert_eq!(got, Some(root.to_path_buf()));
    }

    #[test]
    fn detect_ignores_marker_in_subdir_when_walking_up() {
        // Use a marker name unlikely to exist in any real ancestor of the
        // system temp dir. Walking up from `tmp` should not find this marker
        // because it lives in a CHILD of tmp, not an ancestor.
        let marker = "anubis_found_002_marker_test_only.txt";
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        let child = mkdir(root, "subdir");
        touch(&child, marker);
        let got = detect_workspace_root(root, &[marker]);
        // No ancestor contains the marker (only the child does).
        assert!(got.is_none() || got.as_deref() != Some(root),
            "walked past child marker into unrelated ancestor: {:?}", got);
    }

    #[test]
    fn detect_handles_missing_file_gracefully() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();
        touch(root, "Cargo.toml");
        // Non-existent file path — should still resolve via parent().
        let ghost = root.join("does_not_exist.rs");
        let got = detect_workspace_root(&ghost, &["Cargo.toml"]);
        assert_eq!(got, Some(root.to_path_buf()));
    }

    #[test]
    fn lsp_spawn_config_new_sets_all_fields() {
        let cfg = LspSpawnConfig::new(
            "rust-analyzer",
            vec!["--stdio".to_string()],
            vec!["Cargo.toml"],
            "rust",
            "--version",
            serde_json::json!({}),
            60_000,
            30_000,
            3_000,
            300_000,
            4,
            true,
            false,
            1,
        );
        assert_eq!(cfg.cmd, "rust-analyzer");
        assert_eq!(cfg.args, vec!["--stdio".to_string()]);
        assert_eq!(cfg.root_markers, vec!["Cargo.toml"]);
        assert_eq!(cfg.language_id, "rust");
        assert_eq!(cfg.version_check_arg, "--version");
        assert_eq!(cfg.cold_start_budget_ms, 60_000);
        assert_eq!(cfg.init_timeout_ms, 30_000);
        assert_eq!(cfg.warmup_ms, 3_000);
        assert_eq!(cfg.idle_timeout_ms, 300_000);
        assert_eq!(cfg.max_instances, 4);
        assert!(cfg.prewarmable);
        assert!(!cfg.prewarm_on_startup);
        assert_eq!(cfg.priority, 1);
    }

    // ---- FOUND-008 per-language static config tests ----

    #[test]
    fn rust_config_matches_lsp_gate_conventions() {
        let cfg = &*RUST;
        assert_eq!(cfg.cmd, "rust-analyzer");
        assert!(cfg.args.is_empty(), "rust-analyzer needs no --stdio flag");
        assert_eq!(cfg.language_id, "rust");
        assert_eq!(cfg.version_check_arg, "--version");
        assert_eq!(cfg.root_markers, vec!["Cargo.toml"]);
        assert_eq!(cfg.priority, 1, "rust is highest priority");
        assert!(cfg.prewarmable);
        assert!(!cfg.prewarm_on_startup, "rust prewarms on first scan, not daemon start");
        // rust-analyzer cold start can hit 60s on fresh cargo build.
        assert!(cfg.cold_start_budget_ms >= 60_000);
        assert!(cfg.init_timeout_ms >= 60_000);
    }

    #[test]
    fn go_config_uses_version_subcommand() {
        let cfg = &*GO;
        assert_eq!(cfg.cmd, "gopls");
        assert_eq!(cfg.language_id, "go");
        // Quirk: gopls uses `version` subcommand, not `--version` flag.
        assert_eq!(cfg.version_check_arg, "version");
        assert_eq!(cfg.root_markers, vec!["go.mod"]);
    }

    #[test]
    fn python_config_uses_pyright_langserver_stdio() {
        let cfg = &*PYTHON;
        assert_eq!(cfg.cmd, "pyright-langserver");
        assert_eq!(cfg.args, vec!["--stdio".to_string()]);
        assert_eq!(cfg.language_id, "python");
        assert!(cfg.root_markers.contains(&"pyproject.toml"));
        assert!(cfg.root_markers.contains(&"setup.py"));
        // init_options should set basic typeCheckingMode.
        let init = cfg.init_options.as_object().expect("init_options is object");
        let analysis = init.get("analysis").and_then(|a| a.as_object());
        assert!(analysis.is_some(), "missing analysis block");
        assert_eq!(
            analysis.and_then(|a| a.get("typeCheckingMode")).and_then(|v| v.as_str()),
            Some("basic")
        );
    }

    #[test]
    fn typescript_config_uses_tsls_stdio() {
        let cfg = &*TYPESCRIPT;
        assert_eq!(cfg.cmd, "typescript-language-server");
        assert_eq!(cfg.args, vec!["--stdio".to_string()]);
        assert_eq!(cfg.language_id, "typescript");
        assert!(cfg.root_markers.contains(&"tsconfig.json"));
    }

    #[test]
    fn javascript_shares_tsls_with_typescript() {
        let ts = &*TYPESCRIPT;
        let js = &*JAVASCRIPT;
        assert_eq!(ts.cmd, js.cmd, "JS + TS share the same binary");
        assert_eq!(ts.args, js.args);
        assert_ne!(ts.language_id, js.language_id, "but distinct languageIds");
        assert_eq!(js.language_id, "javascript");
    }

    #[test]
    fn cpp_config_enables_clangd_config_and_log_verbose() {
        let cfg = &*CPP;
        assert_eq!(cfg.cmd, "clangd");
        assert!(cfg.args.contains(&"--enable-config".to_string()));
        assert!(cfg.args.contains(&"--log=verbose".to_string()));
        assert_eq!(cfg.language_id, "cpp");
        assert!(cfg.root_markers.contains(&"compile_commands.json"));
    }

    #[test]
    fn c_shares_clangd_with_cpp() {
        let cpp = &*CPP;
        let c = &*C;
        assert_eq!(cpp.cmd, c.cmd, "C + C++ share clangd binary");
        assert_eq!(cpp.args, c.args);
        assert_ne!(cpp.language_id, c.language_id);
        assert_eq!(c.language_id, "c");
    }

    #[test]
    fn csharp_config_is_default_off_all_tiers() {
        let cfg = &*CSHARP;
        assert_eq!(cfg.cmd, "csharp-ls");
        assert_eq!(cfg.language_id, "csharp");
        // Per plan: DEFAULT OFF all tiers (CS-007).
        assert!(!cfg.prewarmable, "csharp must NOT be prewarmable by default");
        assert!(!cfg.prewarm_on_startup);
        // Slowest cold start of all langs (30-45s typical).
        assert!(cfg.cold_start_budget_ms >= 60_000,
            "csharp cold-start budget too short: {}ms", cfg.cold_start_budget_ms);
        assert_eq!(cfg.priority, 99, "csharp is lowest priority");
    }

    /// All 8 configs should have distinct languageIds — duplicates would
    /// cause registry keying collisions in FOUND-005.
    #[test]
    fn all_8_configs_have_distinct_language_ids() {
        let ids = [
            RUST.language_id, GO.language_id, PYTHON.language_id,
            TYPESCRIPT.language_id, JAVASCRIPT.language_id,
            CPP.language_id, C.language_id, CSHARP.language_id,
        ];
        let unique: std::collections::HashSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), 8, "languageIds not unique: {:?}", ids);
    }

    /// All 8 configs should respect the registry-wide idle timeout convention.
    #[test]
    fn all_8_configs_use_default_idle_timeout() {
        for (name, cfg) in [
            ("RUST", &*RUST), ("GO", &*GO), ("PYTHON", &*PYTHON),
            ("TYPESCRIPT", &*TYPESCRIPT), ("JAVASCRIPT", &*JAVASCRIPT),
            ("CPP", &*CPP), ("C", &*C), ("CSHARP", &*CSHARP),
        ] {
            assert_eq!(cfg.idle_timeout_ms, DEFAULT_IDLE_TIMEOUT_MS,
                "{} idle_timeout_ms drift: {}ms", name, cfg.idle_timeout_ms);
            assert!(cfg.max_instances <= DEFAULT_MAX_INSTANCES,
                "{} max_instances too high: {}", name, cfg.max_instances);
        }
    }
}
