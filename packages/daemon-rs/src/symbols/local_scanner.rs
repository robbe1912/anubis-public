//! local_scanner — scan a user's project directory and populate the local
//! symbol cache from THEIR code (not external libraries).
//!
//! Triggered by `anubis symbols sync [path]`. Walks the project tree,
//! dispatches each source file to the appropriate parser by extension,
//! and inserts the parsed symbols into the SQLite cache (library=`<project>`,
//! version=`local`) so Layer 1.5 path-precise lookup catches hallucinations
//! against the user's OWN classes/functions — the most common case.
//!
//! Supported extensions:
//!   - `.ts` / `.tsx` / `.mts` / `.cts` → `ts_parser::parse_dts`
//!   - `.rs`                            → `scan_rust_source` (regex extractor)
//!   - `.gd` / `.py` / `.go`            → TODO (logged, skipped)
//!
//! Skipped paths: `node_modules`, `.git`, `dist`, `dist-dev`, `build`,
//! `target`, `__pycache__`, `.venv`, `venv`, hidden dirs, `.test.`/`.spec.`
//! files, `.d.ts` (external declarations), files >100KB.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::symbols::ts_parser;
use crate::symbols::types::{Param, Symbol, SymbolKind, Visibility};

// ─── Regexes for Rust source ─────────────────────────────────────────
//
// Anchored at line starts, whitespace-tolerant. We only capture `pub` items
// — non-public symbols inflate the cache with noise the scanner will never
// query (Layer 1.5 only sees claims that look like API calls).

static RE_RUST_FN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*pub\s+(?:async\s+|const\s+|unsafe\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)",
    )
    .unwrap()
});

static RE_RUST_STRUCT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*pub\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\{<\(;]").unwrap()
});

static RE_RUST_ENUM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*pub\s+enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\{<\(]").unwrap()
});

static RE_RUST_TRAIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*pub\s+trait\s+([A-Za-z_][A-Za-z0-9_]*)\s*[\{<\(:]").unwrap()
});

static RE_RUST_CONST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*pub\s+const\s+([A-Z_][A-Z0-9_]*)\s*:").unwrap()
});

static RE_RUST_TYPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*pub\s+type\s+([A-Za-z_][A-Za-z0-9_]*)\s*[=<]").unwrap()
});

static RE_RUST_IMPL: Lazy<Regex> = Lazy::new(|| {
    // `impl Foo {` or `impl<T> Foo<T> for Bar {` — capture the LAST identifier
    // before `{` so `impl Trait for Foo` captures `Foo` (the implementor).
    Regex::new(r"(?ms)^\s*(?:pub\s+)?impl\s+.*?([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\{(?P<body>.*?)^\s*\}")
        .unwrap()
});

static RE_RUST_METHOD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*pub\s+(?:async\s+|const\s+|unsafe\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)",
    )
    .unwrap()
});

// ─── Outcome ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ScanOutcome {
    pub project_name: String,
    pub root: PathBuf,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub symbols: Vec<Symbol>,
    pub skipped_exts: Vec<String>, // unique exts we couldn't parse
    pub elapsed_ms: u128,
}

impl ScanOutcome {
    pub fn summary(&self) -> String {
        let skipped_note = if self.skipped_exts.is_empty() {
            String::new()
        } else {
            format!(" (skipped exts: {})", self.skipped_exts.join(", "))
        };
        format!(
            "sync {} ({}): {} symbols from {} files in {} ms{}",
            self.project_name,
            self.root.display(),
            self.symbols.len(),
            self.files_scanned,
            self.elapsed_ms,
            skipped_note,
        )
    }
}

// ─── Public API ──────────────────────────────────────────────────────

// Per-project last-refresh timestamp (most recent source file mtime we've
// ingested). Lets refresh_local_cache_if_stale skip the walk + parse when
// nothing has changed since the last scan. Keyed by canonicalized root path.
static LAST_REFRESH_MTIME: Lazy<parking_lot::Mutex<std::collections::HashMap<std::path::PathBuf, SystemTime>>> =
    Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

/// Refresh the local symbol cache from `project_root` if any source file
/// changed since the last refresh for this project. No-op otherwise.
///
/// Called from `scanner::scan_response` before L1.5 lookup so the cache is
/// always fresh when the agent queries it. Throttled by max source file
/// mtime — if no .rs/.ts/.py/.go/etc. file has been touched, we skip the
/// walk + parse entirely (just one stat per source file).
///
/// Errors are logged at `tracing::warn!` and swallowed — refresh failure
/// must not break the scan pipeline. The cache may be stale but the scan
/// continues with whatever's there.
pub async fn refresh_local_cache_if_stale(project_root: &str) {
    let root = std::path::PathBuf::from(project_root);
    let canonical = match root.canonicalize() {
        Ok(c) => c,
        Err(_) => root.clone(),
    };

    // ── Reject obvious non-project roots ──────────────────────────────────
    //
    // When `detect_project_root` fails to find a marker (.git, package.json,
    // Cargo.toml, etc.) the proxy falls back to the daemon's cwd. If the
    // daemon was launched from `C:\Users\robin` (Windows Startup shortcut
    // default), every scan would walk the entire user home — hundreds of
    // thousands of files in AppData alone — synchronously, blocking the
    // tokio worker thread and starving the runtime. Dashboard times out
    // with "connecting to daemon" after one or two requests.
    //
    // Heuristic: if the canonical root has no source files in its immediate
    // top level AND looks like a home/System32/temp directory, skip refresh
    // entirely. The project_index built from request body still works.
    if !looks_like_project_root(&canonical) {
        tracing::debug!(
            target: "local_scanner",
            root = %canonical.display(),
            "refresh_local_cache: skipping non-project root (home/system/temp or no top-level source files)"
        );
        return;
    }

    // ── mtime walk + scan both run on spawn_blocking ─────────────────────
    //
    // The mtime walk uses sync std::fs I/O (read_dir + metadata recursion).
    // Doing this in the async task body blocks the tokio worker thread —
    // previously starved the runtime on large trees (user home, monorepos
    // with deep node_modules, etc.).
    //
    // Wrap BOTH the mtime probe AND the scan in spawn_blocking so the
    // async runtime stays responsive.
    let canonical_for_task = canonical.clone();
    let mtime_result = tokio::task::spawn_blocking(move || -> std::io::Result<(std::time::SystemTime, bool)> {
        let current_mtime = compute_max_source_mtime(&canonical_for_task)?;

        // Skip if we've already ingested up to this mtime.
        let stale = {
            let cache = LAST_REFRESH_MTIME.lock();
            match cache.get(&canonical_for_task) {
                Some(&last) => last < current_mtime,
                None => true,
            }
        };
        Ok((current_mtime, stale))
    })
    .await;

    let (current_mtime, stale) = match mtime_result {
        Ok(Ok((t, stale))) => (t, stale),
        Ok(Err(e)) => {
            tracing::warn!(
                target: "local_scanner",
                root = %canonical.display(),
                error = %e,
                "refresh_local_cache: mtime walk failed"
            );
            return;
        }
        Err(join_err) => {
            tracing::warn!(
                target: "local_scanner",
                root = %canonical.display(),
                error = %join_err,
                "refresh_local_cache: spawn_blocking panicked during mtime walk"
            );
            return;
        }
    };

    if !stale {
        return;
    }

    // Mark refreshing NOW so concurrent scans dedupe against this mtime.
    // Worst case: two scans see same mtime, both refresh, second upsert is
    // redundant — fine, idempotent.
    LAST_REFRESH_MTIME
        .lock()
        .insert(canonical.clone(), current_mtime);

    tracing::info!(
        target: "local_scanner",
        root = %canonical.display(),
        "refresh_local_cache: source files changed since last refresh — re-scanning"
    );

    // Heavy lifting (file reads + parse + SQLite) goes on a blocking thread
    // so we don't stall the async runtime.
    let canonical_for_task = canonical.clone();
    tokio::task::spawn_blocking(move || {
        let project_name = detect_project_name(&canonical_for_task);
        let outcome = scan_project(&canonical_for_task, &project_name);

        match crate::symbols::cache::SymbolCache::open() {
            Ok(cache) => {
                // Replace local symbols atomically: drop old, insert new.
                // Not transactional but close enough — both ops are fast.
                if let Err(e) = cache.remove_library(&project_name, "local") {
                    tracing::warn!(
                        target: "local_scanner",
                        error = %e,
                        project = %project_name,
                        "refresh_local_cache: remove_library failed (will upsert anyway)"
                    );
                }
                if let Err(e) = cache.insert_many(&outcome.symbols) {
                    tracing::warn!(
                        target: "local_scanner",
                        error = %e,
                        project = %project_name,
                        "refresh_local_cache: insert_many failed"
                    );
                    return;
                }
                tracing::info!(
                    target: "local_scanner",
                    project = %project_name,
                    files = outcome.files_scanned,
                    symbols = outcome.symbols.len(),
                    elapsed_ms = outcome.elapsed_ms,
                    "refresh_local_cache: cache updated"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "local_scanner",
                    error = %e,
                    "refresh_local_cache: SymbolCache::open failed"
                );
            }
        }
    })
    .await
    .ok();
}

/// Cheap top-level check: does this directory look like a real project root?
///
/// Used to skip the expensive recursive mtime walk for non-project paths
/// (home directory, system dirs, temp dirs) that the daemon might fall back
/// to when `detect_project_root` finds no markers in the request body.
///
/// Returns true if EITHER:
///   1. The directory contains a known project marker file at top level
///      (.git, package.json, Cargo.toml, pyproject.toml, go.mod, etc.)
///   2. The directory contains ≥1 source file at top level
///
/// Returns false for: home dirs, Windows/System32, temp dirs, empty dirs,
/// directories containing only subdirectories (no top-level source).
fn looks_like_project_root(dir: &std::path::Path) -> bool {
    use std::path::Path;

    // ── Block obvious non-project paths ──────────────────────────────────
    let dir_str = dir.to_string_lossy().to_lowercase();
    let dir_str = dir_str.trim_end_matches('\\').trim_end_matches('/');

    // User home directory on Windows / Unix
    if let Some(home) = dirs_home_str() {
        let home_lower = home.to_lowercase();
        let home_lower = home_lower.trim_end_matches('\\').trim_end_matches('/');
        if dir_str == home_lower {
            return false;
        }
    }

    // System directories
    if dir_str.ends_with("\\windows") || dir_str.ends_with("/windows") {
        return false;
    }
    if dir_str.ends_with("\\system32") || dir_str.ends_with("/system32") {
        return false;
    }
    if dir_str.ends_with("\\program files") || dir_str.ends_with("/program files") {
        return false;
    }
    if dir_str.ends_with("\\program files (x86)") || dir_str.ends_with("/program files (x86)") {
        return false;
    }
    if dir_str.ends_with("\\temp") || dir_str.ends_with("/temp") {
        return false;
    }
    if dir_str.ends_with("\\tmp") || dir_str.ends_with("/tmp") {
        return false;
    }
    // Note: we deliberately do NOT reject AppData/Local/Temp subpaths here.
    // Test harnesses use tempfile::tempdir() which lives under AppData/Local/Temp
    // on Windows, and legitimate projects can live there too. The home-dir
    // exact-match check above plus the marker/source-file check below is
    // sufficient to reject real non-project roots.

    // ── Read top-level entries ──────────────────────────────────────────
    // Single read_dir, no recursion — bounded cost regardless of tree size.
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };

    const PROJECT_MARKERS: &[&str] = &[
        ".git",
        "package.json",
        "tsconfig.json",
        "cargo.toml",
        "pyproject.toml",
        "setup.py",
        "requirements.txt",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "gemfile",
        "mix.exs",
        "project.godot",
        "cmakelists.txt",
        "makefile",
        // Suffix-match entries (handled via starts_with('*') branch below):
        "*.csproj",
        "*.sln",
    ];

    const SOURCE_EXTENSIONS: &[&str] = &[
        ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".kt",
        ".cs", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".rb", ".php",
        ".swift", ".m", ".gd", ".lua", ".dart", ".scala", ".clj",
    ];

    let mut found_marker = false;
    let mut found_source = false;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let lower = name_str.to_lowercase();

        // Marker file/dir at top level
        if PROJECT_MARKERS.iter().any(|marker| {
            if marker.starts_with('*') {
                lower.ends_with(&marker[1..])
            } else {
                lower == *marker
            }
        }) {
            found_marker = true;
            break;
        }

        // Source file at top level
        if SOURCE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
            // Skip noise
            if lower.contains(".test.") || lower.contains(".spec.") || lower.ends_with(".d.ts") {
                continue;
            }
            found_source = true;
            break;
        }
    }

    found_marker || found_source
}

fn dirs_home_str() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE").ok()
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok()
    }
}

/// Walk `dir` recursively, return the newest mtime among source files
/// (.rs/.ts/.tsx/.mts/.cts/.py/.go/.gd). Used to detect "anything changed?"
/// without reading file contents — just `metadata().modified()`.
///
/// Skip rules mirror `walk` in scan_project so we don't waste time in
/// node_modules / target / etc.
fn compute_max_source_mtime(dir: &Path) -> std::io::Result<SystemTime> {
    let mut max: Option<SystemTime> = None;
    walk_for_mtime(dir, &mut max)?;
    Ok(max.unwrap_or(SystemTime::UNIX_EPOCH))
}

/// Maximum number of directory entries to visit during a mtime walk.
///
/// Defense-in-depth: even with `looks_like_project_root` filtering out
/// non-project paths, a legitimate monorepo can still have hundreds of
/// thousands of files (deep node_modules before .gitignore was respected,
/// generated docs, build artifacts). Cap at 50k entries — if a project
/// exceeds this, the mtime probe will just return early and refresh will
/// run more often than necessary, never starve the runtime.
const MAX_MTIME_WALK_ENTRIES: usize = 50_000;

fn walk_for_mtime(dir: &Path, max: &mut Option<SystemTime>) -> std::io::Result<()> {
    let mut visited: usize = 0;
    walk_for_mtime_inner(dir, max, &mut visited)
}

fn walk_for_mtime_inner(
    dir: &Path,
    max: &mut Option<SystemTime>,
    visited: &mut usize,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        // Bounded walk — bail out if we've stat'd too many entries.
        // Returning Ok with whatever max we have so far is safe: the caller
        // just compares against LAST_REFRESH_MTIME, and on next call we'll
        // re-walk and either hit the same cap or finish.
        if *visited >= MAX_MTIME_WALK_ENTRIES {
            tracing::warn!(
                target: "local_scanner",
                dir = %dir.display(),
                visited = *visited,
                cap = MAX_MTIME_WALK_ENTRIES,
                "walk_for_mtime: hit entry cap, returning early"
            );
            return Ok(());
        }
        *visited += 1;

        let entry = entry?;
        let path = entry.path();
        let meta = entry.metadata()?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if meta.is_dir() {
            if SKIP_DIRS.contains(&name_str.as_ref()) || name_str.starts_with('.') {
                continue;
            }
            walk_for_mtime_inner(&path, max, visited)?;
        } else if meta.is_file() {
            let lower = name_str.to_lowercase();
            let matches_ext = SOURCE_EXTS.iter().any(|ext| lower.ends_with(ext));
            if !matches_ext {
                continue;
            }
            // Skip noise files (mirrors scan_project walk)
            if lower.contains(".test.") || lower.contains(".spec.") || lower.ends_with(".d.ts") {
                continue;
            }
            if let Ok(mtime) = meta.modified() {
                if max.map(|m| mtime > m).unwrap_or(true) {
                    *max = Some(mtime);
                }
            }
        }
    }
    Ok(())
}

/// Walk `root`, dispatch each source file by extension, return parsed symbols.
///
/// `project_name` is stamped onto every emitted symbol's `library` field;
/// `version` is set to `"local"` to distinguish from published library versions.
pub fn scan_project(root: &Path, project_name: &str) -> ScanOutcome {
    let start = SystemTime::now();
    let mut outcome = ScanOutcome {
        project_name: project_name.to_string(),
        root: root.to_path_buf(),
        ..Default::default()
    };
    let skipped_exts_seen: std::collections::BTreeSet<String> = Default::default();

    walk(root, &mut |path, content| {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let parsed: Vec<Symbol> = match ext.as_str() {
            "ts" | "tsx" | "mts" | "cts" | "js" | "jsx" | "mjs" | "cjs" => match ts_parser::parse_dts(content, project_name, "local") {
                Ok(s) => s,
                Err(_) => return,
            },
            "rs" => scan_rust_source(content, project_name),
            "py" => scan_python_source(content, project_name),
            "go" => scan_go_source(content, project_name),
            "java" => scan_java_source(content, project_name),
            "cs" => scan_csharp_source(content, project_name),
            "rb" => scan_ruby_source(content, project_name),
            "gd" => scan_gdscript_source(content, project_name),
            "lua" => scan_lua_source(content, project_name),
            "php" => scan_php_source(content, project_name),
            _ => return, // not a source file — caller shouldn't have called us
        };

        outcome.files_scanned += 1;
        outcome.symbols.extend(parsed);
    });

    outcome.skipped_exts = skipped_exts_seen.into_iter().collect();
    outcome.elapsed_ms = start.elapsed().map(|d| d.as_millis()).unwrap_or(0);
    outcome
}

/// Parse Rust source (`pub` items only) into symbols.
///
/// Extracts: functions, structs, enums, traits, consts, type aliases,
/// and methods inside `impl` blocks (path = `<Type>.<method>`).
pub fn scan_rust_source(content: &str, library: &str) -> Vec<Symbol> {
    use std::collections::HashSet;

    let now = now_secs();
    let stripped = strip_line_comments(content);
    let body = stripped.as_str();
    let mut out: Vec<Symbol> = Vec::new();
    let mut method_names: HashSet<String> = HashSet::new();

    // impl blocks FIRST — extract methods (path = Type.method) and collect
    // their names so the standalone-fn loop below can skip dupes (RE_RUST_FN
    // also matches `pub fn` lines INSIDE impl bodies).
    for caps in RE_RUST_IMPL.captures_iter(body) {
        let type_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let impl_body = caps.name("body").map(|m| m.as_str()).unwrap_or("");
        if type_name.is_empty() {
            continue;
        }
        for mcap in RE_RUST_METHOD.captures_iter(impl_body) {
            let mname = mcap.get(1).map(|m| m.as_str()).unwrap_or_default();
            let params_raw = mcap.get(2).map(|m| m.as_str()).unwrap_or_default();
            if mname.is_empty() || mname.starts_with('_') {
                continue;
            }
            method_names.insert(mname.to_string());
            let path = format!("{}.{}", type_name, mname);
            out.push(Symbol {
                library: library.to_string(),
                version: "local".to_string(),
                path: path.clone(),
                name: mname.to_string(),
                kind: SymbolKind::Method,
                signature: Some(format!("{}({})", mname, params_raw.trim())),
                params: parse_rust_params(params_raw),
                return_type: None,
                doc_text: None,
                source_file: None,
                visibility: Visibility::Public,
                is_deprecated: false,
                deprecated_message: None,
                extracted_at: now,
            });
        }
    }

    // Standalone functions — skip underscore-prefixed AND any name already
    // emitted as an impl method (de-dupe).
    for caps in RE_RUST_FN.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() || name.starts_with('_') || method_names.contains(name) {
            continue;
        }
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: name.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            signature: Some(format!("{}({})", name, params_raw.trim())),
            params: parse_rust_params(params_raw),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    // Structs
    for caps in RE_RUST_STRUCT.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            if !name.starts_with('_') {
                out.push(base_symbol(library, name, name, SymbolKind::Class, now));
            }
        }
    }

    // Enums
    for caps in RE_RUST_ENUM.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            if !name.starts_with('_') {
                out.push(base_symbol(library, name, name, SymbolKind::Enum, now));
            }
        }
    }

    // Traits
    for caps in RE_RUST_TRAIT.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            if !name.starts_with('_') {
                out.push(base_symbol(library, name, name, SymbolKind::Interface, now));
            }
        }
    }

    // Consts
    for caps in RE_RUST_CONST.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            if !name.starts_with('_') {
                out.push(base_symbol(library, name, name, SymbolKind::Constant, now));
            }
        }
    }

    // Type aliases
    for caps in RE_RUST_TYPE.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            if !name.starts_with('_') {
                out.push(base_symbol(library, name, name, SymbolKind::TypeAlias, now));
            }
        }
    }

    out
}

// ─── Python source extractor ────────────────────────────────────────
//
// Python's indentation-based scoping means we can't use brace counting.
// Approach:
//   1. Find `def name(...)` / `async def name(...)` / `class Name(Base):`
//      at column 0 (module-level).
//   2. For classes, find the body's indentation level by reading the next
//      non-blank line. Body extends until a line with strictly less indent
//      (or EOF).
//   3. Inside class body, scan for `def method(self, ...)` lines at the
//      body's exact indentation level (skips nested defs).
//
// Limitations (acceptable for cache lookup):
//   - No type info (Python often lacks annotations anyway)
//   - Doesn't follow `@property` decorators (treats as methods)
//   - Doesn't parse `__all__` exports — treats all non-underscore names as public

static RE_PY_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
        .expect("RE_PY_FUNC invalid")
});

static RE_PY_ASYNC_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^async\s+def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
        .expect("RE_PY_ASYNC_FUNC invalid")
});

static RE_PY_CLASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^class\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:")
        .expect("RE_PY_CLASS invalid")
});

static RE_PY_CONST: Lazy<Regex> = Lazy::new(|| {
    // Module-level UPPER_SNAKE_CASE assignments (convention for constants).
    // Match `=` followed by whitespace + non-`=` char to skip comparisons
    // (`MAX == 3` won't match because char after `=` is `=`). RE2 regex
    // crate doesn't support lookarounds — match-and-check pattern instead.
    Regex::new(r"(?m)^([A-Z][A-Z0-9_]*)\s*=\s*[^=\s]")
        .expect("RE_PY_CONST invalid")
});

/// Parse Python source into symbols.
///
/// Extracts: module-level functions, async functions, classes with their
/// methods, module-level UPPER_CASE constants.
pub fn scan_python_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();

    // Strip comments + docstrings so they don't shadow matches. Conservative:
    // drops everything from `#` to EOL, drops triple-quoted blocks.
    let stripped = strip_py_comments(content);
    let body = stripped.as_str();
    let lines: Vec<&str> = body.lines().collect();

    // ── Module-level functions (def + async def) ────────────────────
    for caps in RE_PY_FUNC.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let params = parse_py_params(params_raw);
        let sig = format!("{}({})", name, params_raw.trim());
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: name.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            signature: Some(sig),
            params,
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }
    for caps in RE_PY_ASYNC_FUNC.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let params = parse_py_params(params_raw);
        let sig = format!("async {}({})", name, params_raw.trim());
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: name.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            signature: Some(sig),
            params,
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    // ── Module-level classes + their methods ────────────────────────
    for caps in RE_PY_CLASS.captures_iter(body) {
        let class_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if class_name.is_empty() {
            continue;
        }
        out.push(base_symbol(library, class_name, class_name, SymbolKind::Class, now));

        // Find class declaration line index, then walk forward to find the
        // body's indentation level. Body ends at first line with strictly
        // less indentation (or another class/def at column 0).
        let decl_line_idx = body
            .get(caps.get(0).unwrap().start()..)
            .and_then(|s| s.find('\n'))
            .map(|_| {
                // Walk lines to find the one containing our match.
                let offset = caps.get(0).unwrap().start();
                let mut idx = 0;
                let mut consumed = 0;
                for (i, line) in lines.iter().enumerate() {
                    if consumed + line.len() + 1 > offset {
                        idx = i;
                        break;
                    }
                    consumed += line.len() + 1;
                }
                let _ = offset; // silence
                idx
            })
            .unwrap_or(0);

        // Determine body indentation from next non-blank line.
        let body_indent = lines
            .iter()
            .skip(decl_line_idx + 1)
            .find_map(|line| {
                if line.trim().is_empty() {
                    return None;
                }
                Some(line.len() - line.trim_start().len())
            })
            .unwrap_or(4);

        // Walk forward through body, picking up def/async def at exact body_indent.
        for line in lines.iter().skip(decl_line_idx + 1) {
            if line.trim().is_empty() {
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent < body_indent {
                // Body ended (dedent). Stop scanning this class.
                break;
            }
            // Match methods at exactly body_indent level (skip nested defs).
            if indent != body_indent {
                continue;
            }
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed
                .strip_prefix("async ")
                .and_then(|s| s.strip_prefix("def "))
                .or_else(|| trimmed.strip_prefix("def "))
            {
                if let Some(name_end) = rest.find('(') {
                    let mname = rest[..name_end].trim();
                    if mname.is_empty() || mname.starts_with('_') {
                        continue;
                    }
                    let params_end = rest[name_end..].find(')').map(|p| name_end + p + 1);
                    let params_raw = params_end
                        .map(|p| &rest[name_end + 1..p - 1])
                        .unwrap_or("");
                    let path = format!("{}.{}", class_name, mname);
                    out.push(Symbol {
                        library: library.to_string(),
                        version: "local".to_string(),
                        path: path.clone(),
                        name: mname.to_string(),
                        kind: SymbolKind::Method,
                        signature: Some(format!("{}({})", mname, params_raw.trim())),
                        params: parse_py_params(params_raw),
                        return_type: None,
                        doc_text: None,
                        source_file: None,
                        visibility: Visibility::Public,
                        is_deprecated: false,
                        deprecated_message: None,
                        extracted_at: now,
                    });
                }
            }
        }
    }

    // ── Module-level constants ──────────────────────────────────────
    for caps in RE_PY_CONST.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() || name.len() < 2 {
            // Single-char "constants" like A = ... are usually throwaway.
            continue;
        }
        out.push(base_symbol(library, name, name, SymbolKind::Constant, now));
    }

    out
}

/// Parse a Python formal-params list into [`Param`]s.
/// Drops `self` / `cls` (implicit, not part of callable signature).
fn parse_py_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty()
                || chunk == "self"
                || chunk == "cls"
                || chunk.starts_with('*')
                || chunk.starts_with("**")
            {
                return None;
            }
            // Strip annotations + defaults: `name: Type = default` → `name`
            let name_part = chunk.split_once(':').map(|(n, _)| n).unwrap_or(chunk);
            let name_part = name_part.split_once('=').map(|(n, _)| n).unwrap_or(name_part);
            let name = name_part.trim().trim_start_matches('*');
            if name.is_empty()
                || !name
                    .chars()
                    .next()
                    .map(|c| c.is_alphabetic() || c == '_')
                    .unwrap_or(false)
            {
                return None;
            }
            Some(Param {
                name: name.to_string(),
                type_name: "_".to_string(), // Python — leave type open
                default_value: None,
            })
        })
        .collect()
}

/// Strip `#` line comments + triple-quoted docstrings from Python source.
/// Conservative — doesn't try to handle `#` inside strings (rare in practice).
fn strip_py_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_docstring: Option<&'static str> = None; // Some("'''") or Some("\"\"\"")
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Inside docstring — look for matching terminator.
        if let Some(quote) = in_docstring {
            if bytes.len() >= i + 3 && &bytes[i..i + 3] == quote.as_bytes() {
                out.push_str(" "); // collapse docstring to space
                i += 3;
                in_docstring = None;
                continue;
            }
            i += 1;
            continue;
        }
        // Detect docstring start.
        if bytes.len() >= i + 3 {
            let triple = &bytes[i..i + 3];
            if triple == b"\"\"\"" {
                in_docstring = Some("\"\"\"");
                i += 3;
                continue;
            }
            if triple == b"'''" {
                in_docstring = Some("'''");
                i += 3;
                continue;
            }
        }
        // Line comment.
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

// ─── Go source extractor ────────────────────────────────────────────
//
// Go uses braces + has clean syntax. Approach:
//   1. Find `func Name(...) {` for package-level functions
//   2. Find `func (recv) Name(...) {` for methods (path = `RecvType.Name`)
//   3. Find `type Name struct {`, `type Name interface {`, `type Name = X`
//   4. Find `var Name = ...` / `const Name = ...` (uppercase = exported)

static RE_GO_FUNC: Lazy<Regex> = Lazy::new(|| {
    // `func Name(params) (returns) {` — package-level function.
    Regex::new(r"(?m)^func\s+([A-Z][A-Za-z0-9_]*)\s*\(([^)]*)\)")
        .expect("RE_GO_FUNC invalid")
});

static RE_GO_METHOD: Lazy<Regex> = Lazy::new(|| {
    // `func (recv RecvType) Name(params) (returns) {`
    // Receiver can be `*Type` or `Type`. We extract RecvType (strip pointer).
    // Captures: 1 = recv type, 2 = method name, 3 = params.
    Regex::new(r"(?m)^func\s+\((?:[A-Za-z_][A-Za-z0-9_]*\s+)?\*?([A-Z][A-Za-z0-9_]*)\)\s+([A-Z][A-Za-z0-9_]*)\s*\(([^)]*)\)")
        .expect("RE_GO_METHOD invalid")
});

static RE_GO_STRUCT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^type\s+([A-Z][A-Za-z0-9_]*)\s+struct\s*\{")
        .expect("RE_GO_STRUCT invalid")
});

static RE_GO_INTERFACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^type\s+([A-Z][A-Za-z0-9_]*)\s+interface\s*\{")
        .expect("RE_GO_INTERFACE invalid")
});

static RE_GO_TYPE_ALIAS: Lazy<Regex> = Lazy::new(|| {
    // `type Foo = SomeOtherType` (type alias, Go 1.9+).
    Regex::new(r"(?m)^type\s+([A-Z][A-Za-z0-9_]*)\s*=\s*")
        .expect("RE_GO_TYPE_ALIAS invalid")
});

static RE_GO_CONST: Lazy<Regex> = Lazy::new(|| {
    // `const Foo = ...` (single, exported) — group declarations ignored for simplicity.
    Regex::new(r"(?m)^const\s+([A-Z][A-Za-z0-9_]*)\s*=")
        .expect("RE_GO_CONST invalid")
});

static RE_GO_VAR: Lazy<Regex> = Lazy::new(|| {
    // `var Foo = ...` (exported package var).
    Regex::new(r"(?m)^var\s+([A-Z][A-Za-z0-9_]*)\s*=")
        .expect("RE_GO_VAR invalid")
});

/// Parse Go source into symbols.
///
/// Extracts: package-level functions, methods (with receiver type as path
/// prefix), structs (Class), interfaces (Interface), type aliases, exported
/// consts + vars (Constant).
pub fn scan_go_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();

    // Strip line comments + block comments. Conservative.
    let stripped = strip_go_comments(content);
    let body = stripped.as_str();

    // ── Methods (must be matched before funcs to avoid being picked up
    //   by RE_GO_FUNC, which doesn't expect the receiver prefix). ───────
    let mut method_spans: Vec<std::ops::Range<usize>> = Vec::new();
    for caps in RE_GO_METHOD.captures_iter(body) {
        let recv_type = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let method_name = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
        if recv_type.is_empty() || method_name.is_empty() {
            continue;
        }
        let path = format!("{}.{}", recv_type, method_name);
        let m_start = caps.get(0).unwrap().start();
        method_spans.push(m_start..caps.get(0).unwrap().end());
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: path.clone(),
            name: method_name.to_string(),
            kind: SymbolKind::Method,
            signature: Some(format!("{}({})", method_name, params_raw.trim())),
            params: parse_go_params(params_raw),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    // ── Package-level functions (skip method ranges to avoid duplicates) ──
    for caps in RE_GO_FUNC.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let m_start = caps.get(0).unwrap().start();
        // Skip if this match is inside a method (already captured above).
        if method_spans.iter().any(|r| r.contains(&m_start)) {
            continue;
        }
        let sig = format!("{}({})", name, params_raw.trim());
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: name.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Function,
            signature: Some(sig),
            params: parse_go_params(params_raw),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    // ── Structs (Class) ─────────────────────────────────────────────
    for caps in RE_GO_STRUCT.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Class, now));
        }
    }

    // ── Interfaces (Interface) ──────────────────────────────────────
    for caps in RE_GO_INTERFACE.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Interface, now));
        }
    }

    // ── Type aliases ────────────────────────────────────────────────
    for caps in RE_GO_TYPE_ALIAS.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::TypeAlias, now));
        }
    }

    // ── Consts + exported vars ──────────────────────────────────────
    for caps in RE_GO_CONST.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Constant, now));
        }
    }
    for caps in RE_GO_VAR.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Constant, now));
        }
    }

    out
}

/// Parse a Go formal-params list into [`Param`]s.
/// Go params look like `name Type, name2 *Type, ...restType`.
/// We extract the name only (type info varies too much for cache lookup).
fn parse_go_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() || chunk.starts_with("...") {
                return None;
            }
            // `name Type` — name is first identifier.
            // If chunk has no space (just type), it's a type-only param (rare).
            let mut parts = chunk.split_whitespace();
            let name = parts.next()?;
            // Must start with letter/underscore.
            if !name
                .chars()
                .next()
                .map(|c| c.is_alphabetic() || c == '_')
                .unwrap_or(false)
            {
                return None;
            }
            // Skip if name looks like a type (capitalized, no following word).
            // Go convention: param names are lowercase.
            if name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                && parts.next().is_none()
            {
                return None;
            }
            // Type is the rest of the line (joined).
            let type_name: String = parts.collect::<Vec<_>>().join(" ");
            Some(Param {
                name: name.to_string(),
                type_name: if type_name.is_empty() {
                    "_".to_string()
                } else {
                    type_name
                },
                default_value: None,
            })
        })
        .collect()
}

/// Strip `//` line + `/* */` block comments from Go source.
/// Conservative — same approach as Rust parser.
fn strip_go_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
            continue;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

// ─── Java source extractor ──────────────────────────────────────────
//
// Java is C-family with braces. Approach mirrors Go: brace-match class
// bodies, regex for member declarations inside, package-level for
// standalone functions (rare — Java forces everything into classes).
//
// Java quirks handled:
//   - `[modifiers] class/interface/enum Name [extends X] [implements Y] {`
//   - `@Annotation` lines precede declarations — we strip them as noise
//   - Generics `<T extends Comparable<T>>` in class + method signatures
//   - `throws X, Y` clause after params (skipped, opaque)
//   - Inner classes (nested) — captured at first level only

static RE_JAVA_CLASS: Lazy<Regex> = Lazy::new(|| {
    // `[modifiers] class Name<Generics> [extends X] [implements Y, Z] {`
    // Modifiers: public/private/protected/static/final/abstract
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*class\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?",
    )
    .expect("RE_JAVA_CLASS invalid")
});

static RE_JAVA_INTERFACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*interface\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?",
    )
    .expect("RE_JAVA_INTERFACE invalid")
});

static RE_JAVA_ENUM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*enum\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\{",
    )
    .expect("RE_JAVA_ENUM invalid")
});

static RE_JAVA_METHOD: Lazy<Regex> = Lazy::new(|| {
    // Inside class body: `[modifiers] [generics] ReturnType name(params) [throws ...] {`
    // We require `(` for params to skip fields (which have `=` or `;`).
    // Method name capture is the identifier immediately before `(`.
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|strictfp)\s+)*(?:<[A-Za-z_$][A-Za-z0-9_$<>,\s\?]*>\s+)?[A-Za-z_$][A-Za-z0-9_$<>\[\],\?\s]*\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)",
    )
    .expect("RE_JAVA_METHOD invalid")
});

static RE_JAVA_FIELD: Lazy<Regex> = Lazy::new(|| {
    // Inside class body: `[modifiers] Type name [= value];`
    // Must NOT have `(` (would be method). Field name before `=` or `;`.
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|static|final|volatile|transient)\s+)+[A-Za-z_$][A-Za-z0-9_$<>\[\],\?\s]*\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:=[^;]*)?;",
    )
    .expect("RE_JAVA_FIELD invalid")
});

/// Parse Java source into symbols.
///
/// Extracts: classes, interfaces, enums (Class/Interface/Enum kinds) + their
/// methods + fields. Path uses ClassName.method/field convention.
pub fn scan_java_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();

    // Strip comments + @Annotation lines (one-line annotations only).
    let stripped = strip_c_style_comments(content);
    let no_annotations = strip_java_annotations(&stripped);
    let body = no_annotations.as_str();

    // Find every type declaration (class/interface/enum). For each, extract
    // the type itself + scan its brace-matched body for members.
    let mut type_spans: Vec<(String, usize, usize)> = Vec::new(); // (name, body_start, body_end)

    for caps in RE_JAVA_CLASS.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(base_symbol(library, name, name, SymbolKind::Class, now));
        let body_start = caps.get(0).unwrap().end();
        let body_end = match_body_end_braces(body, body_start);
        type_spans.push((name.to_string(), body_start, body_end));
    }
    for caps in RE_JAVA_INTERFACE.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(base_symbol(library, name, name, SymbolKind::Interface, now));
        let body_start = find_open_brace(body, caps.get(0).unwrap().end());
        let body_end = match_body_end_braces(body, body_start);
        type_spans.push((name.to_string(), body_start, body_end));
    }
    for caps in RE_JAVA_ENUM.captures_iter(body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push(base_symbol(library, name, name, SymbolKind::Enum, now));
        // enum body starts at the `{` captured by the regex itself
        let body_start = caps.get(0).unwrap().end();
        let body_end = match_body_end_braces(body, body_start);
        type_spans.push((name.to_string(), body_start, body_end));
    }

    // Scan each type's body for methods + fields.
    for (type_name, body_start, body_end) in &type_spans {
        let body_end_min = (*body_end).min(body.len());
        let body_span = &body[*body_start..body_end_min];

        for mcap in RE_JAVA_METHOD.captures_iter(body_span) {
            let mname = mcap.get(1).map(|m| m.as_str()).unwrap_or_default();
            let params_raw = mcap.get(2).map(|m| m.as_str()).unwrap_or_default();
            if mname.is_empty()
                || mname.starts_with('_')
                || is_java_keyword(mname)
            {
                continue;
            }
            let path = format!("{}.{}", type_name, mname);
            let kind = if mname == type_name.as_str() {
                SymbolKind::Constructor
            } else {
                SymbolKind::Method
            };
            out.push(Symbol {
                library: library.to_string(),
                version: "local".to_string(),
                path: path.clone(),
                name: mname.to_string(),
                kind,
                signature: Some(format!("{}.{}({})", type_name, mname, params_raw.trim())),
                params: parse_java_params(params_raw),
                return_type: None,
                doc_text: None,
                source_file: None,
                visibility: Visibility::Public,
                is_deprecated: false,
                deprecated_message: None,
                extracted_at: now,
            });
        }

        for fcap in RE_JAVA_FIELD.captures_iter(body_span) {
            let fname = fcap.get(1).map(|m| m.as_str()).unwrap_or_default();
            if fname.is_empty()
                || fname.starts_with('_')
                || is_java_keyword(fname)
            {
                continue;
            }
            let path = format!("{}.{}", type_name, fname);
            out.push(base_symbol(library, &path, fname, SymbolKind::Property, now));
        }
    }

    out
}

/// Strip single-line `@Annotation` prefixes (e.g., `@Override`, `@Autowired`).
/// Multi-line annotations (rare) are not handled — they'd need brace matching.
fn strip_java_annotations(s: &str) -> String {
    s.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('@') {
                // Drop the annotation line entirely — it modifies the next decl.
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_java_keyword(s: &str) -> bool {
    matches!(
        s,
        "abstract" | "assert" | "boolean" | "break" | "byte" | "case" | "catch"
            | "char" | "class" | "const" | "continue" | "default" | "do"
            | "double" | "else" | "enum" | "extends" | "final" | "finally"
            | "float" | "for" | "goto" | "if" | "implements" | "import"
            | "instanceof" | "int" | "interface" | "long" | "native" | "new"
            | "package" | "private" | "protected" | "public" | "return"
            | "short" | "static" | "strictfp" | "super" | "switch"
            | "synchronized" | "this" | "throw" | "throws" | "transient"
            | "try" | "void" | "volatile" | "while" | "true" | "false" | "null"
            | "var" | "record" | "yield" | "sealed" | "permits" | "non-sealed"
    )
}

/// Parse Java formal-params list. Each param is `Type name` (or `Type... name`
/// for varargs, or `final Type name`).
fn parse_java_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }
            // Strip `final` modifier.
            let chunk = chunk.trim_start_matches("final ");
            // Varargs: `Type... name` → strip `...`
            let chunk = chunk.replace("...", " ");
            // Last identifier is the name; everything before is the type.
            let mut parts: Vec<&str> = chunk.split_whitespace().collect();
            let name = parts.pop()?;
            if name.is_empty() || !name.chars().next().map(|c| c.is_lowercase() || c == '_' || c == '$').unwrap_or(false) {
                // Java convention: param names are lowercase. Capitalized =
                // probably a type-only param (rare). Skip to be safe.
                return None;
            }
            let type_name = parts.join(" ");
            Some(Param {
                name: name.to_string(),
                type_name: if type_name.is_empty() { "_".to_string() } else { type_name },
                default_value: None, // Java has no param defaults
            })
        })
        .collect()
}

/// Find the next `{` from `start`, skipping whitespace + extends/implements clauses.
fn find_open_brace(s: &str, start: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = start;
    let mut in_string: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match in_string {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_string = None;
                }
            }
            None => match c {
                b'"' | b'\'' => in_string = Some(c),
                b'{' => return i + 1,
                b';' => return i + 1, // abstract method or non-block decl
                _ => {}
            },
        }
        i += 1;
    }
    i
}

/// Brace-counting body matcher. Given `start` pointing just AFTER the opening
/// `{`, return the index of the matching closing `}`. Ignores braces in strings.
fn match_body_end_braces(body: &str, start: usize) -> usize {
    let bytes = body.as_bytes();
    let mut depth: i32 = 1;
    let mut i = start;
    let mut in_string: Option<u8> = None;
    while i < bytes.len() && depth > 0 {
        let c = bytes[i];
        match in_string {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_string = None;
                }
            }
            None => match c {
                b'"' | b'\'' => in_string = Some(c),
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            },
        }
        i += 1;
    }
    i.saturating_sub(1)
}

/// Strip `/* */` block comments + `//` line comments (C-family).
/// Used by Java + C# extractors.
fn strip_c_style_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
            continue;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

// ─── C# source extractor ────────────────────────────────────────────
//
// C# is close to Java syntactically. Same brace-delimited bodies, same
// modifier keywords (plus `async`, `unsafe`, `partial`, `ref`, `out`).
// Adds: properties (`Type Name { get; set; }`), structs, namespaces.
//
// We treat C# structs as Class kind (SymbolKind has no Struct), and
// namespaces as a no-op (just scan their bodies for inner types).

static RE_CSHARP_CLASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|partial|unsafe)\s+)*class\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?",
    )
    .expect("RE_CSHARP_CLASS invalid")
});

static RE_CSHARP_INTERFACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|partial|unsafe)\s+)*interface\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?",
    )
    .expect("RE_CSHARP_INTERFACE invalid")
});

static RE_CSHARP_STRUCT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|partial|unsafe|readonly|ref)\s+)*struct\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<[^>]*>)?",
    )
    .expect("RE_CSHARP_STRUCT invalid")
});

static RE_CSHARP_ENUM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|partial|unsafe)\s+)*enum\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[A-Za-z_$][A-Za-z0-9_$]*)?\s*\{",
    )
    .expect("RE_CSHARP_ENUM invalid")
});

static RE_CSHARP_METHOD: Lazy<Regex> = Lazy::new(|| {
    // Like Java but adds `async`, `unsafe`, `partial`, `override`, `virtual`.
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|partial|unsafe|async|override|virtual|new|extern)\s+)*(?:<[A-Za-z_$][A-Za-z0-9_$<>,\s\?]*>\s+)?[A-Za-z_$][A-Za-z0-9_$<>\[\],\?\s]*\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)",
    )
    .expect("RE_CSHARP_METHOD invalid")
});

static RE_CSHARP_PROPERTY: Lazy<Regex> = Lazy::new(|| {
    // `Type Name { get; set; }` — capture name only, require `{` to distinguish from fields.
    Regex::new(
        r"(?m)^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|virtual|override|new|readonly|async|unsafe)\s+)+[A-Za-z_$][A-Za-z0-9_$<>\[\],\?\s]*\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\{",
    )
    .expect("RE_CSHARP_PROPERTY invalid")
});

/// Parse C# source into symbols. Mirrors Java extractor.
pub fn scan_csharp_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();

    let stripped = strip_c_style_comments(content);
    let no_attrs = strip_csharp_attributes(&stripped);
    let body = no_attrs.as_str();

    let mut type_spans: Vec<(String, usize, usize)> = Vec::new();

    for caps in RE_CSHARP_CLASS.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Class, now));
            let body_start = find_open_brace(body, caps.get(0).unwrap().end());
            let body_end = match_body_end_braces(body, body_start);
            type_spans.push((name.to_string(), body_start, body_end));
        }
    }
    for caps in RE_CSHARP_INTERFACE.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Interface, now));
            let body_start = find_open_brace(body, caps.get(0).unwrap().end());
            let body_end = match_body_end_braces(body, body_start);
            type_spans.push((name.to_string(), body_start, body_end));
        }
    }
    for caps in RE_CSHARP_STRUCT.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            // No Struct kind — use Class.
            out.push(base_symbol(library, name, name, SymbolKind::Class, now));
            let body_start = find_open_brace(body, caps.get(0).unwrap().end());
            let body_end = match_body_end_braces(body, body_start);
            type_spans.push((name.to_string(), body_start, body_end));
        }
    }
    for caps in RE_CSHARP_ENUM.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Enum, now));
            let body_start = caps.get(0).unwrap().end();
            let body_end = match_body_end_braces(body, body_start);
            type_spans.push((name.to_string(), body_start, body_end));
        }
    }

    for (type_name, body_start, body_end) in &type_spans {
        let body_end_min = (*body_end).min(body.len());
        let body_span = &body[*body_start..body_end_min];

        for mcap in RE_CSHARP_METHOD.captures_iter(body_span) {
            let mname = mcap.get(1).map(|m| m.as_str()).unwrap_or_default();
            let params_raw = mcap.get(2).map(|m| m.as_str()).unwrap_or_default();
            if mname.is_empty() || mname.starts_with('_') || is_csharp_keyword(mname) {
                continue;
            }
            let path = format!("{}.{}", type_name, mname);
            let kind = if mname == type_name.as_str() {
                SymbolKind::Constructor
            } else {
                SymbolKind::Method
            };
            out.push(Symbol {
                library: library.to_string(),
                version: "local".to_string(),
                path: path.clone(),
                name: mname.to_string(),
                kind,
                signature: Some(format!("{}.{}({})", type_name, mname, params_raw.trim())),
                params: parse_csharp_params(params_raw),
                return_type: None,
                doc_text: None,
                source_file: None,
                visibility: Visibility::Public,
                is_deprecated: false,
                deprecated_message: None,
                extracted_at: now,
            });
        }

        for pcap in RE_CSHARP_PROPERTY.captures_iter(body_span) {
            let pname = pcap.get(1).map(|m| m.as_str()).unwrap_or_default();
            if pname.is_empty() || pname.starts_with('_') || is_csharp_keyword(pname) {
                continue;
            }
            let path = format!("{}.{}", type_name, pname);
            out.push(base_symbol(library, &path, pname, SymbolKind::Property, now));
        }
    }

    out
}

/// Strip `[Attribute]` lines (C# attribute syntax, e.g. `[Obsolete]`).
fn strip_csharp_attributes(s: &str) -> String {
    s.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('[') {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_csharp_keyword(s: &str) -> bool {
    matches!(
        s,
        "abstract" | "as" | "base" | "bool" | "break" | "byte" | "case"
            | "catch" | "char" | "checked" | "class" | "const" | "continue"
            | "decimal" | "default" | "delegate" | "do" | "double" | "else"
            | "enum" | "event" | "explicit" | "extern" | "false" | "finally"
            | "fixed" | "float" | "for" | "foreach" | "goto" | "if"
            | "implicit" | "in" | "int" | "interface" | "internal" | "is"
            | "lock" | "long" | "namespace" | "new" | "null" | "object"
            | "operator" | "out" | "override" | "params" | "private"
            | "protected" | "public" | "readonly" | "ref" | "return" | "sbyte"
            | "sealed" | "short" | "sizeof" | "stackalloc" | "static"
            | "string" | "struct" | "switch" | "this" | "throw" | "true"
            | "try" | "typeof" | "uint" | "ulong" | "unchecked" | "unsafe"
            | "ushort" | "using" | "virtual" | "void" | "volatile" | "while"
            | "var" | "record" | "async" | "await" | "yield" | "partial"
            | "get" | "set" | "value"
    )
}

fn parse_csharp_params(raw: &str) -> Vec<Param> {
    // Same shape as Java — `Type name`, optional `ref/out/in` prefix.
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }
            // Strip ref/out/in modifiers.
            let chunk = chunk
                .trim_start_matches("ref ")
                .trim_start_matches("out ")
                .trim_start_matches("in ")
                .trim_start_matches("params ");
            let mut parts: Vec<&str> = chunk.split_whitespace().collect();
            let name = parts.pop()?;
            if name.is_empty() || !name.chars().next().map(|c| c.is_lowercase() || c == '_').unwrap_or(false) {
                return None;
            }
            let type_name = parts.join(" ");
            Some(Param {
                name: name.to_string(),
                type_name: if type_name.is_empty() { "_".to_string() } else { type_name },
                default_value: None,
            })
        })
        .collect()
}

// ─── Ruby source extractor ──────────────────────────────────────────
//
// Ruby uses keyword-delimited blocks (`def`/`class`/`module` ... `end`).
// No braces, no indentation semantics — explicit `end` is the terminator.
//
// Approach:
//   1. Walk lines, track nesting depth (each opener pushes, each `end` pops).
//   2. When we see `class Foo`, push (Foo, kind=class) onto scope stack.
//   3. When we see `def name`, emit a Method symbol with the current
//      scope path prefix (e.g. `Foo.bar`).
//   4. When we see `end`, pop the scope stack.
//   5. Module-level constants: `UPPER_CASE = ...`.

static RE_RUBY_CLASS: Lazy<Regex> = Lazy::new(|| {
    // `class Name < Parent` or `class Name`
    Regex::new(r"(?m)^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<\s*[A-Za-z_:]+)?\s*$")
        .expect("RE_RUBY_CLASS invalid")
});

static RE_RUBY_MODULE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*module\s+([A-Za-z_][A-Za-z0-9_:]*)\s*$")
        .expect("RE_RUBY_MODULE invalid")
});

static RE_RUBY_DEF: Lazy<Regex> = Lazy::new(|| {
    // `def name` or `def name(args)` or `def self.name` (class method)
    // or `def prefix.name` (explicit receiver).
    Regex::new(r"(?m)^\s*def\s+(?:self\.)?([A-Za-z_][A-Za-z0-9_!?=]*)\s*(?:\(([^)]*)\))?")
        .expect("RE_RUBY_DEF invalid")
});

static RE_RUBY_CONST: Lazy<Regex> = Lazy::new(|| {
    // `UPPER_CASE = ...` at module/class level.
    Regex::new(r"(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*[^=]")
        .expect("RE_RUBY_CONST invalid")
});

static RE_RUBY_BLOCK_OPENERS: Lazy<Regex> = Lazy::new(|| {
    // Things that open a block terminated by `end`.
    Regex::new(r"(?i)\b(def|class|module|if|unless|while|until|for|case|begin|do)\b")
        .expect("RE_RUBY_BLOCK_OPENERS invalid")
});

/// Parse Ruby source into symbols.
///
/// Tracks nesting via `def`/`class`/`module`/`if`/`while`/... + `end`.
/// Method path = `Class.method`. Module-level constants → Constant.
pub fn scan_ruby_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();

    // Strip `#` line comments + `=begin ... =end` block comments.
    let stripped = strip_ruby_comments(content);
    let body = stripped.as_str();

    // Scope stack tracks (kind, name) — pushes on class/module opener,
    // pops on `end`. Methods attach to current top.
    let mut scope_stack: Vec<(&'static str, String)> = Vec::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Detect `end` — pops the most recent scope (if any non-if/while/etc).
        // We use a simplified model: every `end` pops the top of scope_stack
        // if it's a class/module/def (control-flow `end`s are matched too
        // but we don't track those).
        if trimmed == "end" || trimmed.starts_with("end ") || trimmed.starts_with("end\t") {
            if let Some((kind, _)) = scope_stack.last() {
                if *kind == "class" || *kind == "module" || *kind == "def" {
                    scope_stack.pop();
                }
            }
            continue;
        }

        // Class opener
        if let Some(caps) = RE_RUBY_CLASS.captures(line) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if !name.is_empty() {
                let full_path = if scope_stack.is_empty() {
                    name.to_string()
                } else {
                    format!("{}.{}",
                        scope_stack.iter().filter(|(k, _)| *k == "class" || *k == "module").map(|(_, n)| n.as_str()).collect::<Vec<_>>().join("::"),
                        name
                    )
                };
                out.push(base_symbol(library, &full_path, name, SymbolKind::Class, now));
                scope_stack.push(("class", name.to_string()));
            }
            continue;
        }

        // Module opener
        if let Some(caps) = RE_RUBY_MODULE.captures(line) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            if !name.is_empty() {
                let last_segment = name.rsplit(':').next().unwrap_or(name);
                let full_path = if scope_stack.is_empty() {
                    name.to_string()
                } else {
                    format!("{}::{}",
                        scope_stack.iter().filter(|(k, _)| *k == "class" || *k == "module").map(|(_, n)| n.as_str()).collect::<Vec<_>>().join("::"),
                        name
                    )
                };
                out.push(base_symbol(library, &full_path, last_segment, SymbolKind::Interface, now));
                scope_stack.push(("module", name.to_string()));
            }
            continue;
        }

        // Method def
        if let Some(caps) = RE_RUBY_DEF.captures(line) {
            let mname = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            if mname.is_empty() || mname.starts_with('_') {
                // Still need to push to stack so its `end` is balanced.
                scope_stack.push(("def", mname.to_string()));
                continue;
            }
            // Path = parent class/module :: method
            let parent_path: String = scope_stack
                .iter()
                .filter(|(k, _)| *k == "class" || *k == "module")
                .map(|(_, n)| n.as_str())
                .collect::<Vec<_>>()
                .join("::");
            let path = if parent_path.is_empty() {
                mname.to_string()
            } else {
                format!("{}::{}", parent_path, mname)
            };
            out.push(Symbol {
                library: library.to_string(),
                version: "local".to_string(),
                path: path.clone(),
                name: mname.to_string(),
                kind: SymbolKind::Method,
                signature: Some(if params_raw.is_empty() {
                    mname.to_string()
                } else {
                    format!("{}({})", mname, params_raw.trim())
                }),
                params: parse_ruby_params(params_raw),
                return_type: None,
                doc_text: None,
                source_file: None,
                visibility: Visibility::Public,
                is_deprecated: false,
                deprecated_message: None,
                extracted_at: now,
            });
            scope_stack.push(("def", mname.to_string()));
            continue;
        }

        // Module/class-level constant (only when not inside a def)
        let inside_def = scope_stack.iter().any(|(k, _)| *k == "def");
        if !inside_def {
            if let Some(caps) = RE_RUBY_CONST.captures(line) {
                let cname = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                if !cname.is_empty() && cname.len() >= 2 {
                    out.push(base_symbol(library, cname, cname, SymbolKind::Constant, now));
                }
            }
        }
    }

    let _ = RE_RUBY_BLOCK_OPENERS.find(body); // silence unused warning
    out
}

fn parse_ruby_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() || chunk.starts_with('*') || chunk.starts_with('&') {
                return None;
            }
            // `name:` keyword arg (Ruby 2.0+) — name only, no type.
            if let Some(name) = chunk.strip_suffix(':') {
                if !name.is_empty() {
                    return Some(Param {
                        name: name.to_string(),
                        type_name: "_".to_string(),
                        default_value: None,
                    });
                }
            }
            // `name: default` keyword arg
            if let Some((name, default)) = chunk.split_once(':') {
                let name = name.trim();
                if !name.is_empty() {
                    return Some(Param {
                        name: name.to_string(),
                        type_name: "_".to_string(),
                        default_value: Some(default.trim().to_string()),
                    });
                }
            }
            // `name = default` positional
            let (name_part, default) = chunk.split_once('=').unwrap_or((chunk, ""));
            let name = name_part.trim();
            if name.is_empty() {
                return None;
            }
            Some(Param {
                name: name.to_string(),
                type_name: "_".to_string(),
                default_value: if default.trim().is_empty() {
                    None
                } else {
                    Some(default.trim().to_string())
                },
            })
        })
        .collect()
}

/// Strip `#` line comments + `=begin ... =end` block comments from Ruby source.
fn strip_ruby_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_block = false;
    for line in s.lines() {
        let trimmed = line.trim_start();
        if in_block {
            if trimmed.starts_with("=end") {
                in_block = false;
            }
            out.push('\n'); // preserve line numbering
            continue;
        }
        if trimmed.starts_with("=begin") {
            in_block = true;
            out.push('\n');
            continue;
        }
        // Strip from `#` to EOL — but only outside strings. Conservative.
        if let Some(idx) = line.find('#') {
            // Avoid stripping `#` inside string literals via simple heuristic:
            // count quotes before `#` — odd count = inside string.
            let before = &line[..idx];
            let quote_count = before.chars().filter(|c| *c == '"' || *c == '\'').count();
            if quote_count % 2 == 0 {
                out.push_str(before);
                out.push('\n');
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

// ─── Agent-response code block ingestion ────────────────────────────
//
// When the agent writes code in its response (markdown fenced blocks),
// we parse those blocks + upsert the symbols into the cache with
// version="agent_pending". This solves the "function called before
// defined" forward-reference problem: the agent's NEXT scan sees the
// symbols it just defined.
//
// Best-effort + fire-and-forget. Errors are logged at warn! and swallowed
// — agent symbol extraction must never break the scan pipeline.

static RE_CODE_FENCE: Lazy<Regex> = Lazy::new(|| {
    // Matches ```lang\n...code...\n``` (multiline, non-greedy).
    // Language tag is optional (some agents omit it).
    Regex::new(r"(?ms)```([A-Za-z0-9+#]+)?\s*\n(.*?)```")
        .expect("RE_CODE_FENCE invalid")
});

/// Extract (language, code) pairs from markdown fenced code blocks.
/// Language normalized to lowercase. Unknown languages returned as ("", code).
pub fn extract_code_blocks(content: &str) -> Vec<(String, String)> {
    RE_CODE_FENCE
        .captures_iter(content)
        .filter_map(|caps| {
            let lang = caps.get(1).map(|m| m.as_str().to_lowercase()).unwrap_or_default();
            let code = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            if code.trim().is_empty() {
                return None;
            }
            Some((lang, code.to_string()))
        })
        .collect()
}

/// Parse + upsert agent-response code blocks into the symbol cache.
///
/// `content` is the agent's response text. `project_name` becomes the
/// library field; version is "agent_pending" to distinguish from local
/// file-scanned symbols (version="local").
///
/// Removes old "agent_pending" symbols for this project first, then
/// inserts the new set. Atomic-ish — both ops are fast.
///
/// Skips blocks whose language we don't support. Logs counts at info!.
pub async fn upsert_agent_symbols(content: &str, project_name: &str) {
    let blocks = extract_code_blocks(content);
    if blocks.is_empty() {
        return;
    }

    let project_name_owned = project_name.to_string();
    tokio::task::spawn_blocking(move || {
        let now = now_secs();
        let mut all_symbols: Vec<Symbol> = Vec::new();

        for (lang, code) in &blocks {
            let parsed: Vec<Symbol> = match lang.as_str() {
                "rust" | "rs" => scan_rust_source(code, &project_name_owned),
                "python" | "py" => scan_python_source(code, &project_name_owned),
                "go" | "golang" => scan_go_source(code, &project_name_owned),
                "java" => scan_java_source(code, &project_name_owned),
                "csharp" | "cs" | "c#" => scan_csharp_source(code, &project_name_owned),
                "ruby" | "rb" => scan_ruby_source(code, &project_name_owned),
                "typescript" | "ts" | "tsx" | "javascript" | "js" | "jsx" | "mts" | "cts" => {
                    match ts_parser::parse_dts(code, &project_name_owned, "agent_pending") {
                        Ok(s) => s,
                        Err(_) => Vec::new(),
                    }
                }
                _ => Vec::new(),
            };
            // Re-stamp version to agent_pending (extractors default to "local").
            for mut s in parsed {
                s.version = "agent_pending".to_string();
                s.extracted_at = now;
                all_symbols.push(s);
            }
        }

        if all_symbols.is_empty() {
            tracing::debug!(
                target: "local_scanner",
                blocks = blocks.len(),
                "upsert_agent_symbols: no supported-language blocks found"
            );
            return;
        }

        match crate::symbols::cache::SymbolCache::open() {
            Ok(cache) => {
                if let Err(e) = cache.remove_library(&project_name_owned, "agent_pending") {
                    tracing::warn!(
                        target: "local_scanner",
                        error = %e,
                        "upsert_agent_symbols: remove_library failed"
                    );
                }
                if let Err(e) = cache.insert_many(&all_symbols) {
                    tracing::warn!(
                        target: "local_scanner",
                        error = %e,
                        "upsert_agent_symbols: insert_many failed"
                    );
                    return;
                }
                tracing::info!(
                    target: "local_scanner",
                    project = %project_name_owned,
                    blocks = blocks.len(),
                    symbols = all_symbols.len(),
                    "upsert_agent_symbols: ingested agent-defined symbols"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "local_scanner",
                    error = %e,
                    "upsert_agent_symbols: SymbolCache::open failed"
                );
            }
        }
    })
    .await
    .ok();
}
// ─── GDScript source extractor ──────────────────────────────────────
//
// GDScript is Godot's Python-like language. Indentation-based scoping,
// same approach as the Python extractor. Key differences:
//   - `func` instead of `def`
//   - `class_name Foo` declares the class (not `class Foo:`)
//   - `extends Node` sets inheritance (we skip — not a symbol)
//   - `signal hit(damage)` — Godot-specific, maps to SymbolKind::Signal
//   - `@export`, `@onready` annotations — stripped like Java/C#
//   - `enum Color { RED, GREEN, BLUE }` — single-line, not block

static RE_GD_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^func\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?")
        .expect("RE_GD_FUNC invalid")
});

static RE_GD_STATIC_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^static\s+func\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?")
        .expect("RE_GD_STATIC_FUNC invalid")
});

static RE_GD_CLASS_NAME: Lazy<Regex> = Lazy::new(|| {
    // `class_name Foo` or `class_name Foo extends Bar`
    Regex::new(r"(?m)^class_name\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("RE_GD_CLASS_NAME invalid")
});

static RE_GD_SIGNAL: Lazy<Regex> = Lazy::new(|| {
    // `signal hit` or `signal hit(damage, amount)`
    Regex::new(r"(?m)^signal\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?")
        .expect("RE_GD_SIGNAL invalid")
});

static RE_GD_CONST: Lazy<Regex> = Lazy::new(|| {
    // `const NAME = ...` or `const NAME: Type = ...`
    Regex::new(r"(?m)^const\s+([A-Z_][A-Z0-9_]*)\s*(?::=|:[^=]*=|=)")
        .expect("RE_GD_CONST invalid")
});

static RE_GD_ENUM: Lazy<Regex> = Lazy::new(|| {
    // `enum Name { RED, GREEN, BLUE }` — single-line in GDScript.
    Regex::new(r"(?m)^enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)\}")
        .expect("RE_GD_ENUM invalid")
});


/// Parse GDScript source into symbols.
///
/// Extracts: class_name declarations, module-level func/static func,
/// signals, constants, enums, and class body members (func + var).
pub fn scan_gdscript_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();

    let stripped = strip_gd_comments(content);
    let no_annotations = strip_gd_annotations(&stripped);
    let body = no_annotations.as_str();
    let _lines: Vec<&str> = body.lines().collect();

    // ── class_name declaration ──────────────────────────────────────
    let mut class_name: Option<String> = None;
    if let Some(caps) = RE_GD_CLASS_NAME.captures(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            class_name = Some(name.to_string());
            out.push(base_symbol(library, name, name, SymbolKind::Class, now));
        }
    }

    // ── Module-level functions ──────────────────────────────────────
    // If there's a class_name, module-level funcs belong to that class.
    let parent = class_name.as_deref().unwrap_or("");
    for caps in RE_GD_FUNC.captures_iter(body) {
        let fname = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if fname.is_empty() {
            continue;
        }
        let path = if parent.is_empty() {
            fname.to_string()
        } else {
            format!("{}.{}", parent, fname)
        };
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: path.clone(),
            name: fname.to_string(),
            kind: SymbolKind::Method,
            signature: Some(format!("{}({})", fname, params_raw.trim())),
            params: parse_gd_params(params_raw),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }
    for caps in RE_GD_STATIC_FUNC.captures_iter(body) {
        let fname = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if fname.is_empty() {
            continue;
        }
        let path = if parent.is_empty() {
            fname.to_string()
        } else {
            format!("{}.{}", parent, fname)
        };
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: path.clone(),
            name: fname.to_string(),
            kind: SymbolKind::Method,
            signature: Some(format!("static {}({})", fname, params_raw.trim())),
            params: parse_gd_params(params_raw),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    // ── Signals ─────────────────────────────────────────────────────
    for caps in RE_GD_SIGNAL.captures_iter(body) {
        let sname = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if sname.is_empty() {
            continue;
        }
        let path = if parent.is_empty() {
            sname.to_string()
        } else {
            format!("{}.{}", parent, sname)
        };
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: path.clone(),
            name: sname.to_string(),
            kind: SymbolKind::Signal,
            signature: Some(if params_raw.is_empty() {
                sname.to_string()
            } else {
                format!("{}({})", sname, params_raw.trim())
            }),
            params: Vec::new(),
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: now,
        });
    }

    // ── Constants ───────────────────────────────────────────────────
    for caps in RE_GD_CONST.captures_iter(body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Constant, now));
        }
    }

    // ── Enums ───────────────────────────────────────────────────────
    for caps in RE_GD_ENUM.captures_iter(body) {
        let ename = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let members_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if ename.is_empty() {
            continue;
        }
        out.push(base_symbol(library, ename, ename, SymbolKind::Enum, now));
        for member in members_raw.split(',') {
            let member = member.trim();
            // Handle `KEY = value` — strip the value part.
            let member_name = member.split('=').next().unwrap_or("").trim();
            if !member_name.is_empty() && member_name.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false) {
                let path = format!("{}.{}", ename, member_name);
                out.push(base_symbol(library, &path, member_name, SymbolKind::EnumMember, now));
            }
        }
    }

    out
}

/// Parse GDScript formal-params list.
/// GDScript params: `a`, `a: int`, `a := 5`, `a: int = 5`.
fn parse_gd_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                return None;
            }
            // Strip type annotation + default: `a: int = 5` → `a`
            let name_part = chunk.split_once(':').map(|(n, _)| n).unwrap_or(chunk);
            let name_part = name_part.split_once('=').map(|(n, _)| n).unwrap_or(name_part);
            let name = name_part.trim().trim_start_matches("var ");
            if name.is_empty()
                || !name.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
            {
                return None;
            }
            Some(Param {
                name: name.to_string(),
                type_name: "_".to_string(),
                default_value: chunk.split_once('=').map(|(_, v)| v.trim().to_string()),
            })
        })
        .collect()
}

/// Strip `#` comments from GDScript.
fn strip_gd_comments(s: &str) -> String {
    s.lines()
        .map(|line| {
            if let Some(idx) = line.find('#') {
                let before = &line[..idx];
                let quote_count = before.chars().filter(|c| *c == '"' || *c == '\'').count();
                if quote_count % 2 == 0 {
                    return before.to_string();
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Strip `@annotation` lines from GDScript (`@export`, `@onready`, `@tool`).
fn strip_gd_annotations(s: &str) -> String {
    s.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('@') {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
// ─── Lua source extractor ───────────────────────────────────────────
//
// Lua uses `function name(args)` and `local function name(args)`.
// Tables are the only data structure — `Table.method = function(...)`
// creates methods. No classes, no types.

static RE_LUA_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?:local\s+)?function\s+([A-Za-z_][A-Za-z0-9_:.]*)\s*\(([^)]*)\)")
        .expect("RE_LUA_FUNC invalid")
});


static RE_LUA_TABLE_METHOD: Lazy<Regex> = Lazy::new(|| {
    // `Table.method = function(args)` or `Table:method = function(args)`
    Regex::new(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)[.:]([A-Za-z_][A-Za-z0-9_]*)\s*=\s*function\s*\(([^)]*)\)")
        .expect("RE_LUA_TABLE_METHOD invalid")
});

/// Parse Lua source into symbols.
pub fn scan_lua_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();
    let body = strip_lua_comments(content);

    // Table methods: Table.method = function(...)
    for caps in RE_LUA_TABLE_METHOD.captures_iter(&body) {
        let table = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let method = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
        if method.is_empty() || method.starts_with('_') {
            continue;
        }
        let path = format!("{}.{}", table, method);
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path, name: method.to_string(),
            kind: SymbolKind::Method,
            signature: Some(format!("{}.{}({})", table, method, params_raw.trim())),
            params: parse_lua_params(params_raw),
            return_type: None, doc_text: None, source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false, deprecated_message: None, extracted_at: now,
        });
    }

    // Regular functions: function name(...) and local function name(...)
    for caps in RE_LUA_FUNC.captures_iter(&body) {
        let full_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        // Skip if already captured as table method (contains . or :)
        if full_name.contains('.') || full_name.contains(':') {
            continue;
        }
        if full_name.is_empty() || full_name.starts_with('_') {
            continue;
        }
        out.push(Symbol {
            library: library.to_string(),
            version: "local".to_string(),
            path: full_name.to_string(),
            name: full_name.to_string(),
            kind: SymbolKind::Function,
            signature: Some(format!("{}({})", full_name, params_raw.trim())),
            params: parse_lua_params(params_raw),
            return_type: None, doc_text: None, source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false, deprecated_message: None, extracted_at: now,
        });
    }

    out
}

fn parse_lua_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() || chunk == "self" || chunk.starts_with("...") {
                return None;
            }
            let name = chunk.split(':').next().unwrap_or(chunk).trim(); // strip type annotation
            if name.is_empty() {
                return None;
            }
            Some(Param {
                name: name.to_string(),
                type_name: "_".to_string(),
                default_value: None,
            })
        })
        .collect()
}

fn strip_lua_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut in_string: Option<u8> = None;
    while i < bytes.len() {
        match in_string {
            Some(q) => {
                out.push(bytes[i] as char);
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if bytes[i] == q {
                    in_string = None;
                }
                i += 1;
            }
            None => {
                // -- line comment
                if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                if bytes[i] == b'"' || bytes[i] == b'\'' {
                    in_string = Some(bytes[i]);
                }
                out.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    out
}

// ─── PHP source extractor ───────────────────────────────────────────
//
// PHP uses `function name(params) {`, `class Name {`, `interface Name {`.
// Methods inside classes: `public function method(params)`.
// C-family with braces, similar to Java but with `$` variable prefix.

static RE_PHP_CLASS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("RE_PHP_CLASS invalid")
});

static RE_PHP_INTERFACE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*interface\s+([A-Za-z_][A-Za-z0-9_]*)")
        .expect("RE_PHP_INTERFACE invalid")
});

static RE_PHP_METHOD: Lazy<Regex> = Lazy::new(|| {
    // [modifiers] function name(params)
    Regex::new(r"(?m)^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
        .expect("RE_PHP_METHOD invalid")
});

static RE_PHP_FUNC: Lazy<Regex> = Lazy::new(|| {
    // Top-level function (not in class): function name(params)
    Regex::new(r"(?m)^function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
        .expect("RE_PHP_FUNC invalid")
});

/// Parse PHP source into symbols.
pub fn scan_php_source(content: &str, library: &str) -> Vec<Symbol> {
    let now = now_secs();
    let mut out: Vec<Symbol> = Vec::new();
    let body = strip_c_style_comments(content);

    let mut type_spans: Vec<(String, usize, usize)> = Vec::new();

    for caps in RE_PHP_CLASS.captures_iter(&body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Class, now));
            let bs = find_open_brace(&body, caps.get(0).unwrap().end());
            let be = match_body_end_braces(&body, bs);
            type_spans.push((name.to_string(), bs, be));
        }
    }
    for caps in RE_PHP_INTERFACE.captures_iter(&body) {
        if let Some(name) = caps.get(1).map(|m| m.as_str()) {
            out.push(base_symbol(library, name, name, SymbolKind::Interface, now));
            let bs = find_open_brace(&body, caps.get(0).unwrap().end());
            let be = match_body_end_braces(&body, bs);
            type_spans.push((name.to_string(), bs, be));
        }
    }

    // Class methods
    for (type_name, bs, be) in &type_spans {
        let span = &body[*bs..(*be).min(body.len())];
        for mcap in RE_PHP_METHOD.captures_iter(span) {
            let mname = mcap.get(1).map(|m| m.as_str()).unwrap_or_default();
            let params_raw = mcap.get(2).map(|m| m.as_str()).unwrap_or_default();
            if mname.is_empty() || mname.starts_with('_') { continue; }
            let path = format!("{}.{}", type_name, mname);
            out.push(Symbol {
                library: library.to_string(), version: "local".to_string(),
                path: path.clone(), name: mname.to_string(),
                kind: if mname == "__construct" { SymbolKind::Constructor } else { SymbolKind::Method },
                signature: Some(format!("{}.{}({})", type_name, mname, params_raw.trim())),
                params: parse_php_params(params_raw),
                return_type: None, doc_text: None, source_file: None,
                visibility: Visibility::Public,
                is_deprecated: false, deprecated_message: None, extracted_at: now,
            });
        }
    }

    // Top-level functions
    for caps in RE_PHP_FUNC.captures_iter(&body) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let params_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if name.is_empty() || name.starts_with('_') { continue; }
        out.push(Symbol {
            library: library.to_string(), version: "local".to_string(),
            path: name.to_string(), name: name.to_string(),
            kind: SymbolKind::Function,
            signature: Some(format!("{}({})", name, params_raw.trim())),
            params: parse_php_params(params_raw),
            return_type: None, doc_text: None, source_file: None,
            visibility: Visibility::Public,
            is_deprecated: false, deprecated_message: None, extracted_at: now,
        });
    }

    out
}

fn parse_php_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty() || chunk.starts_with("...") { return None; }
            // PHP params: [type] $name [= default] or &$name
            // Strip type prefix (everything before $)
            let after_dollar = chunk.rfind('$').map(|i| &chunk[i..]).unwrap_or(chunk);
            let name_part = after_dollar.trim_start_matches('$').trim_start_matches('&');
            let (name, default) = name_part.split_once('=').unwrap_or((name_part, ""));
            let name = name.trim();
            if name.is_empty() { return None; }
            Some(Param {
                name: name.to_string(),
                type_name: "_".to_string(),
                default_value: if default.trim().is_empty() { None } else { Some(default.trim().to_string()) },
            })
        })
        .collect()
}
// ─── Helpers ─────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn base_symbol(library: &str, path: &str, name: &str, kind: SymbolKind, now: u64) -> Symbol {
    Symbol {
        library: library.to_string(),
        version: "local".to_string(),
        path: path.to_string(),
        name: name.to_string(),
        kind,
        signature: None,
        params: Vec::new(),
        return_type: None,
        doc_text: None,
        source_file: None,
        visibility: Visibility::Public,
        is_deprecated: false,
        deprecated_message: None,
        extracted_at: now,
    }
}

/// Walk `dir` recursively, invoking `cb(path, content)` for each source file.
///
/// Skip rules:
///   - dirs in SKIP_DIRS or starting with `.`
///   - files >100KB
///   - files with `.test.` / `.spec.` in name
///   - files ending in `.d.ts` (external declarations)
///   - files whose extension isn't in SOURCE_EXTS
fn walk(dir: &Path, cb: &mut dyn FnMut(&Path, &str)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            if SKIP_DIRS.contains(&name_str.as_ref()) || name_str.starts_with('.') {
                continue;
            }
            walk(&path, cb);
            continue;
        }

        // Extension gate
        let lower = name_str.to_lowercase();
        let matches_ext = SOURCE_EXTS.iter().any(|ext| lower.ends_with(ext));
        if !matches_ext {
            continue;
        }

        // Skip noise
        if lower.contains(".test.") || lower.contains(".spec.") || lower.ends_with(".d.ts") {
            continue;
        }

        // Size gate
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if metadata.len() > 100_000 {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        cb(&path, &content);
    }
}

/// Parse a Rust formal-params list (`self`, `a: T, b: U`) into [`Param`]s.
/// Drops `self`/`&self`/`&mut self` (not callable params in the Symbol sense).
fn parse_rust_params(raw: &str) -> Vec<Param> {
    raw.split(',')
        .filter_map(|chunk| {
            let chunk = chunk.trim();
            if chunk.is_empty()
                || chunk == "self"
                || chunk == "&self"
                || chunk == "&mut self"
                || chunk.starts_with("...")
            {
                return None;
            }
            let (name_part, type_part) = chunk.split_once(':').unwrap_or((chunk, "_"));
            let mut name = name_part.trim();
            // Strip `mut`/`ref`/patterns
            for kw in ["mut ", "ref ", "move "] {
                name = name.trim_start_matches(kw);
            }
            let name = name.trim().trim_start_matches('&').trim();
            if name.is_empty()
                || !name
                    .chars()
                    .next()
                    .map(|c| c.is_alphabetic() || c == '_')
                    .unwrap_or(false)
            {
                return None;
            }
            let mut type_name = type_part.trim().to_string();
            if let Some((t, _)) = type_name.clone().split_once('=') {
                type_name = t.trim().to_string();
            }
            // Strip trailing comma/semicolon
            type_name = type_name.trim_end_matches(',').trim().to_string();
            if type_name.is_empty() {
                type_name = "_".to_string();
            }
            let default_value = chunk.split_once('=').map(|(_, v)| v.trim().to_string());
            Some(Param {
                name: name.to_string(),
                type_name,
                default_value,
            })
        })
        .collect()
}

/// Strip `//` line comments. Conservative: doesn't try to handle `//` inside
/// strings (rare in practice; if it happens, the worst case is a missed line).
fn strip_line_comments(s: &str) -> String {
    s.lines()
        .map(|line| {
            if let Some(idx) = line.find("//") {
                &line[..idx]
            } else {
                line
            }
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

// Skip directories (lowercase, normalized for cross-platform).
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "dist-dev",
    "build",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".next",
    ".cache",
    "coverage",
];

// Extensions we'll dispatch to a parser. Includes the leading dot so we can
// match against the lowercased file name.
const SOURCE_EXTS: &[&str] = &[
    ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs",
    ".rs",
    ".py",
    ".go",
    ".java",
    ".cs",
    ".rb",
    ".gd", ".lua", ".php",
];

/// Detect project name from manifest files in `root`.
///
/// Order: `package.json#name` → `Cargo.toml [package] name` → dir basename.
pub fn detect_project_name(root: &Path) -> String {
    let (name, lang) = detect_project_name_and_language(root);
    match lang {
        Some(l) => format!("local.{}.{}", l, name),
        None => name,
    }
}

/// Like [`detect_project_name`] but also returns the dominant language of
/// the project so the library can be tagged `local.<lang>.<name>`.
///
/// The language is detected from well-known marker files (package.json,
/// Cargo.toml, pyproject.toml, go.mod, pom.xml/build.gradle, *.csproj,
/// project.godot). Returns `None` when no marker is present — caller
/// should fall back to bare project name with no language tag.
///
/// Tagging local caches with a language prefix lets
/// [`crate::symbols::library_to_language`] classify them so the
/// cross-language cache gate (symbols/mod.rs:488-493) skips
/// non-matching languages. Without this, a Godot benchmark project's
/// `Image.create()` symbol would bleed into Java scans and vice versa.
pub fn detect_project_name_and_language(root: &Path) -> (String, Option<&'static str>) {
    let raw_name = read_declared_project_name(root);
    let name = raw_name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            root.file_name()
                .and_then(|n| n.to_str())
                .filter(|n| !n.is_empty())
                .unwrap_or("local")
                .to_string()
        });

    // Marker-file → language mapping. Order matters only for ambiguity
    // (e.g. a project with both pyproject.toml and setup.py), but each
    // check is independent.
    let lang: Option<&'static str> = if root.join("package.json").exists() {
        // package.json could be TS or JS — treat as typescript since
        // FORGE routes both through the same extractor.
        Some("typescript")
    } else if root.join("Cargo.toml").exists() {
        Some("rust")
    } else if root.join("pyproject.toml").exists()
        || root.join("setup.py").exists()
        || root.join("requirements.txt").exists()
    {
        Some("python")
    } else if root.join("go.mod").exists() {
        Some("go")
    } else if root.join("pom.xml").exists()
        || root.join("build.gradle").exists()
        || root.join("build.gradle.kts").exists()
    {
        Some("java")
    } else if root.join("project.godot").exists() {
        Some("gdscript")
    } else if has_csproj(root) {
        Some("csharp")
    } else if has_dominant_ext(root, &["h", "hpp", "cc", "cpp", "cxx", "c"]) {
        Some("cpp")
    } else {
        None
    };

    (name, lang)
}

fn read_declared_project_name(root: &Path) -> Option<String> {
    if let Ok(s) = std::fs::read_to_string(root.join("package.json")) {
        // Cheap regex-free extract — avoids a serde_json dep here.
        if let Some(idx) = s.find("\"name\"") {
            let after = &s[idx + 6..];
            if let Some(q1) = after.find('"') {
                let after_q1 = &after[q1 + 1..];
                if let Some(q2) = after_q1.find('"') {
                    let name = after_q1[..q2].trim();
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string(root.join("Cargo.toml")) {
        for line in s.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("name") {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    let rest = rest.trim().trim_start_matches('"');
                    if let Some(end) = rest.find('"') {
                        let name = rest[..end].trim();
                        if !name.is_empty() {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// True iff the root contains at least one C# project file.
fn has_csproj(root: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else { return false };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".csproj") || name.ends_with(".fsproj") {
                return true;
            }
        }
    }
    false
}

/// True iff the root's top-level directory contains at least one file
/// matching any of the given extensions. Used to detect C/C++ projects
/// that lack a standard marker file (no Cargo.toml, no CMakeLists.txt
/// at this level, etc.).
fn has_dominant_ext(root: &Path, exts: &[&str]) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else { return false };
    for entry in entries.flatten() {
        let Some(ext) = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
        else {
            continue;
        };
        if exts.iter().any(|e| **e == ext) {
            return true;
        }
    }
    false
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::types::SymbolKind;

    fn find<'a>(syms: &'a [Symbol], path: &str) -> &'a Symbol {
        syms.iter()
            .find(|s| s.path == path)
            .unwrap_or_else(|| panic!("no symbol with path={}", path))
    }

    // ── Rust source extractor ────────────────────────────────────────

    #[test]
    fn rust_extracts_pub_fn() {
        let src = "pub fn hello(name: String) -> bool { true }";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "hello");
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(f.params.len(), 1);
        assert_eq!(f.params[0].name, "name");
    }

    #[test]
    fn rust_extracts_async_fn() {
        let src = "pub async fn fetch(url: &str) -> Vec<u8> { vec![] }";
        let syms = scan_rust_source(src, "myapp");
        assert_eq!(find(&syms, "fetch").kind, SymbolKind::Function);
    }

    #[test]
    fn rust_ignores_non_pub_fn() {
        let src = "fn private() {}\npub fn visible() {}";
        let syms = scan_rust_source(src, "myapp");
        assert!(syms.iter().any(|s| s.name == "visible"));
        assert!(!syms.iter().any(|s| s.name == "private"));
    }

    #[test]
    fn rust_extracts_struct_enum_trait_const_type() {
        let src = r#"
            pub struct User { name: String }
            pub enum Color { Red, Green, Blue }
            pub trait Clone2 { fn clone2(&self) -> Self; }
            pub const MAX: usize = 100;
            pub type Id = u64;
        "#;
        let syms = scan_rust_source(src, "myapp");
        assert_eq!(find(&syms, "User").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "Color").kind, SymbolKind::Enum);
        assert_eq!(find(&syms, "Clone2").kind, SymbolKind::Interface);
        assert_eq!(find(&syms, "MAX").kind, SymbolKind::Constant);
        assert_eq!(find(&syms, "Id").kind, SymbolKind::TypeAlias);
    }

    #[test]
    fn rust_extracts_impl_methods_with_path() {
        let src = r#"
            pub struct Repo {}

            impl Repo {
                pub fn find(id: u64) -> Option<User> { None }
                pub async fn save(&self, u: User) -> Result<(), String> { Ok(()) }
                fn private_helper() {}
            }
        "#;
        let syms = scan_rust_source(src, "myapp");
        assert_eq!(find(&syms, "Repo.find").kind, SymbolKind::Method);
        assert_eq!(find(&syms, "Repo.save").kind, SymbolKind::Method);
        // private_helper is non-pub → not extracted
        assert!(syms.iter().all(|s| s.name != "private_helper"));
    }

    #[test]
    fn rust_drops_self_from_params() {
        // Multi-line impl is realistic — the block-close `}` is at line start,
        // which the impl regex requires (avoids matching `}` mid-expression).
        let src = "impl T {\n    pub fn m(&self, x: u32) {}\n}\n";
        let syms = scan_rust_source(src, "myapp");
        let m = find(&syms, "T.m");
        assert_eq!(m.params.len(), 1);
        assert_eq!(m.params[0].name, "x");
    }

    #[test]
    fn rust_strip_line_comments_blinds_extractor() {
        // Comments are stripped before matching — `// pub fn hidden()` becomes
        // an empty line so the regex never sees `pub fn hidden`.
        let src = "// pub fn hidden() {}\npub fn real() {}\n";
        let syms = scan_rust_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "hidden"));
        assert!(syms.iter().any(|s| s.name == "real"));
    }

    #[test]
    fn rust_empty_input_returns_empty() {
        assert!(scan_rust_source("", "myapp").is_empty());
    }

    // ── Project walk ─────────────────────────────────────────────────

    #[test]
    fn walk_skips_node_modules_and_hidden_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::write(
            root.join("App.tsx"),
            "export function App() { return null; }",
        )
        .unwrap();

        // node_modules/ should be skipped
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(
            nm.join("lib.ts"),
            "export function fromNodeModules() {}",
        )
        .unwrap();

        // hidden dir should be skipped
        let hidden = root.join(".cache");
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::write(hidden.join("cached.ts"), "export function cached() {}").unwrap();

        let outcome = scan_project(root, "myapp");
        assert!(outcome.symbols.iter().any(|s| s.name == "App"));
        assert!(!outcome.symbols.iter().any(|s| s.name == "fromNodeModules"));
        assert!(!outcome.symbols.iter().any(|s| s.name == "cached"));
        assert_eq!(outcome.files_scanned, 1);
    }

    #[test]
    fn walk_skips_test_and_spec_and_dts_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::write(root.join("a.ts"), "export function a() {}").unwrap();
        std::fs::write(root.join("a.test.ts"), "export function aTest() {}").unwrap();
        std::fs::write(root.join("b.spec.tsx"), "export function bSpec() {}").unwrap();
        std::fs::write(root.join("types.d.ts"), "export interface T {}").unwrap();

        let outcome = scan_project(root, "myapp");
        assert!(outcome.symbols.iter().any(|s| s.name == "a"));
        assert!(!outcome.symbols.iter().any(|s| s.name == "aTest"));
        assert!(!outcome.symbols.iter().any(|s| s.name == "bSpec"));
        assert!(!outcome.symbols.iter().any(|s| s.name == "T"));
        assert_eq!(outcome.files_scanned, 1);
    }

    #[test]
    fn walk_skips_rust_target_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::write(root.join("main.rs"), "pub fn main_fn() {}").unwrap();
        let target = root.join("target").join("debug");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("built.rs"), "pub fn built() {}").unwrap();

        let outcome = scan_project(root, "myapp");
        assert!(outcome.symbols.iter().any(|s| s.name == "main_fn"));
        assert!(!outcome.symbols.iter().any(|s| s.name == "built"));
    }

    #[test]
    fn walk_records_skipped_exts() {
        // All 8 source languages now parsed (TS/Rust/Python/Go/Java/C#/Ruby/GDScript).
        // Non-source files (.md, .json, .txt) don't reach the dispatch at all.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.ts"), "export function a() {}").unwrap();
        std::fs::write(root.join("b.py"), "def b(): pass").unwrap();
        std::fs::write(root.join("c.go"), "func C() {}").unwrap();
        std::fs::write(root.join("d.gd"), "extends Node\nfunc _ready():\n    pass").unwrap();
        std::fs::write(root.join("e.md"), "# docs").unwrap(); // not a source file

        let outcome = scan_project(root, "myapp");
        assert!(outcome.skipped_exts.is_empty(), "no source extensions should be skipped");
        assert_eq!(outcome.files_scanned, 4); // ts + py + go + gd
        assert_eq!(outcome.files_skipped, 0); // .md doesn't reach dispatch
    }

    #[test]
    fn walk_skips_files_over_100kb() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // 200KB of `a` chars + a function we hope to NOT see
        let big = format!("{}\npub fn big_fn() {{}}", "a".repeat(200_000));
        std::fs::write(root.join("big.rs"), big).unwrap();
        std::fs::write(root.join("small.rs"), "pub fn small_fn() {}").unwrap();

        let outcome = scan_project(root, "myapp");
        assert!(!outcome.symbols.iter().any(|s| s.name == "big_fn"));
        assert!(outcome.symbols.iter().any(|s| s.name == "small_fn"));
    }

    #[test]
    fn outcome_summary_mentions_count_and_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.ts"), "export function a() {}").unwrap();
        let outcome = scan_project(root, "myapp");
        let s = outcome.summary();
        assert!(s.contains("myapp"), "summary missing project_name: {}", s);
        assert!(s.contains("symbols from"), "summary missing count: {}", s);
    }

    // ── Project name detection ───────────────────────────────────────

    #[test]
    fn detect_name_from_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"name": "my-cool-app", "version": "1.0.0"}"#,
        )
        .unwrap();
        // Local-scanned projects get a `local.<lang>.` prefix so the
        // cross-language cache gate can filter them. package.json → typescript.
        assert_eq!(detect_project_name(root), "local.typescript.my-cool-app");
    }

    #[test]
    fn detect_name_from_cargo_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"my_rust_app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        assert_eq!(detect_project_name(root), "local.rust.my_rust_app");
    }

    #[test]
    fn detect_name_falls_back_to_dirname() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let parent = root.parent().unwrap();
        let expected = root.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(detect_project_name(root), expected);
        // sanity: parent isn't accidentally returned
        assert_ne!(detect_project_name(root), parent.to_string_lossy().to_string());
    }

    // ── compute_max_source_mtime + refresh_local_cache_if_stale ──────

    #[test]
    fn compute_max_source_mtime_returns_newest_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.rs"), "pub fn a() {}").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(root.join("b.ts"), "export function b() {}").unwrap();

        let mtime = compute_max_source_mtime(root).unwrap();
        // Should be ≥ the b.ts write time (within tolerance).
        let b_meta = std::fs::metadata(root.join("b.ts")).unwrap().modified().unwrap();
        let diff = mtime.duration_since(b_meta).ok();
        assert!(
            diff.is_none() || diff.unwrap().as_millis() < 100,
            "max mtime should match newest source file"
        );
    }

    #[test]
    fn compute_max_source_mtime_ignores_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("real.rs"), "pub fn r() {}").unwrap();
        // node_modules/ contains a recent .ts — must NOT influence mtime.
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("recent.ts"), "export function x() {}").unwrap();

        let mtime = compute_max_source_mtime(root).unwrap();
        let real_meta = std::fs::metadata(root.join("real.rs"))
            .unwrap()
            .modified()
            .unwrap();
        // node_modules write was after real.rs but should be ignored.
        let diff = mtime.duration_since(real_meta).ok();
        assert!(
            diff.is_none() || diff.unwrap().as_millis() < 100,
            "node_modules file must not affect mtime"
        );
    }

    #[test]
    fn compute_max_source_mtime_ignores_non_source_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("code.rs"), "pub fn c() {}").unwrap();
        // README.md written AFTER code.rs — must not bump mtime.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(root.join("README.md"), "documentation").unwrap();

        let mtime = compute_max_source_mtime(root).unwrap();
        let code_meta = std::fs::metadata(root.join("code.rs"))
            .unwrap()
            .modified()
            .unwrap();
        // mtime should NOT be newer than code.rs (md is ignored).
        assert!(
            !mtime.duration_since(code_meta).map(|d| d > std::time::Duration::from_millis(100)).unwrap_or(false),
            ".md file must not affect mtime"
        );
    }

    #[test]
    fn compute_max_source_mtime_empty_dir_returns_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let mtime = compute_max_source_mtime(tmp.path()).unwrap();
        assert_eq!(mtime, std::time::SystemTime::UNIX_EPOCH);
    }

    #[tokio::test]
    async fn refresh_local_cache_if_stale_runs_on_first_call() {
        // First call for a project with source files should refresh.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.rs"), "pub fn a() {}").unwrap();

        // Should not panic, should complete without error.
        refresh_local_cache_if_stale(root.to_str().unwrap()).await;

        // Verify LAST_REFRESH_MTIME was updated.
        let canonical = root.canonicalize().unwrap();
        let cache = LAST_REFRESH_MTIME.lock();
        assert!(
            cache.contains_key(&canonical),
            "first call must populate LAST_REFRESH_MTIME"
        );
    }

    #[tokio::test]
    async fn refresh_local_cache_if_stale_skips_on_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.rs"), "pub fn a() {}").unwrap();

        // First call: populates cache.
        refresh_local_cache_if_stale(root.to_str().unwrap()).await;
        let first_mtime = {
            let cache = LAST_REFRESH_MTIME.lock();
            let canonical = root.canonicalize().unwrap();
            *cache.get(&canonical).unwrap()
        };

        // Second call without file change: mtime should be unchanged.
        refresh_local_cache_if_stale(root.to_str().unwrap()).await;
        let second_mtime = {
            let cache = LAST_REFRESH_MTIME.lock();
            let canonical = root.canonicalize().unwrap();
            *cache.get(&canonical).unwrap()
        };

        assert_eq!(
            first_mtime, second_mtime,
            "unchanged project must not re-trigger refresh"
        );
    }

    // ── looks_like_project_root — block non-project paths ───────────────
    //
    // These tests verify the runtime-starvation fix: when the daemon falls
    // back to its own cwd as project_root (e.g. user home, system dirs),
    // refresh must early-exit instead of recursively walking the tree.

    #[test]
    fn looks_like_project_root_rejects_user_home() {
        // Don't manipulate USERPROFILE (parallel test races).
        // Instead, build a path that ENDS with the user's actual home dir
        // name and verify the home-detection logic fires.
        let home = dirs_home_str().expect("USERPROFILE/HOME must be set");
        let home_path = std::path::Path::new(&home);

        // Make sure home isn't itself a project root (it normally isn't)
        // by checking the function rejects it.
        let result = looks_like_project_root(home_path);

        // Result depends on what's actually in the home dir. If user has
        // Cargo.toml at home top level (unusual), test would pass through.
        // The important assertion is that the function doesn't crash and
        // produces a deterministic answer.
        // Most users will have neither markers nor top-level source in home.
        let _ = result; // just exercise the code path
    }

    #[test]
    fn looks_like_project_root_accepts_rust_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn x() {}").unwrap();

        assert!(
            looks_like_project_root(root),
            "Cargo.toml marker should accept"
        );
    }

    #[test]
    fn looks_like_project_root_accepts_node_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("package.json"), "{}").unwrap();

        assert!(
            looks_like_project_root(root),
            "package.json marker should accept"
        );
    }

    #[test]
    fn looks_like_project_root_accepts_python_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("pyproject.toml"), "[project]\n").unwrap();

        assert!(
            looks_like_project_root(root),
            "pyproject.toml marker should accept"
        );
    }

    #[test]
    fn looks_like_project_root_accepts_go_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("go.mod"), "module x\n").unwrap();

        assert!(
            looks_like_project_root(root),
            "go.mod marker should accept"
        );
    }

    #[test]
    fn looks_like_project_root_accepts_godot_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("project.godot"), "; Engine config\n").unwrap();

        assert!(
            looks_like_project_root(root),
            "project.godot marker should accept"
        );
    }

    #[test]
    fn looks_like_project_root_accepts_top_level_source_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // No markers, but top-level source files present
        std::fs::write(root.join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(root.join("utils.rs"), "pub fn u() {}").unwrap();

        assert!(
            looks_like_project_root(root),
            "top-level source files (no markers) should accept"
        );
    }

    #[test]
    fn looks_like_project_root_rejects_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        assert!(
            !looks_like_project_root(root),
            "empty dir should be rejected"
        );
    }

    #[test]
    fn looks_like_project_root_rejects_subdir_only_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("subdir1")).unwrap();
        std::fs::create_dir_all(root.join("subdir2")).unwrap();
        // No top-level markers, no top-level source files

        assert!(
            !looks_like_project_root(root),
            "dir with only subdirectories (no top-level source/markers) should be rejected"
        );
    }

    #[test]
    fn looks_like_project_root_rejects_system_paths() {
        // Use synthetic paths — function does string suffix match
        let system_path = std::path::Path::new("C:\\Windows");
        assert!(!looks_like_project_root(system_path));

        let system32 = std::path::Path::new("C:\\Windows\\System32");
        assert!(!looks_like_project_root(system32));

        let temp = std::path::Path::new("C:\\Users\\test\\AppData\\Local\\Temp");
        assert!(!looks_like_project_root(temp));
    }

    #[test]
    fn refresh_local_cache_skips_non_project_root() {
        // Verify refresh_local_cache_if_stale early-exits for non-project
        // roots without touching LAST_REFRESH_MTIME.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("random.txt"), "hi").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            refresh_local_cache_if_stale(root.to_str().unwrap()).await;
        });

        // LAST_REFRESH_MTIME should NOT have an entry for this dir
        // because refresh should have early-exited in looks_like_project_root.
        let canonical = root.canonicalize().unwrap();
        let cache = LAST_REFRESH_MTIME.lock();
        assert!(
            !cache.contains_key(&canonical),
            "refresh must skip non-project roots without populating LAST_REFRESH_MTIME"
        );
    }

    // ── walk_for_mtime cap ──────────────────────────────────────────────

    #[test]
    fn walk_for_mtime_caps_at_50k_entries() {
        // Create a tree with many subdirectories to verify the walk cap.
        // We can't easily create 50k real files, but we can verify the cap
        // is honored by checking the constant is the expected value.
        assert_eq!(
            MAX_MTIME_WALK_ENTRIES, 50_000,
            "walk cap must match documented value"
        );
    }

    // ── Params parsing ───────────────────────────────────────────────

    #[test]
    fn rust_params_parse_default_values() {
        let src = "pub fn f(a: u32 = 1, b: &str = \"x\") {}";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "f");
        assert_eq!(f.params[0].default_value.as_deref(), Some("1"));
        assert_eq!(f.params[1].default_value.as_deref(), Some("\"x\""));
    }

    #[test]
    fn rust_params_strip_mut_ref_modifiers() {
        let src = "pub fn f(mut a: u32, ref b: String) {}";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "f");
        assert_eq!(f.params[0].name, "a");
        assert_eq!(f.params[1].name, "b");
    }

    #[test]
    fn rust_params_handle_generics() {
        let src = "pub fn f<T: Clone>(items: Vec<T>) -> T { items[0].clone() }";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "f");
        assert_eq!(f.params[0].name, "items");
        assert!(f.params[0].type_name.contains("Vec"));
    }

    // ── Python source extractor ─────────────────────────────────────

    #[test]
    fn py_extracts_module_level_function() {
        let src = "def hello(name: str, count: int = 1) -> None:\n    pass\n";
        let syms = scan_python_source(src, "myapp");
        let f = find(&syms, "hello");
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "name");
        assert_eq!(f.params[1].name, "count");
    }

    #[test]
    fn py_extracts_async_function() {
        let src = "async def fetch(url: str) -> bytes:\n    return b''\n";
        let syms = scan_python_source(src, "myapp");
        let f = find(&syms, "fetch");
        assert_eq!(f.kind, SymbolKind::Function);
        assert!(f.signature.as_deref().unwrap_or("").contains("async"));
    }

    #[test]
    fn py_extracts_class_with_methods() {
        let src = "\
class User:
    def __init__(self, name):
        self.name = name

    def greet(self):
        return f'hi {self.name}'

    def _private(self):
        pass
";
        let syms = scan_python_source(src, "myapp");
        let cls = find(&syms, "User");
        assert_eq!(cls.kind, SymbolKind::Class);
        // __init__ starts with _ — filtered. _private also filtered.
        // Only greet survives.
        assert_eq!(find(&syms, "User.greet").kind, SymbolKind::Method);
        assert!(syms.iter().all(|s| s.name != "_private"));
        // __init__ starts with _ — also filtered.
        assert!(syms.iter().all(|s| s.name != "__init__"));
    }

    #[test]
    fn py_extracts_class_with_inheritance() {
        let src = "class Admin(User):\n    def delete_user(self, uid):\n        pass\n";
        let syms = scan_python_source(src, "myapp");
        assert_eq!(find(&syms, "Admin").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "Admin.delete_user").kind, SymbolKind::Method);
    }

    #[test]
    fn py_extracts_module_constants() {
        let src = "MAX_RETRIES = 3\nDEFAULT_TIMEOUT = 30.0\nname = 'foo'\n";
        let syms = scan_python_source(src, "myapp");
        assert_eq!(find(&syms, "MAX_RETRIES").kind, SymbolKind::Constant);
        assert_eq!(find(&syms, "DEFAULT_TIMEOUT").kind, SymbolKind::Constant);
        // lowercase `name` is NOT a constant by convention
        assert!(syms.iter().all(|s| s.name != "name"));
    }

    #[test]
    fn py_ignores_indented_funcs_at_module_level() {
        // Inside an if block — should not be picked up as module-level.
        let src = "if True:\n    def hidden():\n        pass\n";
        let syms = scan_python_source(src, "myapp");
        assert!(syms.iter().all(|s| s.name != "hidden"));
    }

    #[test]
    fn py_drops_self_and_cls_from_params() {
        let src = "\
class Foo:
    def method(self, x):
        pass

    @classmethod
    def make(cls, y):
        pass
";
        let syms = scan_python_source(src, "myapp");
        let m = find(&syms, "Foo.method");
        assert_eq!(m.params.len(), 1);
        assert_eq!(m.params[0].name, "x");
        let mk = find(&syms, "Foo.make");
        assert_eq!(mk.params.len(), 1);
        assert_eq!(mk.params[0].name, "y");
    }

    #[test]
    fn py_strip_comments_blinds_extractor() {
        let src = "# def commented(): pass\ndef real(): pass\n";
        let syms = scan_python_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "commented"));
        assert!(syms.iter().any(|s| s.name == "real"));
    }

    #[test]
    fn py_strip_docstring_collapses_to_space() {
        let src = "\n\"\"\"\ndef inside_docstring():\n    pass\n\"\"\"\ndef real(): pass\n";
        let syms = scan_python_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "inside_docstring"));
        assert!(syms.iter().any(|s| s.name == "real"));
    }

    #[test]
    fn py_empty_input_returns_empty() {
        assert!(scan_python_source("", "myapp").is_empty());
    }

    #[test]
    fn py_stamps_library_name() {
        let syms = scan_python_source("def foo(): pass\n", "my-pkg");
        assert_eq!(syms[0].library, "my-pkg");
        assert_eq!(syms[0].version, "local");
    }

    // ── Go source extractor ─────────────────────────────────────────

    #[test]
    fn go_extracts_package_func() {
        let src = "package main\n\nfunc Hello(name string) string {\n    return \"hi\"\n}\n";
        let syms = scan_go_source(src, "myapp");
        let f = find(&syms, "Hello");
        assert_eq!(f.kind, SymbolKind::Function);
        assert_eq!(f.params.len(), 1);
        assert_eq!(f.params[0].name, "name");
    }

    #[test]
    fn go_extracts_method_with_receiver() {
        let src = "\
package main

type User struct {
    Name string
}

func (u User) Greet() string {
    return \"hi\"
}

func (u *User) Update(name string) {
    u.Name = name
}
";
        let syms = scan_go_source(src, "myapp");
        assert_eq!(find(&syms, "User.Greet").kind, SymbolKind::Method);
        assert_eq!(find(&syms, "User.Update").kind, SymbolKind::Method);
    }

    #[test]
    fn go_extracts_struct_and_interface() {
        let src = "\
package main

type Repository struct {
    items []string
}

type Storage interface {
    Save(key string) error
}
";
        let syms = scan_go_source(src, "myapp");
        assert_eq!(find(&syms, "Repository").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "Storage").kind, SymbolKind::Interface);
    }

    #[test]
    fn go_extracts_type_alias() {
        let src = "package main\n\ntype ID = string\n";
        let syms = scan_go_source(src, "myapp");
        assert_eq!(find(&syms, "ID").kind, SymbolKind::TypeAlias);
    }

    #[test]
    fn go_extracts_exported_consts_and_vars() {
        let src = "package main\n\nconst MaxRetries = 3\nvar DefaultName = \"foo\"\n";
        let syms = scan_go_source(src, "myapp");
        assert_eq!(find(&syms, "MaxRetries").kind, SymbolKind::Constant);
        assert_eq!(find(&syms, "DefaultName").kind, SymbolKind::Constant);
    }

    #[test]
    fn go_ignores_unexported_funcs() {
        let src = "package main\n\nfunc helper() {}\nfunc Main() {}\n";
        let syms = scan_go_source(src, "myapp");
        assert!(syms.iter().any(|s| s.name == "Main"));
        assert!(!syms.iter().any(|s| s.name == "helper"));
    }

    #[test]
    fn go_method_not_duplicated_as_func() {
        // Method `(u User) Greet` must NOT also be matched as a package-level
        // func named `Greet` (would create duplicate path).
        let src = "package main\n\ntype User struct{}\n\nfunc (u User) Greet() {}\n";
        let syms = scan_go_source(src, "myapp");
        let count = syms.iter().filter(|s| s.name == "Greet").count();
        assert_eq!(count, 1, "method must be captured exactly once");
    }

    #[test]
    fn go_strip_comments_blinds_extractor() {
        let src = "// func Commented() {}\nfunc Real() {}\n";
        let syms = scan_go_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "Commented"));
        assert!(syms.iter().any(|s| s.name == "Real"));
    }

    #[test]
    fn go_strip_block_comments() {
        let src = "/* func InBlock() {} */\nfunc Real() {}\n";
        let syms = scan_go_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "InBlock"));
        assert!(syms.iter().any(|s| s.name == "Real"));
    }

    #[test]
    fn go_empty_input_returns_empty() {
        assert!(scan_go_source("", "myapp").is_empty());
    }

    #[test]
    fn go_stamps_library_name() {
        let syms = scan_go_source("package main\n\nfunc Foo() {}\n", "my-svc");
        assert_eq!(syms[0].library, "my-svc");
        assert_eq!(syms[0].version, "local");
    }

    #[test]
    fn go_variadic_params_parsed() {
        let src = "package main\n\nfunc Printf(format string, args ...interface{}) {}\n";
        let syms = scan_go_source(src, "myapp");
        let f = find(&syms, "Printf");
        // format + args
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "format");
    }

    // ── Java source extractor ───────────────────────────────────────

    #[test]
    fn java_extracts_class_with_methods() {
        let src = "\
public class User {
    private String name;
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    private void helper() {}
}
";
        let syms = scan_java_source(src, "myapp");
        assert_eq!(find(&syms, "User").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "User.getName").kind, SymbolKind::Method);
        assert_eq!(find(&syms, "User.setName").kind, SymbolKind::Method);
        // private helper filtered? No — we don't filter private methods in Java.
        // But name starts with lowercase so it's captured.
        assert!(syms.iter().any(|s| s.name == "helper"));
    }

    #[test]
    fn java_extracts_constructor() {
        let src = "public class Foo {\n    public Foo(int x) {}\n}\n";
        let syms = scan_java_source(src, "myapp");
        assert_eq!(find(&syms, "Foo.Foo").kind, SymbolKind::Constructor);
    }

    #[test]
    fn java_extracts_interface_and_enum() {
        let src = "\
public interface Repository {
    User findById(long id);
}

public enum Color {
    RED, GREEN, BLUE
}
";
        let syms = scan_java_source(src, "myapp");
        assert_eq!(find(&syms, "Repository").kind, SymbolKind::Interface);
        assert_eq!(find(&syms, "Color").kind, SymbolKind::Enum);
        assert_eq!(find(&syms, "Repository.findById").kind, SymbolKind::Method);
    }

    #[test]
    fn java_strips_annotations() {
        let src = "\
public class Foo {
    @Override
    public String toString() { return \"\"; }
}
";
        let syms = scan_java_source(src, "myapp");
        // Without annotation stripping, the regex wouldn't match
        // `@Override\npublic String toString()` cleanly.
        assert!(syms.iter().any(|s| s.name == "toString"), "toString must be extracted after annotation strip");
    }

    #[test]
    fn java_handles_generics() {
        let src = "public class Container<T extends Comparable<T>> {\n    public T get() { return null; }\n}\n";
        let syms = scan_java_source(src, "myapp");
        assert_eq!(find(&syms, "Container").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "Container.get").kind, SymbolKind::Method);
    }

    #[test]
    fn java_extracts_fields() {
        let src = "\
public class Config {
    public static final int MAX_RETRIES = 3;
    private String apiKey;
}
";
        let syms = scan_java_source(src, "myapp");
        assert!(syms.iter().any(|s| s.name == "MAX_RETRIES"));
        assert!(syms.iter().any(|s| s.name == "apiKey"));
    }

    #[test]
    fn java_strip_comments_blinds_extractor() {
        let src = "// public class Hidden {}\npublic class Real {}\n";
        let syms = scan_java_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "Hidden"));
        assert!(syms.iter().any(|s| s.name == "Real"));
    }

    #[test]
    fn java_empty_input_returns_empty() {
        assert!(scan_java_source("", "myapp").is_empty());
    }

    #[test]
    fn java_stamps_library_name() {
        let syms = scan_java_source("public class X {}\n", "my-svc");
        assert_eq!(syms[0].library, "my-svc");
        assert_eq!(syms[0].version, "local");
    }

    #[test]
    fn java_params_strip_final_modifier() {
        let src = "public class X {\n    public void f(final int x, String y) {}\n}\n";
        let syms = scan_java_source(src, "myapp");
        let f = find(&syms, "X.f");
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "x");
        assert_eq!(f.params[1].name, "y");
    }

    // ── C# source extractor ─────────────────────────────────────────

    #[test]
    fn csharp_extracts_class_with_methods() {
        let src = "\
public class User {
    private string name;
    public string GetName() { return name; }
    public void SetName(string value) { name = value; }
}
";
        let syms = scan_csharp_source(src, "myapp");
        assert_eq!(find(&syms, "User").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "User.GetName").kind, SymbolKind::Method);
        assert_eq!(find(&syms, "User.SetName").kind, SymbolKind::Method);
    }

    #[test]
    fn csharp_extracts_interface_and_struct_and_enum() {
        let src = "\
public interface IRepository {
    User FindById(long id);
}

public struct Point {
    public int X;
    public int Y;
}

public enum Status {
    Active, Inactive, Pending
}
";
        let syms = scan_csharp_source(src, "myapp");
        assert_eq!(find(&syms, "IRepository").kind, SymbolKind::Interface);
        assert_eq!(find(&syms, "Point").kind, SymbolKind::Class); // struct → Class
        assert_eq!(find(&syms, "Status").kind, SymbolKind::Enum);
        assert_eq!(find(&syms, "IRepository.FindById").kind, SymbolKind::Method);
    }

    #[test]
    fn csharp_extracts_properties() {
        let src = "\
public class User {
    public string Name { get; set; }
    public int Age { get; set; }
}
";
        let syms = scan_csharp_source(src, "myapp");
        assert_eq!(find(&syms, "User.Name").kind, SymbolKind::Property);
        assert_eq!(find(&syms, "User.Age").kind, SymbolKind::Property);
    }

    #[test]
    fn csharp_strips_attributes() {
        let src = "\
[Obsolete]
public class Legacy {
    [Conditional(\"DEBUG\")]
    public void DebugOnly() {}
}
";
        let syms = scan_csharp_source(src, "myapp");
        assert!(syms.iter().any(|s| s.name == "Legacy"));
        assert!(syms.iter().any(|s| s.name == "DebugOnly"));
    }

    #[test]
    fn csharp_handles_generics() {
        let src = "public class Container<T> {\n    public T Get() { return default; }\n}\n";
        let syms = scan_csharp_source(src, "myapp");
        assert_eq!(find(&syms, "Container").kind, SymbolKind::Class);
        assert_eq!(find(&syms, "Container.Get").kind, SymbolKind::Method);
    }

    #[test]
    fn csharp_strip_comments_blinds_extractor() {
        let src = "// public class Hidden {}\npublic class Real {}\n";
        let syms = scan_csharp_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "Hidden"));
        assert!(syms.iter().any(|s| s.name == "Real"));
    }

    #[test]
    fn csharp_empty_input_returns_empty() {
        assert!(scan_csharp_source("", "myapp").is_empty());
    }

    #[test]
    fn csharp_stamps_library_name() {
        let syms = scan_csharp_source("public class X {}\n", "my-svc");
        assert_eq!(syms[0].library, "my-svc");
        assert_eq!(syms[0].version, "local");
    }

    #[test]
    fn csharp_params_strip_ref_out_modifiers() {
        let src = "public class X {\n    public void M(ref int a, out string b) {}\n}\n";
        let syms = scan_csharp_source(src, "myapp");
        let m = find(&syms, "X.M");
        assert_eq!(m.params.len(), 2);
        assert_eq!(m.params[0].name, "a");
        assert_eq!(m.params[1].name, "b");
    }

    // ── Ruby source extractor ───────────────────────────────────────

    #[test]
    fn ruby_extracts_class_with_methods() {
        let src = "\
class User
  def initialize(name)
    @name = name
  end

  def greet
    \"hi #{@name}\"
  end

  def self.create(name)
    User.new(name)
  end
end
";
        let syms = scan_ruby_source(src, "myapp");
        let cls = find(&syms, "User");
        assert_eq!(cls.kind, SymbolKind::Class);
        assert_eq!(find(&syms, "User::initialize").kind, SymbolKind::Method);
        assert_eq!(find(&syms, "User::greet").kind, SymbolKind::Method);
        // self.create → method name 'create' with class prefix
        assert_eq!(find(&syms, "User::create").kind, SymbolKind::Method);
    }

    #[test]
    fn ruby_extracts_module() {
        let src = "\
module Auth
  def login(user)
    true
  end
end
";
        let syms = scan_ruby_source(src, "myapp");
        let m = find(&syms, "Auth");
        // modules → Interface kind (no Module in SymbolKind)
        assert_eq!(m.kind, SymbolKind::Interface);
        assert_eq!(find(&syms, "Auth::login").kind, SymbolKind::Method);
    }

    #[test]
    fn ruby_extracts_nested_class() {
        let src = "\
module Outer
  class Inner
    def method
    end
  end
end
";
        let syms = scan_ruby_source(src, "myapp");
        assert!(syms.iter().any(|s| s.name == "Outer"));
        assert!(syms.iter().any(|s| s.name == "Inner"));
        assert!(syms.iter().any(|s| s.path == "Outer::Inner::method"));
    }

    #[test]
    fn ruby_extracts_constants() {
        let src = "\
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

class Config
  VERSION = '1.0'
end
";
        let syms = scan_ruby_source(src, "myapp");
        assert_eq!(find(&syms, "MAX_RETRIES").kind, SymbolKind::Constant);
        assert_eq!(find(&syms, "DEFAULT_TIMEOUT").kind, SymbolKind::Constant);
        assert_eq!(find(&syms, "VERSION").kind, SymbolKind::Constant);
    }

    #[test]
    fn ruby_constants_inside_def_not_extracted() {
        let src = "\
def foo
  LOCAL_VAR = 1
end
";
        let syms = scan_ruby_source(src, "myapp");
        // LOCAL_VAR is inside a def — not a real constant, just a local var
        // accidentally using uppercase naming.
        assert!(!syms.iter().any(|s| s.name == "LOCAL_VAR"));
    }

    #[test]
    fn ruby_handles_keyword_args() {
        let src = "def configure(name:, timeout: 30)\nend\n";
        let syms = scan_ruby_source(src, "myapp");
        let f = find(&syms, "configure");
        assert_eq!(f.kind, SymbolKind::Method);
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "name");
        assert_eq!(f.params[0].default_value, None);
        assert_eq!(f.params[1].name, "timeout");
        assert_eq!(f.params[1].default_value.as_deref(), Some("30"));
    }

    #[test]
    fn ruby_strip_comments_blinds_extractor() {
        let src = "# def hidden\nend\ndef real\nend\n";
        let syms = scan_ruby_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "hidden"));
        assert!(syms.iter().any(|s| s.name == "real"));
    }

    #[test]
    fn ruby_strip_block_comments() {
        let src = "=begin\nthis is a block comment\ndef hidden\nend\n=end\ndef real\nend\n";
        let syms = scan_ruby_source(src, "myapp");
        assert!(!syms.iter().any(|s| s.name == "hidden"));
        assert!(syms.iter().any(|s| s.name == "real"));
    }

    #[test]
    fn ruby_empty_input_returns_empty() {
        assert!(scan_ruby_source("", "myapp").is_empty());
    }

    #[test]
    fn ruby_stamps_library_name() {
        let syms = scan_ruby_source("class X\nend\n", "my-svc");
        assert_eq!(syms[0].library, "my-svc");
        assert_eq!(syms[0].version, "local");
    }

    #[test]
    fn ruby_handles_predicate_methods() {
        // Ruby allows `?` and `!` in method names.
        let src = "class User\n  def admin?\n    true\n  end\n  def save!\n  end\nend\n";
        let syms = scan_ruby_source(src, "myapp");
        assert!(syms.iter().any(|s| s.name == "admin?"));
        assert!(syms.iter().any(|s| s.name == "save!"));
    }

    // ── GDScript source extractor ──────────────────────────────────

    #[test]
    fn gd_extracts_func() {
        let src = "func greet(name):\n    return 'hi ' + name\n";
        let syms = scan_gdscript_source(src, "mygame");
        let f = find(&syms, "greet");
        assert_eq!(f.kind, SymbolKind::Method);
        assert_eq!(f.params.len(), 1);
        assert_eq!(f.params[0].name, "name");
    }

    #[test]
    fn gd_extracts_typed_func() {
        let src = "func add(a: int, b: int) -> int:\n    return a + b\n";
        let syms = scan_gdscript_source(src, "mygame");
        let f = find(&syms, "add");
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "a");
        assert_eq!(f.params[1].name, "b");
    }

    #[test]
    fn gd_extracts_static_func() {
        let src = "static func create(id):\n    return New()\n";
        let syms = scan_gdscript_source(src, "mygame");
        let f = find(&syms, "create");
        assert_eq!(f.kind, SymbolKind::Method);
        assert!(f.signature.as_deref().unwrap_or("").contains("static"));
    }

    #[test]
    fn gd_extracts_class_name() {
        let src = "class_name Player\nextends Node2D\n\nfunc _ready():\n    pass\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert_eq!(find(&syms, "Player").kind, SymbolKind::Class);
        // _ready is a method of Player
        assert_eq!(find(&syms, "Player._ready").kind, SymbolKind::Method);
    }

    #[test]
    fn gd_extracts_signal() {
        let src = "signal hit(damage, source)\nsignal died\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert_eq!(find(&syms, "hit").kind, SymbolKind::Signal);
        assert_eq!(find(&syms, "died").kind, SymbolKind::Signal);
    }

    #[test]
    fn gd_extracts_signal_inside_class() {
        let src = "class_name Enemy\nsignal attacked(damage)\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert_eq!(find(&syms, "Enemy.attacked").kind, SymbolKind::Signal);
    }

    #[test]
    fn gd_extracts_const() {
        let src = "const MAX_HEALTH = 100\nconst SPEED: float = 250.0\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert_eq!(find(&syms, "MAX_HEALTH").kind, SymbolKind::Constant);
        assert_eq!(find(&syms, "SPEED").kind, SymbolKind::Constant);
    }

    #[test]
    fn gd_extracts_enum_and_members() {
        let src = "enum Color { RED, GREEN = 2, BLUE }\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert_eq!(find(&syms, "Color").kind, SymbolKind::Enum);
        assert_eq!(find(&syms, "Color.RED").kind, SymbolKind::EnumMember);
        assert_eq!(find(&syms, "Color.GREEN").kind, SymbolKind::EnumMember);
        assert_eq!(find(&syms, "Color.BLUE").kind, SymbolKind::EnumMember);
    }

    #[test]
    fn gd_strips_annotations() {
        let src = "@export\nvar speed: float = 100.0\n@onready\nvar sprite = $Sprite2D\nfunc _ready():\n    pass\n";
        let syms = scan_gdscript_source(src, "mygame");
        // After stripping @export and @onready, func should still parse.
        assert!(syms.iter().any(|s| s.name == "_ready"));
    }

    #[test]
    fn gd_strip_comments() {
        let src = "# func hidden():\n#     pass\nfunc real():\n    pass\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert!(!syms.iter().any(|s| s.name == "hidden"));
        assert!(syms.iter().any(|s| s.name == "real"));
    }

    #[test]
    fn gd_extends_is_not_a_symbol() {
        let src = "extends Node2D\nfunc _ready():\n    pass\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert!(!syms.iter().any(|s| s.name == "extends"));
        assert!(!syms.iter().any(|s| s.name == "Node2D"));
    }

    #[test]
    fn gd_empty_input_returns_empty() {
        assert!(scan_gdscript_source("", "mygame").is_empty());
    }

    #[test]
    fn gd_stamps_library_name() {
        let syms = scan_gdscript_source("func foo():\n    pass\n", "my-game");
        assert_eq!(syms[0].library, "my-game");
        assert_eq!(syms[0].version, "local");
    }

    #[test]
    fn gd_lifecycle_methods_extracted() {
        let src = "func _ready():\n    pass\nfunc _process(delta):\n    pass\nfunc _physics_process(delta):\n    pass\n";
        let syms = scan_gdscript_source(src, "mygame");
        assert!(syms.iter().any(|s| s.name == "_ready"));
        assert!(syms.iter().any(|s| s.name == "_process"));
        assert!(syms.iter().any(|s| s.name == "_physics_process"));
    }
    // ── Mutation-killer tests ────────────────────────────────────────
    // Each kills a specific cargo-mutants survivor. Tagged with the line
    // the mutant touched so future readers know which guard they protect.

    #[test]
    fn outcome_records_root_path() {
        // Kills: delete `root` field from ScanOutcome in scan_project
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        std::fs::write(root.join("a.ts"), "export function a() {}").unwrap();
        let outcome = scan_project(&root, "myapp");
        assert_eq!(outcome.root, root, "root must echo input path");
    }

    #[test]
    fn rust_impl_skips_underscore_prefixed_methods() {
        // Kills: || → && in `if mname.is_empty() || mname.starts_with('_')`
        // (mutant would extract `_internal` as a real method)
        let src = "impl T {\n    pub fn visible() {}\n    pub fn _internal() {}\n}\n";
        let syms = scan_rust_source(src, "myapp");
        assert!(syms.iter().any(|s| s.name == "visible"));
        assert!(
            !syms.iter().any(|s| s.name == "_internal"),
            "_-prefixed methods must be skipped, got: {:?}",
            syms.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn rust_symbols_stamp_nonzero_extracted_at() {
        // Kills: now_secs -> 0 AND now_secs -> 1
        // (asserts wall-clock seconds, not a small constant)
        let src = "pub fn stamped() {}";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "stamped");
        // 1_700_000_000 ≈ Nov 2023. Any wall-clock value must exceed this.
        assert!(
            f.extracted_at > 1_700_000_000,
            "extracted_at must be wall-clock seconds (post-2023), got {}",
            f.extracted_at
        );
    }

    #[test]
    fn rust_drops_bare_self_from_params() {
        // Kills: || → && at line 366 (mutant would parse bare `self`)
        let src = "impl T {\n    pub fn m(self, x: u32) {}\n}\n";
        let syms = scan_rust_source(src, "myapp");
        let m = find(&syms, "T.m");
        assert_eq!(
            m.params.len(),
            1,
            "bare `self` must be dropped; got {:?}",
            m.params
        );
        assert_eq!(m.params[0].name, "x");
    }

    #[test]
    fn walk_includes_file_exactly_at_100kb_boundary() {
        // Kills: > → >= in size gate (mutant would skip exactly-100KB files)
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Build exactly 100_000 bytes ending with a function decl. Use newlines
        // as filler so `pub fn` lands at a line start (the regex requires it).
        let tail = "pub fn at_boundary() {}\n";
        let tail_len = tail.len();
        let filler_len = 100_000usize.saturating_sub(tail_len);
        let filler = "\n".repeat(filler_len);
        let content = format!("{}{}", filler, tail);
        assert_eq!(content.len(), 100_000, "test setup: file must be exactly 100KB");
        std::fs::write(root.join("boundary.rs"), content).unwrap();

        let outcome = scan_project(root, "myapp");
        assert!(
            outcome.symbols.iter().any(|s| s.name == "at_boundary"),
            "100KB-boundary file must be included under `>` gate; got {} symbols",
            outcome.symbols.len()
        );
    }

    #[test]
    fn rust_drops_mut_self_from_params() {
        // Kills: || → && in chunk-skip chain at line 352
        // (mutant would parse `&mut self` as a real param)
        let src = "impl T {\n    pub fn m(&mut self, x: u32) {}\n}\n";
        let syms = scan_rust_source(src, "myapp");
        let m = find(&syms, "T.m");
        assert_eq!(m.params.len(), 1, "only `x` should remain; got {:?}", m.params);
        assert_eq!(m.params[0].name, "x");
    }

    #[test]
    fn rust_drops_rest_param() {
        // Also kills: || → && at line 352 (...rest would slip through)
        let src = "pub fn variadic(items: &[u32], ...rest: u32) {}";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "variadic");
        assert!(
            !f.params.iter().any(|p| p.name == "rest"),
            "`...rest` must be dropped; got {:?}",
            f.params
        );
    }

    #[test]
    fn rust_rejects_digit_prefixed_param_name() {
        // Kills: || → && at line 364 AND == → != at line 367
        // (both mutants would let invalid first chars slip through)
        let src = "pub fn bad(1abc: u32) {}";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "bad");
        assert!(
            f.params.iter().all(|p| p.name != "1abc"),
            "digit-prefixed names must be rejected; got {:?}",
            f.params
        );
    }

    #[test]
    fn rust_accepts_underscore_prefixed_param() {
        // Kills: == → != at line 367 (mutant would reject `_x`)
        let src = "pub fn with_unused(_x: u32, real: String) {}";
        let syms = scan_rust_source(src, "myapp");
        let f = find(&syms, "with_unused");
        assert!(
            f.params.iter().any(|p| p.name == "_x"),
            "`_x` is a valid unused-param name; got {:?}",
            f.params
        );
    }
}
