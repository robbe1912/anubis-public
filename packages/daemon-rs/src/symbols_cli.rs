//! symbols_cli — input parsing + orchestration for `anubis symbols` subcommand.
//!
//! Supports:
//!   - Godot (`godot` or `godot@<ver>`)
//!   - Rust crates (`rust:<crate>` or `rust:auto`)
//!   - TypeScript packages (`ts:<pkg>` or `ts:<pkg>@<ver>`)

use std::path::{Path, PathBuf};

use crate::symbols::cache::SymbolCache;
use crate::symbols::godot_fetcher;
use crate::symbols::godot_parser;
use crate::symbols::rust_fetcher;
use crate::symbols::rust_parser;
use crate::symbols::ts_fetcher;
use crate::symbols::ts_parser;

/// Parsed `symbols add` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolsAddInput {
    pub library: String,
    pub version: Option<String>,
}

/// Parse `anubis symbols add <input>` into library + version.
///
/// Examples:
///   `godot`            → SymbolsAddInput { library: "godot", version: None }
///   `godot@master`     → SymbolsAddInput { library: "godot", version: Some("master") }
///   `godot@4.3-stable` → SymbolsAddInput { library: "godot", version: Some("4.3-stable") }
pub fn parse_input(input: &str) -> Result<SymbolsAddInput, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty input".to_string());
    }

    // Scoped npm packages: @org/pkg or @org/pkg@version
    // The leading @ is part of the package name, not a version separator.
    if trimmed.starts_with('@') && trimmed.contains('/') {
        let (library, version) = match trimmed[1..].split_once('@') {
            Some((lib_rest, ver)) => {
                if ver.is_empty() {
                    return Err(format!("missing version after @ in: {}", input));
                }
                (format!("@{}", lib_rest), Some(ver.to_string()))
            }
            None => (trimmed.to_string(), None),
        };
        return Ok(SymbolsAddInput { library, version });
    }

    // Non-scoped: split on first @ as version separator
    let (library, version) = match trimmed.split_once('@') {
        Some((lib, ver)) => {
            if lib.is_empty() {
                return Err(format!("missing library name before @ in: {}", input));
            }
            if ver.is_empty() {
                return Err(format!("missing version after @ in: {}", input));
            }
            (lib.to_string(), Some(ver.to_string()))
        }
        None => (trimmed.to_string(), None),
    };

    Ok(SymbolsAddInput { library, version })
}

/// Run `anubis symbols add <input>` end-to-end.
///
/// Dispatch by input prefix:
///   `auto`                       → scan cwd, suggest matching libraries
///   `godot` or `godot@<ver>`     → Godot XML pipeline
///   `rust:<crate>` or `rust:<crate>@<ver>` → docs.rs JSON pipeline
///   `rust:auto`                  → read Cargo.toml, fetch all deps
///   `ts:<pkg>` or `ts:<pkg>@<ver>` → unpkg `.d.ts` pipeline
///   `ts:auto`                    → read package.json, fetch all deps
///   Other                         → error
pub async fn run_add(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty input".to_string());
    }

    // Top-level auto-detect: scans cwd for project markers (project.godot,
    // Cargo.toml, package.json) and suggests matching libraries.
    if trimmed == "auto" {
        return run_add_auto().await;
    }

    // Rust dispatch: rust:crate or rust:crate@version
    if let Some(rest) = trimmed.strip_prefix("rust:") {
        return run_add_rust(rest).await;
    }

    // TypeScript dispatch: ts:package or ts:package@version
    if let Some(rest) = trimmed.strip_prefix("ts:") {
        return run_add_ts(rest).await;
    }

    // Default parse for godot/etc
    let parsed = parse_input(trimmed)?;
    match parsed.library.as_str() {
        "godot" => run_add_godot(parsed.version.as_deref()).await,
        other => Err(format!(
            "unsupported library: '{}' — supported: 'godot', 'rust:<crate>', 'ts:<package>', 'auto'",
            other
        )),
    }
}

/// Auto-detect project type from cwd and fetch all relevant symbol bundles.
///
/// Walks the current directory (and parents up to home) looking for project
/// markers:
///   - `project.godot`           → Godot project → fetch Godot symbols
///   - `Cargo.toml`              → Rust project  → fetch all [dependencies]
///   - `package.json`            → JS/TS project → fetch all "dependencies"
///   - `*.csproj` / `*.sln`      → C# project    → (info only, not auto-fetched)
///
/// When multiple markers are present, processes all of them in sequence.
/// This is the recommended entry point for new users — runs the right
/// fetcher automatically based on what's in the project.
pub async fn run_add_auto() -> Result<String, String> {
    let cwd = std::env::current_dir()
        .map_err(|e| format!("getcwd: {e}"))?;
    run_add_auto_at(&cwd).await
}

/// Same as [`run_add_auto`] but takes an explicit start directory.
///
/// Used by the daemon's cache-warming task, which cannot rely on
/// `std::env::current_dir()` (the daemon's cwd is unrelated to the user's
/// project). The daemon infers the project root from intercepted tool-call
/// file paths and passes it here.
pub async fn run_add_auto_at(start_dir: &Path) -> Result<String, String> {
    let detections = detect_project_types(&start_dir.to_path_buf());

    if detections.is_empty() {
        return Err(format!(
            "no project markers found in {} — supported: project.godot, Cargo.toml, package.json\n\
             usage: anubis symbols add <library>[@version]\n\
             examples: anubis symbols add godot\n\
                       anubis symbols add rust:serde\n\
                       anubis symbols add ts:react",
            start_dir.display()
        ));
    }

    let mut summaries: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for detection in &detections {
        match detection.kind.as_str() {
            "godot" => {
                match run_add_godot(Some(&detection.version)).await {
                    Ok(s) => summaries.push(s),
                    Err(e) => errors.push(format!("godot: {e}")),
                }
            }
            "rust" => {
                match run_add_rust_auto_at(&detection.path).await {
                    Ok(s) => summaries.push(s),
                    Err(e) => errors.push(format!("rust: {e}")),
                }
            }
            "ts" => {
                match run_add_ts_auto_at(&detection.path).await {
                    Ok(s) => summaries.push(s),
                    Err(e) => errors.push(format!("ts: {e}")),
                }
            }
            "csharp" => {
                summaries.push(format!(
                    "csharp: detected {} — use `anubis symbols sync <project_dir>` to index local symbols (NuGet fetching not yet supported)",
                    detection.path.display()
                ));
            }
            _ => {}
        }
    }

    let mut out = String::new();
    if !summaries.is_empty() {
        out.push_str(&summaries.join("\n"));
    }
    if !errors.is_empty() {
        if !out.is_empty() { out.push_str("\n\n"); }
        out.push_str("Errors:\n  ");
        out.push_str(&errors.join("\n  "));
    }
    if out.is_empty() {
        return Err("auto-detect ran but produced no output".into());
    }
    Ok(out)
}

/// A detected project (language + marker path + version).
#[derive(Debug, Clone)]
pub struct ProjectDetection {
    pub kind: String,
    pub path: PathBuf,
    pub version: String,
}

/// Scan `dir` (and parent directories up to the user's home) for project markers.
///
/// Returns one detection per marker found, in priority order:
/// Godot > Rust > TypeScript > C#.
pub fn detect_project_types(start_dir: &PathBuf) -> Vec<ProjectDetection> {
    let mut out: Vec<ProjectDetection> = Vec::new();
    let home = crate::dirs_home();

    // Walk up from start_dir to home, looking for project markers.
    let mut current = start_dir.clone();
    loop {
        if let Some(d) = detect_at_dir(&current) {
            // Avoid duplicates when nested projects (e.g. monorepo).
            if !out.iter().any(|x| x.kind == d.kind) {
                out.push(d);
            }
        }
        // Stop at home or filesystem root.
        if current == home || !current.pop() {
            break;
        }
    }

    // Sort by priority for stable output.
    let priority = |k: &str| -> u8 {
        match k { "godot" => 0, "rust" => 1, "ts" => 2, "csharp" => 3, _ => 9 }
    };
    out.sort_by_key(|d| priority(&d.kind));
    out
}

/// Detect a single project type at the given directory (non-recursive).
fn detect_at_dir(dir: &PathBuf) -> Option<ProjectDetection> {
    // Godot
    let godot_marker = dir.join("project.godot");
    if godot_marker.is_file() {
        let version = read_godot_version(&godot_marker).unwrap_or_else(|| "master".to_string());
        return Some(ProjectDetection {
            kind: "godot".to_string(),
            path: godot_marker,
            version,
        });
    }
    // Rust
    let cargo_marker = dir.join("Cargo.toml");
    if cargo_marker.is_file() {
        return Some(ProjectDetection {
            kind: "rust".to_string(),
            path: cargo_marker,
            version: "auto".to_string(),
        });
    }
    // TS / JS
    let pkg_marker = dir.join("package.json");
    if pkg_marker.is_file() {
        return Some(ProjectDetection {
            kind: "ts".to_string(),
            path: pkg_marker,
            version: "auto".to_string(),
        });
    }
    // C#
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".csproj") || name.ends_with(".sln") {
                return Some(ProjectDetection {
                    kind: "csharp".to_string(),
                    path: entry.path(),
                    version: "auto".to_string(),
                });
            }
        }
    }
    None
}

/// Read Godot version from `project.godot`. Returns the `config_version` or
/// a best-guess engine version (4.x) — falls back to "master".
fn read_godot_version(path: &PathBuf) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    // project.godot has `config_version=5` (Godot 4.x) or =4 (Godot 3.x).
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("config_version=") {
            let v = rest.trim();
            if v == "5" { return Some("4.7".to_string()); } // Godot 4 family
            if v == "4" { return Some("3.6".to_string()); } // Godot 3 family
            return Some(v.to_string());
        }
    }
    None
}

/// Like `run_add_rust_auto` but reads Cargo.toml from a specific path.
async fn run_add_rust_auto_at(cargo_toml: &PathBuf) -> Result<String, String> {
    let parent = cargo_toml.parent().ok_or("invalid Cargo.toml path")?;
    run_add_rust_auto_in(parent).await
}

/// Like `run_add_ts_auto` (new) but reads package.json from a specific path.
async fn run_add_ts_auto_at(package_json: &PathBuf) -> Result<String, String> {
    let parent = package_json.parent().ok_or("invalid package.json path")?;
    run_add_ts_auto_in(parent).await
}

/// Read package.json from `dir`, extract dependencies, fetch each via ts:<pkg>.
async fn run_add_ts_auto_in(dir: &std::path::Path) -> Result<String, String> {
    let pkg_path = dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_path)
        .map_err(|e| format!("read {}: {}", pkg_path.display(), e))?;
    let v: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("parse package.json: {e}"))?;

    let mut pkg_names: Vec<String> = Vec::new();
    for field in &["dependencies", "peerDependencies", "devDependencies"] {
        if let Some(map) = v.get(field).and_then(|x| x.as_object()) {
            for name in map.keys() {
                // Skip @types/* (type-only packages already covered by their parent).
                if name.starts_with("@types/") { continue; }
                pkg_names.push(name.clone());
            }
        }
    }
    pkg_names.sort();
    pkg_names.dedup();

    if pkg_names.is_empty() {
        return Err(format!("no dependencies found in {}", pkg_path.display()));
    }

    let mut summaries: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let total = pkg_names.len();
    let mut ok = 0usize;
    for name in &pkg_names {
        match fetch_and_cache_single_ts(name, None).await {
            Ok(s) => { summaries.push(s); ok += 1; }
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }

    let mut out = format!(
        "ts:auto: {ok}/{total} packages from {} fetched successfully",
        pkg_path.display()
    );
    if !errors.is_empty() {
        out.push_str(&format!("\nErrors ({}):\n  {}", errors.len(), errors.join("\n  ")));
    }
    Ok(out)
}

/// Stub: calls run_add_ts for a single package (kept as a separate function
/// so the auto path can batch them).
async fn fetch_and_cache_single_ts(name: &str, version: Option<&str>) -> Result<String, String> {
    let input = match version {
        Some(v) => format!("{name}@{v}"),
        None => name.to_string(),
    };
    run_add_ts(&input).await
}

/// Rust pipeline: fetch rustdoc JSON → parse → cache insert.
/// Input: `<crate>` or `<crate>@<version>` or `auto` (reads Cargo.toml)
async fn run_add_rust(input: &str) -> Result<String, String> {
    // Special case: "auto" reads Cargo.toml and fetches all [dependencies]
    if input.trim() == "auto" {
        return run_add_rust_auto().await;
    }

    let parsed = parse_input(input)?;
    let (_, summary) = fetch_and_cache_single_crate(&parsed.library, parsed.version.as_deref())
        .await?;
    Ok(summary)
}

/// Read Cargo.toml from cwd, extract [dependencies], fetch each crate.
/// Handles both simple (`serde = "1"`) and table (`serde = { version = "1", ... }`) forms.
/// Skips workspace deps (path-only), build-deps, dev-deps (Phase 1 scope).
async fn run_add_rust_auto() -> Result<String, String> {
    let cwd = std::env::current_dir()
        .map_err(|e| format!("getcwd: {e}"))?;
    run_add_rust_auto_in(&cwd).await
}

/// Worker for [`run_add_rust_auto`] that takes an explicit directory.
async fn run_add_rust_auto_in(dir: &std::path::Path) -> Result<String, String> {
    let cargo_toml_path = dir.join("Cargo.toml");
    let cargo_toml = std::fs::read_to_string(&cargo_toml_path)
        .map_err(|e| format!("read {} in {}: {} — run from project root",
            cargo_toml_path.display(), dir.display(), e))?;

    let mut crate_names = Vec::new();
    let mut in_section = false;

    for line in cargo_toml.lines() {
        let trimmed = line.trim();

        // Track section headers
        if trimmed.starts_with('[') {
            in_section = trimmed == "[dependencies]";
            continue;
        }

        if !in_section || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Extract crate name before `=`
        if let Some(eq) = trimmed.find('=') {
            let name = trimmed[..eq].trim();
            // Skip path-only deps (local crates, not on docs.rs)
            let rest = trimmed[eq + 1..].trim();
            if rest.contains("path =") {
                continue;
            }
            // Handle renamed deps: `oldname = { package = "realname" }`
            if rest.contains("package =") {
                if let Some(start) = rest.find("package = \"") {
                    let after = &rest[start + 11..];
                    if let Some(end) = after.find('"') {
                        crate_names.push(after[..end].to_string());
                        continue;
                    }
                }
            }
            if !name.is_empty() {
                crate_names.push(name.to_string());
            }
        }
    }

    if crate_names.is_empty() {
        return Err("no [dependencies] found in Cargo.toml".to_string());
    }

    // Deduplicate
    crate_names.sort();
    crate_names.dedup();

    let total_crates = crate_names.len();
    let mut succeeded = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut total_symbols = 0usize;

    for name in &crate_names {
        // Use the single-crate helper directly (not run_add_rust — avoids async recursion)
        match fetch_and_cache_single_crate(name, None).await {
            Ok((symbol_count, _summary)) => {
                succeeded += 1;
                total_symbols += symbol_count;
            }
            Err(e) => {
                failed.push(format!("{}: {}", name, e));
            }
        }
    }

    let mut result = format!(
        "rust:auto: {}/{} crates cached ({} total symbols)",
        succeeded, total_crates, total_symbols
    );
    if !failed.is_empty() {
        result.push_str(&format!("\n  failed ({}):", failed.len()));
        for f in &failed {
            result.push_str(&format!("\n    {}", f));
        }
    }
    Ok(result)
}

/// Fetch + parse + cache a single Rust crate. Returns (symbol_count, summary_text).
/// Used by both run_add_rust and run_add_rust_auto to avoid async recursion.
pub async fn fetch_and_cache_single_crate(
    crate_name: &str,
    version: Option<&str>,
) -> Result<(usize, String), String> {
    let fetch_result = rust_fetcher::fetch_rustdoc_json(crate_name, version)
        .await
        .map_err(|e| format!("docs.rs fetch failed: {}", e))?;

    let json = std::fs::read_to_string(&fetch_result.raw_path)
        .map_err(|e| format!("read {}: {}", fetch_result.raw_path.display(), e))?;

    let symbols = rust_parser::parse_rustdoc_json(&json, crate_name, &fetch_result.version)
        .map_err(|e| format!("rustdoc parse failed: {}", e))?;

    let total = symbols.len();
    if total == 0 {
        return Err(format!(
            "fetched rustdoc JSON for {}@{} but parsed 0 symbols",
            crate_name, fetch_result.version
        ));
    }

    let cache = SymbolCache::open().map_err(|e| format!("open cache: {}", e))?;
    cache
        .insert_many(&symbols)
        .map_err(|e| format!("cache insert: {}", e))?;

    let status = if fetch_result.skipped_fresh {
        "skipped fresh"
    } else {
        "downloaded"
    };
    let summary = format!(
        "{}@{}: {} symbols cached ({} — {} bytes)",
        crate_name, fetch_result.version, total, status, fetch_result.bytes_downloaded
    );
    Ok((total, summary))
}

/// TypeScript pipeline: fetch `.d.ts` from unpkg → parse → cache insert.
/// Input: `<pkg>` or `<pkg>@<version>` or `auto` (reads package.json deps).
async fn run_add_ts(input: &str) -> Result<String, String> {
    let parsed = parse_input(input)?;
    let (_, summary) =
        fetch_and_cache_single_package(&parsed.library, parsed.version.as_deref()).await?;
    Ok(summary)
}

/// Fetch + parse + cache a single npm TypeScript package. Returns
/// (symbol_count, summary_text). Mirrors `fetch_and_cache_single_crate`.
///
/// Used by `run_add_ts` and by `auto_fetch_missing` as a fallback when a
/// term is not a Rust crate.
pub async fn fetch_and_cache_single_package(
    package: &str,
    version: Option<&str>,
) -> Result<(usize, String), String> {
    let (fetch_result, combined) = ts_fetcher::fetch_and_concat(package, version)
        .await
        .map_err(|e| format!("unpkg fetch failed: {}", e))?;

    let symbols = ts_parser::parse_dts(&combined, package, &fetch_result.version)
        .map_err(|e| format!(".d.ts parse failed: {}", e))?;

    let total = symbols.len();
    if total == 0 {
        return Err(format!(
            "fetched .d.ts for {}@{} but parsed 0 symbols",
            package, fetch_result.version
        ));
    }

    let cache = SymbolCache::open().map_err(|e| format!("open cache: {}", e))?;
    cache
        .insert_many(&symbols)
        .map_err(|e| format!("cache insert: {}", e))?;

    let status = if fetch_result.skipped_fresh {
        "skipped fresh"
    } else {
        "downloaded"
    };
    let summary = format!(
        "{}@{}: {} symbols cached ({} — {} bytes from {} files)",
        package,
        fetch_result.version,
        total,
        status,
        fetch_result.bytes_downloaded,
        fetch_result.raw_files.len()
    );
    Ok((total, summary))
}

/// Godot-specific pipeline: fetch XML → parse → cache insert.
async fn run_add_godot(version: Option<&str>) -> Result<String, String> {
    // Step 1: fetch XML files (~1500 for Godot master)
    let fetch_result = godot_fetcher::fetch_godot_classes(version).await?;

    if fetch_result.files_downloaded == 0 && fetch_result.files_skipped_fresh == 0 {
        return Err(format!(
            "no XML files downloaded for godot@{} (failed={}) — check network or GITHUB_TOKEN",
            fetch_result.version, fetch_result.files_failed
        ));
    }

    // Step 2: parse all XMLs in the raw dir and insert into cache
    let cache = SymbolCache::open().map_err(|e| format!("open cache: {}", e))?;
    let symbols = collect_godot_symbols(&fetch_result.raw_dir, &fetch_result.version)?;

    let total = symbols.len();
    if total == 0 {
        return Err(format!(
            "fetched {} files but parsed 0 symbols — XML format issue?",
            fetch_result.files_downloaded + fetch_result.files_skipped_fresh
        ));
    }

    cache
        .insert_many(&symbols)
        .map_err(|e| format!("cache insert: {}", e))?;

    Ok(format!(
        "godot@{}: {} symbols cached (from {} files, {} skipped fresh, {} failed)",
        fetch_result.version,
        total,
        fetch_result.files_downloaded,
        fetch_result.files_skipped_fresh,
        fetch_result.files_failed
    ))
}

/// Walk a raw/ directory, parse each .xml file, collect all symbols.
fn collect_godot_symbols(
    raw_dir: &PathBuf,
    version: &str,
) -> Result<Vec<crate::symbols::types::Symbol>, String> {
    let mut all = Vec::new();
    let mut files_parsed = 0usize;
    let mut parse_errors = 0usize;

    let entries =
        std::fs::read_dir(raw_dir).map_err(|e| format!("read dir {}: {}", raw_dir.display(), e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("xml") {
            continue;
        }

        let xml = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("skip {}: {}", path.display(), e);
                parse_errors += 1;
                continue;
            }
        };

        match godot_parser::parse_xml(&xml, version) {
            Ok(syms) => {
                files_parsed += 1;
                all.extend(syms);
            }
            Err(e) => {
                tracing::warn!("parse {}: {}", path.display(), e);
                parse_errors += 1;
            }
        }
    }

    tracing::info!(
        "parsed {} files ({} errors), collected {} symbols",
        files_parsed,
        parse_errors,
        all.len()
    );

    Ok(all)
}

/// Run `anubis symbols sync [path]`.
///
/// Walks the project at `path` (default: cwd), parses each source file by
/// extension, and inserts the parsed symbols into the local SQLite cache with
/// `library=<project_name>` and `version="local"`. Re-runnable: clears any
/// previous local symbols for the project before re-inserting.
///
/// Supported: .ts/.tsx/.mts/.cts (via ts_parser), .rs (via local_scanner).
/// Skipped (logged in summary): .gd, .py, .go — TODO.
pub async fn run_sync(path: Option<&str>) -> Result<String, String> {
    use crate::symbols::local_scanner;
use std::path::{Path, PathBuf};

    let root: PathBuf = match path {
        Some(p) if !p.trim().is_empty() => PathBuf::from(p.trim()),
        _ => std::env::current_dir()
            .map_err(|e| format!("cwd unavailable: {}", e))?,
    };

    if !root.is_dir() {
        return Err(format!("not a directory: {}", root.display()));
    }

    let project_name = local_scanner::detect_project_name(&root);
    tracing::info!("sync: scanning {} as project '{}'", root.display(), project_name);

    let outcome = local_scanner::scan_project(&root, &project_name);

    // Open cache, clear previous local symbols for this project, insert fresh.
    let cache = crate::symbols::cache::SymbolCache::open()?;
    let removed = cache.remove_library(&project_name, "local")?;
    let inserted = cache.insert_many(&outcome.symbols)?;

    tracing::info!(
        "sync: removed {} stale, inserted {} of {} parsed",
        removed,
        inserted,
        outcome.symbols.len()
    );

    Ok(format!(
        "{} (cleared {} stale, inserted {})",
        outcome.summary(),
        removed,
        inserted
    ))
}

/// Run `anubis symbols fetch` — unified command combining `add auto` + `sync`.
///
/// Detects project type, fetches all dependency symbols (Rust crates via docs.rs,
/// TS packages via jsDelivr, Godot classes via GitHub XML), then scans the
/// project source for locally-defined symbols. Returns a summary of what was
/// fetched + cached.
pub async fn run_fetch() -> Result<String, String> {
    let mut parts: Vec<String> = Vec::new();

    match run_add_auto().await {
        Ok(summary) => parts.push(summary),
        Err(e) => parts.push(format!("dependency fetch: {}", e)),
    }

    match run_sync(None).await {
        Ok(summary) => parts.push(summary),
        Err(e) => parts.push(format!("source scan: {}", e)),
    }

    let total = crate::symbols::cache::SymbolCache::open()
        .ok()
        .and_then(|c| c.count().ok())
        .unwrap_or(0);

    parts.push(format!("Total: {} symbols cached.", total));

    Ok(parts.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_input_plain_godot() {
        let r = parse_input("godot").unwrap();
        assert_eq!(r.library, "godot");
        assert_eq!(r.version, None);
    }

    #[test]
    fn parse_input_godot_with_version() {
        let r = parse_input("godot@master").unwrap();
        assert_eq!(r.library, "godot");
        assert_eq!(r.version.as_deref(), Some("master"));
    }

    #[test]
    fn parse_input_godot_stable_tag() {
        let r = parse_input("godot@4.3-stable").unwrap();
        assert_eq!(r.library, "godot");
        assert_eq!(r.version.as_deref(), Some("4.3-stable"));
    }

    #[test]
    fn parse_input_empty_errors() {
        assert!(parse_input("").is_err());
    }

    #[test]
    fn parse_input_only_at_errors() {
        assert!(parse_input("@master").is_err());
        assert!(parse_input("godot@").is_err());
    }

    #[test]
    fn parse_input_scoped_npm_no_version() {
        let r = parse_input("@trpc/server").unwrap();
        assert_eq!(r.library, "@trpc/server");
        assert_eq!(r.version, None);
    }

    #[test]
    fn parse_input_scoped_npm_with_version() {
        let r = parse_input("@trpc/server@10.45.2").unwrap();
        assert_eq!(r.library, "@trpc/server");
        assert_eq!(r.version.as_deref(), Some("10.45.2"));
    }

    #[test]
    fn parse_input_trims_whitespace() {
        let r = parse_input("  godot@master  ").unwrap();
        assert_eq!(r.library, "godot");
        assert_eq!(r.version.as_deref(), Some("master"));
    }

    #[test]
    fn parse_input_rejects_unsupported_lib_in_run_add() {
        // parse_input itself accepts any library name — the gate is in run_add
        let parsed = parse_input("typescript").unwrap();
        assert_eq!(parsed.library, "typescript");
    }

    #[tokio::test]
    async fn run_add_rejects_unknown_library() {
        let r = run_add("typescript@5.0.0").await;
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("unsupported library"));
    }

    #[tokio::test]
    async fn run_add_rejects_empty() {
        let r = run_add("").await;
        assert!(r.is_err());
    }
}
