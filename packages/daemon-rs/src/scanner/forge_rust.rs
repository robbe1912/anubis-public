//! Rust FORGE runner — extracted from forge_pipeline.rs (M1 chunk 8).
//!
//! Verifies Rust source for:
//!   1. Crate imports — crates.io registry lookup
//!   2. Grouped import symbols — `use crate::{A, B, C}` against cached API
//!   3. Undefined variables — tree-sitter AST (`rust_ast_extractor`)
//!   4. Method calls — docs.rs type introspection (receiver + static)
//!   5. Cross-file definitions — supplements AST with project index
//!
//! Regex-based scope checker (`extract_rust_undefined_variables`) kept as
//! historical reference; the production path uses the tree-sitter AST
//! extractor in `rust_ast_extractor.rs`.

use crate::scanner::forge_types::ForgeResult;
use crate::scanner::package_index::ImportStatus;
use crate::scanner::string_filters::{filter_function_calls, strip_c_style_string_literals};

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

// Static regex patterns for extract_project_rust_functions
static FN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bfn\s+([a-z_][a-zA-Z0-9_]*)").unwrap());
static CONST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:const|static)\s+([A-Z_][A-Z0-9_]*)").unwrap());

// Static regex patterns for run_forge_rust
static RUST_USE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\buse\s+([a-z_][a-z0-9_-]*)::").unwrap());
static EXTERN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bextern\s+crate\s+([a-z_][a-z0-9_-]*)").unwrap());
// Finds the opening brace of a use group: `use <path>::{`. The body is
// extracted separately via `find_matching_close` because regex `[^}]+`
// cannot handle nested brace groups like `use axum::{extract::{Path, State}}`.
static USE_BRACE_OPEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"use\s+([\w:]+)\s*::\s*\{").unwrap());

/// Find the byte index of the `}` matching the `{` at `open_idx`.
/// Returns None if braces are unbalanced.
fn find_matching_close(content: &str, open_idx: usize) -> Option<usize> {
    let bytes = content.as_bytes();
    if open_idx >= bytes.len() || bytes[open_idx] != b'{' {
        return None;
    }
    let mut depth: i32 = 1;
    let mut i = open_idx + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split text on top-level commas, respecting nested `{...}` groups.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth: i32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            b',' if depth == 0 => {
                let part = s[start..i].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < bytes.len() {
        let last = s[start..].trim();
        if !last.is_empty() {
            parts.push(last);
        }
    }
    parts
}

/// Extract leaf symbol names from a use-group body (text inside the
/// outermost `{...}`). Handles nested brace groups like
/// `extract::{Path, State}` — recurses into them and returns only
/// terminal symbol names, not module path components.
fn extract_use_leaves(body: &str) -> Vec<String> {
    let mut leaves = Vec::new();
    for item in split_top_level_commas(body) {
        // Strip optional `as Alias` suffix before any further analysis.
        let item = item.split(" as ").next().unwrap_or(item).trim();
        if item.is_empty() || item == "self" || item == "_" {
            continue;
        }
        // Nested group: `prefix::{a, b}` — recurse on the inner body.
        if let Some(brace_idx) = item.find('{') {
            if let Some(close_idx) = item.rfind('}') {
                let inner = &item[brace_idx + 1..close_idx];
                leaves.extend(extract_use_leaves(inner));
            }
            continue;
        }
        // Leaf name: take the last `::` segment.
        let name = item.split("::").last().unwrap_or(item).trim();
        if !name.is_empty() && name != "self" && name != "_" {
            leaves.push(name.to_string());
        }
    }
    leaves
}

/// Iterate over all `use <crate_path>::{...}` groups in `content`,
/// yielding `(crate_path, body)` for each, where `body` is the text
/// between the outermost matched braces (with nested groups intact).
fn iter_use_groups(content: &str) -> Vec<(&str, &str)> {
    let mut groups = Vec::new();
    for caps in USE_BRACE_OPEN_RE.captures_iter(content) {
        let crate_path = caps.get(1).unwrap().as_str();
        let m = caps.get(0).unwrap();
        // `m.end()` is one past the last matched char (`{`), so the brace
        // itself sits at `m.end() - 1`.
        let open_idx = m.end() - 1;
        match find_matching_close(content, open_idx) {
            Some(close_idx) => {
                let body = &content[open_idx + 1..close_idx];
                groups.push((crate_path, body));
            }
            None => continue, // Unbalanced — skip rather than misparse.
        }
    }
    groups
}

/// Extract function and constant names from the project index string.
/// Used to supplement the tree-sitter scope checker with cross-file definitions.
fn extract_project_rust_functions(project_index: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    // Match: fn name, const NAME, static NAME
    let fn_re = &*FN_RE;
    let const_re = &*CONST_RE;
    for re in [fn_re, const_re] {
        for cap in re.captures_iter(project_index) {
            if let Some(m) = cap.get(1) {
                names.insert(m.as_str().to_string());
            }
        }
    }
    names
}

/// Rust FORGE pipeline (partial implementation).
/// Verifies crate imports against crates.io registry + undefined variable detection.
pub(crate) async fn run_forge_rust(content: &str, project_index: &str) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();

    // Extract user-defined Rust types from project files so the method
    // verifier skips them (they're defined in the same codebase).
    let project_types =
        crate::scanner::rust_introspect::extract_project_rust_types(project_index);

    // ALSO extract types defined in the CURRENT response content. Without
    // this, types like TodoStore/Storage defined in the agent's current
    // response but not yet on disk would fail method verification against
    // docs.rs, producing false positives (store.add → "add not a method
    // on TodoStore"). Merging current + project types gives the verifier
    // the full picture.
    let mut all_types = project_types.clone();
    all_types.extend(crate::scanner::rust_ast_extractor::extract_type_names(content));

    // Extract brace import names: use std::fmt::{self, Formatter, Display}
    // AND single-path imports: use std::fmt::Formatter; use tokio::spawn;
    // These are imported types that should be in all_types to prevent FPs.
    // Handles nested brace groups like `use axum::{extract::{Path, State}, Json}`.
    for (_crate_path, body) in iter_use_groups(content) {
        for name in extract_use_leaves(body) {
            all_types.insert(name);
        }
    }
    // Single-path imports: use std::fmt::Formatter; — extract last segment.
    let single_re = regex::Regex::new(r"use\s+([\w:]+)\s*;").unwrap();
    for caps in single_re.captures_iter(content) {
        if let Some(path) = caps.get(1) {
            if let Some(last) = path.as_str().split("::").last() {
                if !last.is_empty() && last != "self" {
                    all_types.insert(last.to_string());
                }
            }
        }
    }

    // Extract import terms using RUST-SPECIFIC patterns only.
    // The generic extract_lookup_terms runs all language patterns including
    // JS/Python import patterns that match prose like "from 'needed'" —
    // producing false hallucinated-import warnings. Rust imports only come
    // from `use crate::` and `extern crate` statements.
    let rust_use_re = &*RUST_USE_RE;
    let extern_re = &*EXTERN_RE;
    let mut terms = HashSet::new();
    for caps in rust_use_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            terms.insert(m.as_str().to_lowercase());
        }
    }
    for caps in extern_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            terms.insert(m.as_str().to_lowercase());
        }
    }
    result.claims_extracted = terms.len();
    for pkg in &terms {
        if pkg.starts_with('.') || pkg.starts_with('/') {
            continue;
        }
        let crate_name = pkg.split("::").next().unwrap_or(pkg);
        // std/core/alloc are the Rust standard library — always available in
        // every crate without a crates.io entry. crate/self/super are Rust
        // module path keywords for internal references, not external crates.
        // Flagging any of these as "hallucinated-import" is a false positive.
        if matches!(crate_name, "std" | "core" | "alloc" | "crate" | "self" | "super") {
            result.claims_verified += 1;
            continue;
        }
        let status = crate::scanner::package_index::verify_import_with_language("rust", crate_name).await;
        match status {
            ImportStatus::NotFound => {
                let mut msg = format!(
                    "hallucinated-import: `{}` — crate not found in crates.io",
                    crate_name
                );
                if let Some(suggestion) = crate::scanner::package_index::suggest_correct_import(crate_name) {
                    msg.push_str(&format!(" — did you mean `{}`?", suggestion));
                }
                result.warnings.push(msg);
                result.claims_hallucinated += 1;
            }
            ImportStatus::Verified => result.claims_verified += 1,
            _ => result.claims_unknown += 1,
        }
    }

    // Grouped import symbol verification: use crate::{A, B, C}
    // For each leaf symbol, check if it exists in the cached crate's API
    // surface. Only flags when crate IS cached but symbol is NOT — safe
    // (no FP when crate isn't cached, since we can't verify).
    // Handles nested brace groups via `iter_use_groups` + `extract_use_leaves`.
    if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
        let cached_libs = cache.list_libraries();
        for (crate_path, body) in iter_use_groups(content) {
            let crate_name = crate_path.split("::").next().unwrap_or(crate_path);
            // Skip std/core/alloc and `crate` (Rust self-referential module)
            if matches!(crate_name, "std" | "core" | "alloc" | "crate" | "self" | "super") {
                continue;
            }
            // Find cached library names matching this crate
            let matching_libs: Vec<&str> = cached_libs
                .iter()
                .map(|(l, _, _)| l.as_str())
                .filter(|l| l.contains(crate_name))
                .collect();
            if matching_libs.is_empty() {
                continue; // Crate not cached — can't verify symbols
            }
            for sym in extract_use_leaves(body) {
                let sym = sym.trim();
                if sym.is_empty() || sym == "_" || sym.len() < 2 {
                    continue;
                }
                // Skip common stdlib types that crates re-export but that
                // may not be individually cached (type aliases, re-exports).
                if matches!(sym, "Result" | "Option" | "Error" | "Vec"
                    | "String" | "Box" | "Arc" | "Rc" | "HashMap"
                    | "HashSet" | "BTreeMap" | "BTreeSet" | "Cow"
                    | "Pin" | "Cell" | "RefCell" | "Mutex" | "RwLock")
                {
                    continue;
                }
                // Check if symbol exists in any matching cached library.
                // But first: if the crate has very few cached METHOD entries
                // (< 5), the data is incomplete — can't confidently flag
                // missing symbols. Skip to avoid FPs on under-populated crates
                // like clap/sqlx where types exist but named exports aren't
                // individually cached.
                let crate_has_substantial_data = matching_libs.iter()
                    .any(|lib| cache.lookup_prefix(lib, "").iter()
                        .filter(|s| matches!(s.kind,
                            crate::symbols::types::SymbolKind::Method
                            | crate::symbols::types::SymbolKind::Function
                            | crate::symbols::types::SymbolKind::Constructor))
                        .count() >= 5);
                if !crate_has_substantial_data {
                    continue;
                }
                let found = matching_libs.iter().any(|lib| cache.lookup(lib, sym).is_some());
                if !found {
                    // Re-export suppression. Rust crates frequently re-export
                    // types from dependencies (axum re-exports http::StatusCode,
                    // hyper::Response, etc.). The cache indexes each crate's
                    // OWN API surface, so a missing leaf is more likely a
                    // re-export than a hallucination when EITHER:
                    //   (a) the leaf name exists in ANY other cached library
                    //       (real upstream package, not local.* project files)
                    //       — catches `StatusCode` (http), `Response` (hyper);
                    //   OR
                    //   (b) the matching crate has substantial type coverage
                    //       (>=20 cached Class/Enum/Interface entries) — when
                    //       we've indexed 20+ of the crate's own types, a
                    //       missing type leaf is almost certainly a re-export
                    //       from a dep we haven't indexed (axum::IntoResponse
                    //       is axum's own trait but the extractor missed it).
                    // Snake_case leaves (functions) stay strict either way —
                    // function names are crate-specific.
                    let is_type_like = sym
                        .chars()
                        .next()
                        .map_or(false, |c| c.is_ascii_uppercase());
                    let re_exported_elsewhere = is_type_like && {
                        let globals = cache.lookup_global(sym);
                        !globals.is_empty()
                            && globals
                                .iter()
                                .any(|s| !s.library.starts_with("local."))
                    };
                    if re_exported_elsewhere {
                        continue;
                    }
                    let crate_has_type_coverage = is_type_like
                        && matching_libs
                            .iter()
                            .map(|lib| {
                                cache.lookup_prefix(lib, "").iter().filter(|s| matches!(s.kind,
                                    crate::symbols::types::SymbolKind::Class
                                    | crate::symbols::types::SymbolKind::Enum
                                    | crate::symbols::types::SymbolKind::Interface)).count()
                            })
                            .sum::<usize>() >= 20;
                    if crate_has_type_coverage {
                        continue;
                    }
                    result.warnings.push(format!(
                        "hallucinated-import: `{}` not found in crate `{}`",
                        sym, crate_name
                    ));
                    result.claims_hallucinated += 1;
                    result.claims_extracted += 1;
                }
            }
        }
    }

    // Language contamination guard: if content contains more Python/JS
    // line-start keywords than Rust ones, it's prose about code (e.g.,
    // agent thinking about the VERDI paper with Python pseudocode), not
    // actual Rust source. Skip scope check to avoid prose-word FPs.
    let py_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("def ") || t.starts_with("import ") ||
        t.starts_with("from ") || t.starts_with("class ") ||
        t.starts_with("print(") || t.starts_with("self.")
    }).count();
    let rs_lines = content.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("fn ") || t.starts_with("let ") || t.starts_with("use ") ||
        t.starts_with("struct ") || t.starts_with("impl ") || t.starts_with("mod ") ||
        t.starts_with("enum ") || t.starts_with("pub ") || t.starts_with("const ")
    }).count();
    if py_lines > rs_lines {
        result.latency_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    // Prose-to-code ratio guard: even without Python keywords, content
    // can be pure English prose that tree-sitter parses as Rust (each
    // word becomes an identifier). Count English stop words vs Rust
    // keywords anywhere in content. If English dominates 3:1, skip.
    let lower = content.to_lowercase();
    let english_count = ["the ", " a ", " an ", " is ", " are ", " was ", " were ",
        " to ", " of ", " in ", " on ", " at ", " by ", " for ", " with ",
        " from ", " this ", " that ", " it ", " its ", " as ", " be ",
        " have ", " has ", " do ", " does ", " will ", " would ", " could ",
        " should ", " can ", " may ", " might "]
        .iter().map(|w| lower.matches(w).count()).sum::<usize>();
    let rust_kw_count = ["fn ", "let ", "use ", "struct ", "impl ", "mod ",
        "enum ", "pub ", "const ", "mut ", "match ", "trait ", "type ",
        "async ", "await ", "unsafe ", "->", "::", "&&", "||"]
        .iter().map(|w| content.matches(w).count()).sum::<usize>();
    if rust_kw_count == 0 || (english_count > rust_kw_count * 3 && rust_kw_count < 20) {
        result.latency_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    // Undefined variable detection via tree-sitter AST (FORGE 2026 pattern:
    // deterministic AST analysis for 100% precision). Tree-sitter naturally
    // filters prose — invalid Rust produces ERROR nodes → empty result.
    let mut undefined = crate::scanner::rust_ast_extractor::extract_undefined_variables(content);

    // Filter out project-defined functions/constants — these are defined in
    // other files in the same crate and are valid references. The tree-sitter
    // extractor only sees the current response content, so cross-file function
    // calls would be falsely flagged without this supplement.
    let project_fns = extract_project_rust_functions(project_index);

    // Also filter against session symbols (names defined in prior responses
    // of the same proxy session). These are in "session: NAME" format within
    // project_index — extract_project_rust_functions doesn't parse them.
    let session_defined: std::collections::HashSet<String> = project_index
        .lines()
        .filter_map(|l| l.strip_prefix("session: ").map(|s| s.trim().to_string()))
        .collect();
    // Filter against all_types too — type names (Bytes, Provider,
    // StreamingState, HeaderMap) used in annotations are valid references
    // to types defined in the project or imported crates. Without this,
    // every Rust type annotation triggers a hallucinated-variable FP.
    undefined.retain(|n| !project_fns.contains(n) && !session_defined.contains(n) && !all_types.contains(n));
    // Filter out field accesses: row.created_at, user.name, config.timeout.
    // Identifiers accessed via `.` are NOT bare variable references —
    // they're struct/enum field accesses resolved at compile time.
    let field_access_re = regex::Regex::new(r"\.\s*(\w+)").unwrap();
    let field_names: std::collections::HashSet<String> = field_access_re
        .captures_iter(content)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect();
    undefined.retain(|n| !field_names.contains(n));
    for name in &undefined {
        if name.len() >= 3 {
            result.warnings.push(format!(
                "hallucinated-variable: `{}` — referenced but not defined in scope",
                name
            ));
            result.claims_hallucinated += 1;
        }
    }
    result.claims_extracted += undefined.len();

    // Deterministic semantic checks (no network, no cache — pure pattern).
    // These catch classes of LLM hallucinations that AST scope analysis misses:
    //   - SQLite/PostgreSQL placeholder dialect confusion ($N vs ?)
    //   - Missing Debug derive (struct used with {:?} but no #[derive(Debug)])
    let sqlite_warnings = detect_sqlite_placeholder_mismatch(content);
    if !sqlite_warnings.is_empty() {
        result.claims_extracted += sqlite_warnings.len();
        result.claims_hallucinated += sqlite_warnings.len();
        result.warnings.extend(sqlite_warnings);
    }
    let debug_warnings = detect_missing_debug_derive(content);
    if !debug_warnings.is_empty() {
        result.claims_extracted += debug_warnings.len();
        result.claims_hallucinated += debug_warnings.len();
        result.warnings.extend(debug_warnings);
    }

    // Method verification via docs.rs type introspection.
    // NOTE: verify_rust_methods now handles empty receiver_map via the
    // Tier 2.1 bare-type-receiver fallback (`use`-proof + HTTP escalation).
    let receiver_map = crate::scanner::rust_introspect::build_rust_receiver_map(content);
    let method_warnings = crate::scanner::rust_introspect::verify_rust_methods(content, &receiver_map, &all_types).await;
    // Keep ALL method warnings including "uncertain" ones.
    // History: f02653b introduced blanket suppression of uncertain warnings
    // to fix the 94% E2E FP rate. Since then, other FP guards (language
    // contamination, prose ratio, cold-start, method-only cache guards)
    // have eliminated the root causes. The blanket suppression now only
    // suppresses REAL catches (e.g., Abortable::wrap in DELULU). Verified:
    // DELULU Rust 50%→62.5% recall, 0% FPR maintained, eval_corpus passes.
    let method_warnings: Vec<String> = method_warnings;
    result.claims_extracted += method_warnings.len();
    result.claims_hallucinated += method_warnings.iter().filter(|w| w.contains("hallucinated")).count();
    result.warnings.extend(method_warnings);

    // Static/associated method verification (Type::method() patterns).
    let static_warnings = crate::scanner::rust_introspect::verify_rust_static_methods(content, &all_types).await;
    // Keep all warnings including uncertain — see instance method comment above.
    let static_warnings: Vec<String> = static_warnings;
    if !static_warnings.is_empty() {
    result.claims_extracted += static_warnings.len();
    result.claims_hallucinated += static_warnings.iter().filter(|w| w.contains("hallucinated")).count();
    result.warnings.extend(static_warnings);
    }

    result.latency_ms = start.elapsed().as_millis() as u64;
    result
}

/// Measure the density of Rust-specific structural tokens per non-empty line.
///
/// Pure Rust code scores ~2–5 (semicolons, braces, fn/let/use keywords, `::`,
/// `->`, `mut`). Prose-contaminated content scores <1.0 (few structural tokens,
/// many English words). Used to gate bare-identifier extraction: when prose
/// leaks through `filter_prose_lines`, English words match the `\b\w+\b` regex
/// and get flagged as "undefined variables." By requiring a minimum density
/// before running scope checking, we prevent prose FPs while still catching
/// hallucinations in pure-code snippets (DELULU samples).
///
// ---------------------------------------------------------------------------
// SQLite placeholder mismatch detection ($N is PostgreSQL syntax; SQLite uses ?)
// ---------------------------------------------------------------------------
//
// Benchmark miss (task-01-rust-sqlx): code used `SqlitePool` with
// `sqlx::query!("INSERT ... VALUES ($1, $2)")`. SQLite expects `?` placeholders;
// `$N` is PostgreSQL syntax. sqlx would reject this at compile time
// (sqlx::query! validates SQL at compile time against the DB schema). Flagging
// the mismatch deterministically catches this class of cross-dialect confusion.
//
// Detection: content references SQLite (SqlitePool/SqliteConnection/sqlite:)
// AND a string literal inside or near an `sqlx::query*!` macro contains `$N`.

static SQLITE_QUERY_MACRO_RE: Lazy<Regex> = Lazy::new(|| {
    // Match `sqlx::query!`, `sqlx::query_as!`, `sqlx::query_scalar!` followed
    // by an optional generic/type arg and a string literal. Capture the SQL.
    Regex::new(
        r#"sqlx::query(?:_as|_scalar)?!\s*(?:\s*<[^>]*>\s*)?\(\s*(?:"([^"]*)"|'([^']*)')"#,
    )
    .unwrap()
});

static PG_PLACEHOLDER_RE: Lazy<Regex> = Lazy::new(|| {
    // PostgreSQL positional placeholders: $1, $2, ... (NOT $NAME which is psql vars)
    Regex::new(r"\$\d+").unwrap()
});

fn detect_sqlite_placeholder_mismatch(content: &str) -> Vec<String> {
    // SQLite context check: only flag if the code actually uses SQLite.
    // Postgres code legitimately uses $N placeholders.
    let is_sqlite_context = content.contains("SqlitePool")
        || content.contains("SqliteConnection")
        || content.contains("sqlite::")
        || content.contains("sqlite:")
        || content.contains("Sqlite");
    if !is_sqlite_context {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    for caps in SQLITE_QUERY_MACRO_RE.captures_iter(content) {
        let sql = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str());
        if let Some(sql) = sql {
            if let Some(m) = PG_PLACEHOLDER_RE.find(sql) {
                warnings.push(format!(
                    "sqlite-placeholder-mismatch: SQL uses `{}` (PostgreSQL syntax) with SQLite — use `?` instead",
                    m.as_str()
                ));
            }
        }
    }
    warnings
}

// ---------------------------------------------------------------------------
// Missing Debug derive detection
// ---------------------------------------------------------------------------
//
// Benchmark miss (task-01-rust-sqlx): `struct User` had `#[derive(sqlx::FromRow)]`
// but NOT `Debug`. Code then used `println!("User: {:?}", user)`. Rustc rejects
// this with E0277. Catches a common LLM omission: the model derives the ORM
// trait but forgets Debug which is only needed for debug printing.
//
// Strategy:
//   1. Collect structs WITHOUT `#[derive(Debug)]` or `impl Debug for X`.
//   2. Find `{:?}` / `{:#?}` format usages with a single identifier argument.
//   3. Resolve identifier → struct via:
//      a. `let VAR: STRUCT` direct annotation
//      b. snake_case variant of STRUCT name (user → User)
//   4. If resolved struct lacks Debug → flag.

struct StructInfo {
    name: String,
    has_debug: bool,
}

/// Extract struct definitions with their Debug derive status.
fn collect_struct_debug_info(content: &str) -> Vec<StructInfo> {
    let mut out = Vec::new();
    // Match: optional derives (multiple lines), then `struct NAME`
    // We scan line-by-line to associate derives with the struct that follows.
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        // Collect consecutive #[derive(...)] attributes
        let mut derives = String::new();
        while i < lines.len() && lines[i].trim_start().starts_with("#[derive(") {
            // Could span multiple lines, but typical case is single line
            derives.push_str(lines[i]);
            i += 1;
        }
        if i >= lines.len() {
            break;
        }
        let struct_line = lines[i];
        let trimmed = struct_line.trim_start();
        // struct definition: `pub struct NAME` or `struct NAME`
        let name = if let Some(rest) = trimmed
            .strip_prefix("pub struct ")
            .or_else(|| trimmed.strip_prefix("pub(crate) struct "))
            .or_else(|| trimmed.strip_prefix("struct "))
        {
            rest.split_whitespace()
                .next()
                .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric() && c != '_'))
        } else {
            None
        };
        if let Some(name) = name {
            if !name.is_empty() {
                // Also check for `impl Debug for NAME` later via separate pass.
                // For derives, also consider derives that might be on lines
                // between the attribute and the struct (none skipped here).
                let has_debug = derives.contains("Debug") || derives.contains("debug");
                out.push(StructInfo {
                    name: name.to_string(),
                    has_debug,
                });
            }
        }
        i += 1;
    }
    out
}

fn detect_missing_debug_derive(content: &str) -> Vec<String> {
    let structs = collect_struct_debug_info(content);
    if structs.is_empty() {
        return Vec::new();
    }

    // Add manual impl Debug for NAME → mark as has_debug
    let structs = {
        let mut s = structs;
        for si in &mut s {
            let pat = format!("impl Debug for {}", si.name);
            if content.contains(&pat) {
                si.has_debug = true;
            }
        }
        s
    };

    // Build map: snake_case name → struct (for variable→type resolution)
    // and PascalCase name → struct
    use std::collections::HashMap;
    let by_pascal: HashMap<&str, &StructInfo> = structs
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();
    let by_snake: HashMap<String, &StructInfo> = structs
        .iter()
        .filter_map(|s| {
            let snake = pascal_to_snake(&s.name);
            if snake != s.name {
                Some((snake, s))
            } else {
                None
            }
        })
        .collect();

    // Find `{:?}` usages with identifier arguments
    // Pattern: `format!("{:?}", VAR)` or `println!("{:?}", VAR)` etc.
    // Matches double-quoted format strings (raw string literals `r#".."#` are
    // rarer for debug prints — benchmark uses double quotes).
    let format_re =
        Regex::new(r#"(?:println|eprintln|print|eprint|format|write|writeln|panic)!\s*\(\s*"(?:[^"\\]|\\.)*\{:#?\?\}(?:[^"\\]|\\.)*"\s*,\s*([a-zA-Z_]\w*)"#).unwrap();

    // Build let-binding map: VAR → TYPE (PascalCase)
    let let_re = Regex::new(r"\blet\s+(?:mut\s+)?(\w+)\s*:\s*([A-Z]\w*)").unwrap();

    let mut var_types: HashMap<String, String> = HashMap::new();
    for caps in let_re.captures_iter(content) {
        if let (Some(var), Some(ty)) = (caps.get(1), caps.get(2)) {
            var_types.insert(var.as_str().to_string(), ty.as_str().to_string());
        }
    }

    let mut warnings = Vec::new();
    let mut flagged_structs: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in format_re.captures_iter(content) {
        let expr = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        // Resolve expr → struct type
        let resolved_struct: Option<&StructInfo> = if let Some(ty) = var_types.get(expr) {
            // Direct annotation: let VAR: TYPE
            by_pascal.get(ty.as_str()).copied()
        } else {
            // Heuristic: expr name is snake_case of struct name
            by_snake.get(expr).copied()
        };
        if let Some(si) = resolved_struct {
            if !si.has_debug && !flagged_structs.contains(&si.name) {
                flagged_structs.insert(si.name.clone());
                warnings.push(format!(
                    "missing-debug-derive: `{}` used with `{{:?}}` but lacks `#[derive(Debug)]` (rustc E0277)",
                    si.name
                ));
            }
        }
    }
    warnings
}

/// Convert PascalCase to snake_case (User → user, TaskItem → task_item).
fn pascal_to_snake(s: &str) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            for c in ch.to_lowercase() {
                out.push(c);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod sqlite_placeholder_tests {
    use super::*;

    #[test]
    fn sqlite_dollar_placeholder_flagged() {
        let code = r#"
use sqlx::sqlite::SqlitePool;
async fn create(pool: &SqlitePool) {
    sqlx::query!("INSERT INTO users VALUES ($1, $2)", "a", "b")
        .execute(pool).await?;
}
"#;
        let w = detect_sqlite_placeholder_mismatch(code);
        assert!(w.iter().any(|x| x.contains("$1")), "got {:?}", w);
    }

    #[test]
    fn sqlite_question_placeholder_not_flagged() {
        let code = r#"
use sqlx::sqlite::SqlitePool;
async fn create(pool: &SqlitePool) {
    sqlx::query!("INSERT INTO users VALUES (?, ?)", "a", "b")
        .execute(pool).await?;
}
"#;
        let w = detect_sqlite_placeholder_mismatch(code);
        assert!(w.is_empty(), "got {:?}", w);
    }

    #[test]
    fn postgres_dollar_placeholder_not_flagged() {
        // No SqlitePool/sqlite: references — should NOT flag (could be Postgres)
        let code = r#"
async fn create(pool: &PgPool) {
    sqlx::query!("INSERT INTO users VALUES ($1, $2)", "a", "b")
        .execute(pool).await?;
}
"#;
        let w = detect_sqlite_placeholder_mismatch(code);
        assert!(w.is_empty(), "got {:?}", w);
    }
}

#[cfg(test)]
mod debug_derive_tests {
    use super::*;

    #[test]
    fn missing_debug_derive_flagged() {
        // Benchmark task-01-rust-sqlx pattern
        let code = r#"
#[derive(sqlx::FromRow)]
struct User {
    id: i32,
    name: String,
}

fn get_user() -> User { User { id: 1, name: "x".into() } }

fn main() {
    let user = get_user();
    println!("User: {:?}", user);
}
"#;
        let w = detect_missing_debug_derive(code);
        assert!(w.iter().any(|x| x.contains("User")), "got {:?}", w);
    }

    #[test]
    fn with_debug_derive_not_flagged() {
        let code = r#"
#[derive(Debug)]
struct User {
    id: i32,
    name: String,
}

fn main() {
    let user = User { id: 1, name: "x".into() };
    println!("User: {:?}", user);
}
"#;
        let w = detect_missing_debug_derive(code);
        assert!(w.is_empty(), "got {:?}", w);
    }

    #[test]
    fn manual_impl_debug_not_flagged() {
        let code = r#"
struct User {
    id: i32,
    name: String,
}

impl Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "User({})", self.name)
    }
}

fn main() {
    let user = User { id: 1, name: "x".into() };
    println!("User: {:?}", user);
}
"#;
        let w = detect_missing_debug_derive(code);
        assert!(w.is_empty(), "got {:?}", w);
    }
}

// ── Cargo.lock checksum fabrication detection ─────────────────────────────

static CARGO_LOCK_ENTRY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?m)name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)"[\s\S]*?checksum\s*=\s*"([^"]+)""#,
    )
    .unwrap()
});

/// Detect fabricated Cargo.lock checksums.
///
/// Real Cargo.lock checksums:
/// - Old format: 40 hex chars (SHA-1)
/// - New format: `sha256:` + 64 hex chars
///
/// Fabrication patterns detected:
/// 1. Wrong length or non-hex content
/// 2. Exact duplicate checksum across different name+version entries
/// 3. Shared long suffix (≥20 chars) across different entries
pub fn detect_cargo_lock_checksum_fabrication(content: &str) -> Vec<String> {
    // Only process content that looks like Cargo.lock
    if !content.contains("[[package]]") || !content.contains("checksum") {
        return Vec::new();
    }

    let mut entries: Vec<(String, String)> = Vec::new(); // (package_id, checksum)
    for caps in CARGO_LOCK_ENTRY_RE.captures_iter(content) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let version = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let checksum = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        entries.push((format!("{}-{}", name, version), checksum.to_string()));
    }

    if entries.len() < 2 {
        return Vec::new();
    }

    let mut warnings: Vec<String> = Vec::new();
    let mut seen: HashMap<&str, &str> = HashMap::new(); // checksum -> package_id
    let mut suffix_map: HashMap<String, Vec<String>> = HashMap::new();

    for (pkg_id, checksum) in &entries {
        let raw = checksum
            .strip_prefix("sha256:")
            .unwrap_or(checksum.as_str());

        // Check 1: wrong length or non-hex
        let is_valid_sha1 = raw.len() == 40 && raw.chars().all(|c| c.is_ascii_hexdigit());
        let is_valid_sha256 = raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit());
        if !is_valid_sha1 && !is_valid_sha256 && !raw.is_empty() {
            warnings.push(format!(
                "hallucinated-checksum: Cargo.lock `{}` checksum has invalid format (len={}, not 40 hex or 64 hex)",
                pkg_id,
                raw.len()
            ));
        }

        // Check 2: exact duplicate
        if let Some(prev) = seen.get(raw) {
            if prev != pkg_id && !raw.is_empty() {
                warnings.push(format!(
                    "hallucinated-checksum: Cargo.lock `{}` and `{}` share identical checksum `{}`",
                    prev, pkg_id, raw
                ));
            }
        } else {
            seen.insert(raw, pkg_id);
        }

        // Check 3: shared suffix (≥20 chars)
        if raw.len() >= 20 {
            let suffix = raw[raw.len() - 20..].to_string();
            suffix_map.entry(suffix).or_default().push(pkg_id.clone());
        }
    }

    // Emit shared-suffix warnings (skip exact dups already flagged)
    for (suffix, pkgs) in &suffix_map {
        let unique: Vec<&str> = pkgs.iter().map(|s| s.as_str()).collect::<HashSet<_>>().into_iter().collect();
        if unique.len() > 1 {
            warnings.push(format!(
                "hallucinated-checksum: different Cargo.lock entries share identical hash suffix `...{}`: {}",
                suffix,
                unique.join(", ")
            ));
        }
    }

    warnings.dedup();
    warnings
}

#[cfg(test)]
mod cargo_lock_checksum_tests {
    use super::*;

    #[test]
    fn wrong_length_checksum_flagged() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef01234567"
"#;
        let w = detect_cargo_lock_checksum_fabrication(content);
        assert!(w.iter().any(|s| s.contains("serde") && s.contains("invalid format")),
            "expected invalid format warning for serde, got: {:?}", w);
    }

    #[test]
    fn exact_duplicate_checksum_flagged() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        let content = format!(r#"
[[package]]
name = "serde"
version = "1.0.0"
checksum = "{}"

[[package]]
name = "tokio"
version = "1.0.0"
checksum = "{}"
"#, hash, hash);
        let w = detect_cargo_lock_checksum_fabrication(&content);
        assert!(w.iter().any(|s| s.contains("identical checksum")),
            "expected duplicate checksum warning, got: {:?}", w);
    }

    #[test]
    fn distinct_valid_checksums_not_flagged() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
checksum = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

[[package]]
name = "tokio"
version = "1.0.0"
checksum = "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"
"#;
        let w = detect_cargo_lock_checksum_fabrication(content);
        assert!(w.iter().all(|s| !s.contains("serde") && !s.contains("tokio")),
            "should not flag distinct valid checksums, got: {:?}", w);
    }

    #[test]
    fn sha256_format_accepted() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.0"
checksum = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

[[package]]
name = "tokio"
version = "1.0.0"
checksum = "sha256:f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5"
"#;
        let w = detect_cargo_lock_checksum_fabrication(content);
        assert!(w.iter().all(|s| !s.contains("invalid format")),
            "sha256: format should not trigger invalid-format, got: {:?}", w);
    }

    #[test]
    fn non_cargo_lock_content_not_flagged() {
        let content = "let checksum = \"abc\";";
        let w = detect_cargo_lock_checksum_fabrication(content);
        assert!(w.is_empty(), "non-Cargo.lock content should not trigger, got: {:?}", w);
    }
}
