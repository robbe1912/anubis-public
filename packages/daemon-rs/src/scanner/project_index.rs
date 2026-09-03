//! Project index — walks source files, builds declaration index for L1.
//! Extracted from scanner/mod.rs.

use std::path::Path;
use parking_lot::Mutex;
use std::fs;

use super::verdict_cache::current_time_ms;

// ── Council A7: user-extendable L1 fuzzy-match skip list ────────────────
// COMMON_NAMES (below) is a hardcoded list of ~80 names that should never
// trigger L1 fuzzy-match suggestions (Rust keywords, common verbs like
// add/get/set, is_* predicates). Users with domain-specific names that
// routinely fuzzy-match project tokens (e.g. internal jargon, legacy
// method names) had to recompile to extend it.
//
// EXTRA_L1_SKIP_NAMES OnceCell mirrors the COMMON_TS_EXPORTS pattern:
// populated once at daemon startup from ScannerConfig.extra_l1_skip_names,
// first-write-wins (subsequent calls no-op).

static EXTRA_L1_SKIP_NAMES: once_cell::sync::OnceCell<std::collections::HashSet<String>> =
    once_cell::sync::OnceCell::new();

/// Populate the user-provided L1 fuzzy-match skip list (daemon startup only).
/// First-write-wins: subsequent calls are no-ops. Requires daemon restart
/// to apply config changes.
pub fn set_extra_l1_skip_names(names: Vec<String>) {
    let set: std::collections::HashSet<String> = names.into_iter().collect();
    let _ = EXTRA_L1_SKIP_NAMES.set(set);
}

/// True if `name` is in the built-in COMMON_NAMES skip list OR in the
/// user-provided extension set. Caller: `find_close_match_in_index`.
pub fn is_common_l1_skip_name(name: &str) -> bool {
    const COMMON_NAMES: &[&str] = &[
        // Rust keywords
        "pub", "let", "use", "mod", "fn", "impl", "trait", "struct",
        "enum", "type", "where", "self", "super", "crate", "extern",
        "move", "ref", "mut", "const", "static", "async", "await",
        "return", "break", "continue", "if", "else", "for", "while",
        "loop", "match", "unsafe", "true", "false",
        // Extremely common method names (never hallucinated, ambiguous short forms)
        "add", "get", "set", "put", "new", "now", "run", "len", "push",
        "pop", "insert", "remove", "delete", "update", "create", "read",
        "write", "open", "close", "start", "stop", "init", "clear",
        "reset", "save", "load", "send", "clone", "copy",
        "is_empty", "is_none", "is_ok", "is_err", "is_some", "is_ready",
        "complete", "cancel", "abort", "finish", "done",
        "default", "from", "into", "as_ref", "as_mut",
        "fmt", "fmt_debug", "fmt_display",
        "next", "prev", "first", "last", "begin", "end",
        "has", "has_key", "has_value", "contains", "exists",
        "find", "search", "filter", "map", "each", "for_each",
        "count", "size", "capacity", "is_full",
        "name", "path", "dir", "file", "url", "uri",
        // Universal validation/middleware verbs
        "validate", "verify", "authenticate", "authorize", "sanitize",
        // Common short words that fuzzy-match project tokens
        "not", "listen", "g",
    ];
    if COMMON_NAMES.contains(&name) {
        return true;
    }
    EXTRA_L1_SKIP_NAMES.get().is_some_and(|set| set.contains(name))
}

/// Extract index entries from a single source file's content.
///
/// Returns `"filename: NAME"` lines, one per declaration / imported symbol /
/// variable binding. Multi-language aware: TS/JS/Python/Rust/GDScript/Go/Java/C#/C++.
///
/// Why imports + bindings in addition to declarations:
///   - `from sklearn.preprocessing import PolynomialFeatures` — the
///     hallucinated `PolynomialTransformer` is verifiable against the
///     imported `PolynomialFeatures`.
///   - `A = np.array(...)` — the hallucinated `matrixA` is verifiable
///     against the bound `A`.
///   - Without these, the L1 index would only see local declarations and
///     miss the most common hallucination patterns (DELULU benchmark).
pub(crate) fn extract_index_entries(content: &str, fname: &str) -> Vec<String> {
    use once_cell::sync::Lazy;
    use regex::Regex;

    // ── Declaration patterns ────────────────────────────────────────────
    static RE_DECL_TS_JS_PY_RS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?:export\s+)?(?:async\s+)?(?:function|class|const|let|type|interface|enum|def|fn)\s+([A-Za-z_][A-Za-z0-9_]*)",
        ).unwrap()
    });
    static RE_DECL_GD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?:^|\n)\s*(?:func|class_name|signal)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap()
    });
    static RE_DECL_GO: Lazy<Regex> = Lazy::new(|| {
        // `func NAME(` or `func (recv Type) NAME(`
        Regex::new(r"\bfunc\s+(?:\([^)]*\)\s+)?([A-Za-z_]\w*)\s*\(").unwrap()
    });
    static RE_DECL_GO_TYPE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\btype\s+([A-Za-z_]\w*)\s+").unwrap()
    });
    static RE_DECL_JAVA_CS_CLASS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"\b(?:public|private|protected|static|final|abstract|sealed|internal)\s+(?:[\w<>\[\]]+\s+)*class\s+([A-Za-z_]\w*)",
        ).unwrap()
    });
    static RE_DECL_JAVA_CS_METHOD: Lazy<Regex> = Lazy::new(|| {
        // [modifiers] returnType NAME(  — at least one modifier required to
        // distinguish from arbitrary function-call syntax in C# / Java.
        Regex::new(
            r"\b(?:public|private|protected|static|final|virtual|override|abstract|sealed|async)\s+(?:[\w<>\[\]]+\s+)+([A-Za-z_]\w*)\s*\(",
        ).unwrap()
    });
    static RE_DECL_CPP: Lazy<Regex> = Lazy::new(|| {
        // `<ret-type> NAME(` at line start, optional class/struct keyword.
        Regex::new(
            r"^\s*(?:(?:void|int|char|float|double|bool|auto|struct|class|inline|static|virtual)\s+)+([A-Za-z_]\w*)\s*\(",
        ).unwrap()
    });
    static RE_DECL_CPP_CLASS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:class|struct)\s+([A-Z]\w*)\s*(?::|\{|$)").unwrap()
    });
    // C-style `typedef struct { ... } NAME;` — anonymous struct with
    // typedef name at END. RE_DECL_CPP_CLASS misses this because there's
    // no name between `struct` and `{`. Benchmark FP: HashMapEntry.
    static RE_DECL_C_TYPEDEF: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\}\s*([A-Za-z_]\w*)\s*;").unwrap()
    });

    // ── Import / symbol-name patterns ───────────────────────────────────
    static RE_IMP_PY_FROM: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\bfrom\s+\S+\s+import\s+([^\n]+)").unwrap()
    });
    // Parenthesized multi-line Python import:
    //   from typing import (
    //       TYPE_CHECKING,
    //       Iterator,   # may carry `as ALIAS`
    //   )
    // The single-line RE_IMP_PY_FROM misses these (standard isort/black
    // style for long imports) — fragment-visibility FPs on Iterator etc.
    static RE_IMP_PY_FROM_PAREN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?s)\bfrom\s+\S+\s+import\s*\(([^)]{0,2000})\)").unwrap()
    });
    static RE_IMP_PY_IMPORT: Lazy<Regex> = Lazy::new(|| {
        // Capture the full statement tail INCLUDING any `as ALIAS` clause —
        // the handler splits the alias out so the in-scope binding gets
        // indexed (fragment-visibility FP fix). Trailing comments are
        // rejected by the handler's whitespace guard.
        Regex::new(r"\bimport\s+([^\n]+)").unwrap()
    });
    static RE_IMP_JS_TS_DESTRUCT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\bimport\s+\{([^}]+)\}\s+from").unwrap()
    });
    static RE_IMP_JS_TS_DEFAULT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\bimport\s+([A-Za-z_]\w*)\s+from").unwrap()
    });
    static RE_IMP_JAVA_CS: Lazy<Regex> = Lazy::new(|| {
        // import x.y.NAME;  /  using x.y.NAME;
        Regex::new(r"\b(?:import|using)\s+[\w.]+\.(\w+)\s*[;\n]").unwrap()
    });
    static RE_IMP_CPP_HEADER: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"#include\s+[<"]([\w./]+)[>"]"#).unwrap()
    });

    // ── Variable-binding patterns ───────────────────────────────────────
    // Capture LHS identifiers from simple assignments. Used to verify
    // undefinedvariable hallucinations: `error(...)` hallucinated but
    // `error` never bound in prompt scope.
    static RE_BIND: Lazy<Regex> = Lazy::new(|| {
        // `name =`, `name :=`, `name : Type =`, `let/var/const name`
        Regex::new(r"\b(?:let|var|const|mut)\s+([A-Za-z_]\w*)\b").unwrap()
    });
    static RE_BIND_PY: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^\s*([A-Za-z_]\w*)\s*(?::[=]|:=|=\s*[^=])").unwrap()
    });
    static RE_BIND_GO: Lazy<Regex> = Lazy::new(|| {
        // `name := value` (short var decl) — Go-specific.
        Regex::new(r"\b([A-Za-z_]\w*)\s*:?=").unwrap()
    });

    // Keywords we never want to record as bindings/declarations.
    const SKIP: &[&str] = &[
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "return", "break", "continue", "function", "class", "const", "let",
        "var", "type", "interface", "enum", "struct", "func", "def", "import",
        "from", "export", "package", "true", "false", "null", "none", "self",
        "this", "new", "delete", "void", "int", "char", "bool", "float",
        "double", "string", "async", "await", "yield", "static", "public",
        "private", "protected", "virtual", "override", "abstract", "final",
        "nil", "true", "false", "and", "or", "not", "in", "is", "as",
        // GDScript keywords — prevents FP filter from matching keyword-named
        // warnings against session_defined symbols extracted from .gd files.
        "class_name", "extends", "signal", "onready", "tool", "pass", "match",
        "elif", "preload", "load", "yield",
    ];

    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let push = |out: &mut Vec<String>, seen: &mut std::collections::HashSet<String>, name: &str| {
        let name = name.trim();
        if name.is_empty() || name.len() < 2 {
            return;
        }
        if SKIP.contains(&name.to_lowercase().as_str()) {
            return;
        }
        if seen.insert(name.to_string()) {
            out.push(format!("{fname}: {name}"));
        }
    };

    let take_n_lines = content.lines().take(500).collect::<Vec<_>>();
    let joined = take_n_lines.join("\n");

    // Declarations
    for re in [
        &*RE_DECL_TS_JS_PY_RS,
        &*RE_DECL_GD,
        &*RE_DECL_GO,
        &*RE_DECL_GO_TYPE,
        &*RE_DECL_JAVA_CS_CLASS,
        &*RE_DECL_JAVA_CS_METHOD,
        &*RE_DECL_CPP,
        &*RE_DECL_CPP_CLASS,
        &*RE_DECL_C_TYPEDEF,
    ] {
        for cap in re.captures_iter(&joined) {
            if let Some(m) = cap.get(1) {
                push(&mut out, &mut seen, m.as_str());
            }
        }
    }

    // Imports → extract imported NAMES (not package paths).
    // `#` never appears inside a Python import statement outside a trailing
    // comment, so stripping at `#` is safe and keeps `import os, sys  # x`
    // from losing `sys` to the whitespace guard (verifier finding).
    for cap in RE_IMP_PY_FROM.captures_iter(&joined) {
        if let Some(names) = cap.get(1) {
            for n in names.as_str().split(',') {
                let n = n.split('#').next().unwrap_or(n).trim();
                // `NAME as ALIAS` → push BOTH: NAME is the source symbol,
                // ALIAS is the in-scope binding. Dropping ALIAS caused
                // fragment-visibility FPs: `from sqlite3 import dbapi2 as
                // Database` makes `Database` the name code actually uses.
                if let Some((name, alias)) = n.split_once(" as ") {
                    let name = name.trim();
                    let alias = alias.trim();
                    if !name.is_empty() {
                        push(&mut out, &mut seen, name);
                    }
                    if !alias.is_empty() {
                        push(&mut out, &mut seen, alias);
                    }
                } else if !n.is_empty() {
                    push(&mut out, &mut seen, n);
                }
            }
        }
    }
    // Parenthesized multi-line Python imports: same NAME/ALIAS handling
    // as RE_IMP_PY_FROM, split on commas AND newlines. `#` strips
    // per-line comments inside the block.
    for cap in RE_IMP_PY_FROM_PAREN.captures_iter(&joined) {
        if let Some(names) = cap.get(1) {
            for n in names.as_str().split([',', '\n']) {
                let n = n.split('#').next().unwrap_or(n).trim();
                if let Some((name, alias)) = n.split_once(" as ") {
                    let name = name.trim();
                    let alias = alias.trim();
                    if !name.is_empty() {
                        push(&mut out, &mut seen, name);
                    }
                    if !alias.is_empty() {
                        push(&mut out, &mut seen, alias);
                    }
                } else if !n.is_empty() {
                    push(&mut out, &mut seen, n);
                }
            }
        }
    }
    for cap in RE_IMP_PY_IMPORT.captures_iter(&joined) {
        if let Some(names) = cap.get(1) {
            for n in names.as_str().split(',') {
                let n = n.split('#').next().unwrap_or(n).trim();
                // `import a.b.c as x` → both module tail and alias binding.
                let (base, alias) = match n.split_once(" as ") {
                    Some((b, a)) => (b.trim(), Some(a.trim())),
                    None => (n, None),
                };
                // For `import a.b.c`, take the last segment.
                let base = base.rsplit('.').next().unwrap_or(base);
                if !base.is_empty() && !base.contains(char::is_whitespace) {
                    push(&mut out, &mut seen, base);
                }
                if let Some(a) = alias {
                    if !a.is_empty() && !a.contains(char::is_whitespace) {
                        push(&mut out, &mut seen, a);
                    }
                }
            }
        }
    }
    for cap in RE_IMP_JS_TS_DESTRUCT.captures_iter(&joined) {
        if let Some(names) = cap.get(1) {
            for n in names.as_str().split(',') {
                let n = n.trim();
                // `{A as B}` → push both source name and local binding.
                // Strip `type NAME` (TypeScript type-only imports)
                let n = n.strip_prefix("type ").unwrap_or(n).trim();
                if let Some((name, alias)) = n.split_once(" as ") {
                    let name = name.trim();
                    let alias = alias.trim();
                    if !name.is_empty() {
                        push(&mut out, &mut seen, name);
                    }
                    if !alias.is_empty() {
                        push(&mut out, &mut seen, alias);
                    }
                } else if !n.is_empty() {
                    push(&mut out, &mut seen, n);
                }
            }
        }
    }
    for cap in RE_IMP_JS_TS_DEFAULT.captures_iter(&joined) {
        if let Some(m) = cap.get(1) {
            push(&mut out, &mut seen, m.as_str());
        }
    }
    for cap in RE_IMP_JAVA_CS.captures_iter(&joined) {
        if let Some(m) = cap.get(1) {
            push(&mut out, &mut seen, m.as_str());
        }
    }
    for cap in RE_IMP_CPP_HEADER.captures_iter(&joined) {
        if let Some(m) = cap.get(1) {
            // For `<armadillo>` we want the bare name; for `<dlib/clustering.h>`
            // take the basename without extension.
            let raw = m.as_str();
            let basename = raw.rsplit('/').next().unwrap_or(raw);
            let basename = basename.trim_end_matches(".h");
            push(&mut out, &mut seen, basename);
        }
    }

    // Variable bindings
    for cap in RE_BIND.captures_iter(&joined) {
        if let Some(m) = cap.get(1) {
            push(&mut out, &mut seen, m.as_str());
        }
    }
    for line in content.lines().take(500) {
        for cap in RE_BIND_PY.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                push(&mut out, &mut seen, m.as_str());
            }
        }
    }
    for cap in RE_BIND_GO.captures_iter(&joined) {
        if let Some(m) = cap.get(1) {
            push(&mut out, &mut seen, m.as_str());
        }
    }

    out
}

pub(crate) fn build_project_index(project_root: &str) -> String {
    static CACHE: Mutex<Option<ProjectIndexCache>> = Mutex::new(None);

    // ── Guard: skip non-project paths ──────────────────────────────────
    // Same rationale as looks_like_project_root in local_scanner.rs —
    // when detect_project_root fails, the proxy falls back to the daemon's
    // cwd (user home on Windows). Walking the entire home tree synchronously
    // blocks the tokio worker thread for 90+ seconds.
    //
    // Quick top-level check: look for ANY project marker or source file
    // at the root level. Single read_dir, no recursion — O(entries).
    let root_path = Path::new(project_root);
    if !is_likely_project_root(root_path) {
        tracing::debug!(
            target: "project_index",
            root = %root_path.display(),
            "build_project_index: skipping non-project root"
        );
        return String::new();
    }

    let now = current_time_ms();
    {
        let guard = CACHE.lock();
        if let Some(ref cached) = *guard {
            if cached.root == project_root && (now - cached.built_at) < 60_000 {
                // Check if any files changed since build
                if !is_project_stale(project_root, &cached.files) {
                    return cached.text.clone();
                }
            }
        }
    }

    let extensions = [
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".gd", ".py", ".rs",
        // DELULU + general coverage: Go, Java, C#, C/C++.
        ".go", ".java", ".cs", ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hh",
    ];
    let skip_dirs = [
        "node_modules",
        ".git",
        "dist",
        "dist-dev",
        "build",
        "target",
        "__pycache__",
    ];

    let mut lines = Vec::new();
    let mut files: Vec<(String, u64)> = Vec::new();

    walk_source_files(
        Path::new(project_root),
        &extensions,
        &skip_dirs,
        &mut |path, content, mtime| {
            files.push((path.to_string_lossy().to_string(), mtime));
            let fname = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let extracted = extract_index_entries(content, &fname);
            lines.extend(extracted);
            if lines.len() >= 500 {
                lines.truncate(500);
            }
        },
    );

    let text = lines.join("\n");

    {
        let mut guard = CACHE.lock();
        *guard = Some(ProjectIndexCache {
            root: project_root.to_string(),
            text: text.clone(),
            built_at: now,
            files,
        });
    }

    text
}

struct ProjectIndexCache {
    root: String,
    text: String,
    built_at: u64,
    files: Vec<(String, u64)>,
}

// ── Cross-response session symbol accumulator ─────────────────────────
//
// When an agent defines `struct TodoStore` in response 1 and calls
// `TodoStore::load()` in response 5, the file may not be on disk yet
// (or the project_index 60-second cache hasn't refreshed). This accumulator
// tracks ALL definitions seen across responses in the same project,
// eliminating timing-related false positives.
//
// Keyed on project_root (proxy sessions are per-project). Entries expire
// after 30 minutes of inactivity to prevent unbounded growth.

static SESSION_SYMBOLS: Mutex<Option<std::collections::HashMap<String, SessionEntry>>> =
    Mutex::new(None);

struct SessionEntry {
    // name → language tag. Prevents cross-language FP contamination:
    // a TypeScript `queue.empty()` symbol must NOT suppress a C++
    // hallucinated-method warning for `queue.empty()`.
    symbols: std::collections::HashMap<String, String>,
    last_updated: u64,
}

const SESSION_TTL_MS: u64 = 30 * 60 * 1000; // 30 minutes

// Council C6: per-project symbol cap. The 30-min TTL only prunes whole
// projects on inactivity — within an active session, the symbols HashSet
// grew unbounded. A single project generating ~10K unique top-level
// definitions in 30 min would be extraordinary (typical agent session:
// <500 symbols). When cap reached, stop accumulating — slight FN risk
// on pathological inputs vs unbounded memory growth on real ones.
const MAX_SESSION_SYMBOLS_PER_PROJECT: usize = 10_000;

/// Extract defined symbols from response content and accumulate them
/// into the session cache for this project. Called after each scan.
///
/// `language` tags all symbols from this call — prevents cross-language
/// FP contamination (e.g. TypeScript symbols shouldn't suppress C++ warnings).
/// Accumulate session symbols from tool-result/file content (language `""`
/// = universal suppression — matches live-proxy behavior).
pub fn accumulate_session_symbols(project_root: &str, content: &str, language: &str) {
    if project_root.is_empty() || content.is_empty() {
        return;
    }

    // Reuse extract_index_entries — it already extracts declarations,
    // imports, and bindings from all languages.
    let entries = extract_index_entries(content, "session");
    if entries.is_empty() {
        return;
    }

    let now = current_time_ms();

    {
        let mut guard = SESSION_SYMBOLS.lock();
        let map = guard.get_or_insert_with(std::collections::HashMap::new);

        // Prune expired entries
        map.retain(|_, entry| now - entry.last_updated < SESSION_TTL_MS);

        let entry = map
            .entry(project_root.to_string())
            .or_insert_with(|| SessionEntry {
                symbols: std::collections::HashMap::new(),
                last_updated: now,
            });

        for e in &entries {
            // Council C6: stop accumulating once cap reached. Avoids
            // unbounded HashSet growth within an active session.
            if entry.symbols.len() >= MAX_SESSION_SYMBOLS_PER_PROJECT {
                tracing::warn!(
                    target: "session_symbols",
                    project = %project_root,
                    cap = MAX_SESSION_SYMBOLS_PER_PROJECT,
                    "SESSION_SYMBOLS cap reached — further symbols dropped"
                );
                break;
            }
            // Store just the symbol name (after "fname: " prefix) with language tag
            if let Some(name) = e.split(": ").nth(1) {
                entry.symbols.insert(name.to_string(), language.to_string());
            } else {
                entry.symbols.insert(e.clone(), language.to_string());
            }
        }
        entry.last_updated = now;

        tracing::debug!(
            target: "session_symbols",
            project = %project_root,
            total_symbols = entry.symbols.len(),
            new_symbols = entries.len(),
            "accumulate_session_symbols"
        );
    }
}

/// Get accumulated session symbols for a project, formatted as
/// project_index lines (one per symbol, "session: NAME" format).
/// Merge with project_index before passing to FORGE.
///
/// `language` filters to only symbols defined in the same language —
/// prevents cross-language contamination (TS symbols don't suppress C++ FPs).
pub(crate) fn get_session_symbols(project_root: &str, language: &str) -> String {
    if project_root.is_empty() {
        return String::new();
    }

    let now = current_time_ms();

    {
        let guard = SESSION_SYMBOLS.lock();
        if let Some(map) = guard.as_ref() {
            if let Some(entry) = map.get(project_root) {
                if now - entry.last_updated < SESSION_TTL_MS {
                    return entry
                        .symbols
                        .iter()
                        .filter(|(_, lang)| lang.is_empty() || lang == &language)
                        .map(|(s, _)| format!("session: {s}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                }
            }
        }
    }

    String::new()
}

pub(crate) fn is_project_stale(project_root: &str, cached_files: &[(String, u64)]) -> bool {
    let extensions = [
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".gd", ".py", ".rs",
    ];
    let skip_dirs = [
        "node_modules",
        ".git",
        "dist",
        "dist-dev",
        "build",
        "target",
        "__pycache__",
    ];

    let mut current_files: Vec<(String, u64)> = Vec::new();
    walk_source_files(
        Path::new(project_root),
        &extensions,
        &skip_dirs,
        &mut |path, _content, mtime| {
            current_files.push((path.to_string_lossy().to_string(), mtime));
        },
    );

    if current_files.len() != cached_files.len() {
        return true;
    }

    for (a, b) in current_files.iter().zip(cached_files.iter()) {
        if a.0 != b.0 || a.1 != b.1 {
            return true;
        }
    }

    false
}

/// Maximum number of source files to read during project index walk.
/// Prevents 90+ second stalls on large monorepos or when project_root
/// accidentally resolves to user home. 500 files covers most real projects.
const MAX_INDEX_FILES: usize = 500;

pub(crate) fn walk_source_files(
    dir: &Path,
    extensions: &[&str],
    skip_dirs: &[&str],
    callback: &mut dyn FnMut(&Path, &str, u64),
) {
    let mut files_walked = 0usize;
    walk_source_files_inner(dir, extensions, skip_dirs, callback, &mut files_walked);
}

fn walk_source_files_inner(
    dir: &Path,
    extensions: &[&str],
    skip_dirs: &[&str],
    callback: &mut dyn FnMut(&Path, &str, u64),
    files_walked: &mut usize,
) {
    // Hard cap — bail out of the entire walk
    if *files_walked >= MAX_INDEX_FILES {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if *files_walked >= MAX_INDEX_FILES {
            return;
        }

        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip directories
        if path.is_dir() {
            if skip_dirs.contains(&name_str.as_ref()) {
                continue;
            }
            if name_str.starts_with('.') {
                continue;
            }
            walk_source_files_inner(&path, extensions, skip_dirs, callback, files_walked);
            continue;
        }

        // Skip non-source files
        let matches_ext = extensions.iter().any(|ext| name_str.ends_with(ext));
        if !matches_ext {
            continue;
        }

        // Skip test/spec/d.ts files
        if name_str.contains(".test.") || name_str.contains(".spec.") || name_str.ends_with(".d.ts")
        {
            continue;
        }

        // Skip large files (>100KB)
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if metadata.len() > 100_000 {
            continue;
        }

        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        *files_walked += 1;
        callback(&path, &content, mtime);
    }
}

/// Quick top-level check: does this directory look like a real project root?
/// Mirrors looks_like_project_root in local_scanner.rs — single read_dir,
/// no recursion. Returns false for home dirs, system dirs, empty dirs.
fn is_likely_project_root(dir: &Path) -> bool {
    const MARKERS: &[&str] = &[
        ".git", "package.json", "tsconfig.json", "cargo.toml",
        "pyproject.toml", "setup.py", "go.mod", "pom.xml",
        "build.gradle", "build.gradle.kts", "project.godot",
        "cmakelists.txt", "makefile",
    ];
    const SOURCE_EXTS: &[&str] = &[
        ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java",
        ".cs", ".cpp", ".cc", ".c", ".h", ".hpp", ".rb", ".gd",
    ];

    // Block obvious non-project paths
    let dir_str = dir.to_string_lossy().to_lowercase();
    let dir_trimmed = dir_str.trim_end_matches('\\').trim_end_matches('/');
    if dir_trimmed.ends_with("\\windows")
        || dir_trimmed.ends_with("/windows")
        || dir_trimmed.ends_with("\\system32")
        || dir_trimmed.ends_with("/system32")
        || dir_trimmed.ends_with("\\temp")
        || dir_trimmed.ends_with("/temp")
    {
        return false;
    }
    // Block user home exact match
    if let Some(home) = (|| {
        #[cfg(target_os = "windows")]
        { std::env::var("USERPROFILE").ok() }
        #[cfg(not(target_os = "windows"))]
        { std::env::var("HOME").ok() }
    })() {
        let home_lower = home.to_lowercase();
        let home_trimmed = home_lower.trim_end_matches('\\').trim_end_matches('/');
        if dir_trimmed == home_trimmed {
            return false;
        }
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_lowercase();
        if MARKERS.iter().any(|m| lower == *m || lower.ends_with(&m[1..].replace('*', ""))) {
            return true;
        }
        if SOURCE_EXTS.iter().any(|ext| lower.ends_with(ext)) {
            if !lower.contains(".test.") && !lower.contains(".spec.") && !lower.ends_with(".d.ts") {
                return true;
            }
        }
    }
    false
}

/// Check if a claim's method name appears in the project index.
///
/// Uses word-boundary matching rather than naive `contains` to avoid false
/// negatives: a claim for `app()` must NOT match the index line `happiness:
/// true` (which contains the substring "app"). The index is built by
/// `build_project_index` which emits `filename: declaration_name` per line,
/// so we split on whitespace and check set membership against the extracted
/// method name.
pub(crate) fn check_claim_in_index(claim: &str, index: &str) -> bool {
    // Extract method name from claim (e.g., "foo.bar(" → "bar")
    let target = if let Some(dot_pos) = claim.rfind('.') {
        claim[dot_pos + 1..].trim_end_matches('(')
    } else {
        claim.trim_end_matches('(')
    };
    if target.is_empty() {
        return false;
    }
    let target_lower = target.to_lowercase();

    // Word-boundary match: index lines are "filename: declaration_name" so we
    // split each line on whitespace + ':' and check if any token matches the
    // target. This prevents "app" matching inside "happiness".
    for line in index.lines() {
        for token in line.split(|c: char| c.is_whitespace() || c == ':') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            // Match either exact identifier or its trailing segment (after last '_')
            if token.eq_ignore_ascii_case(target) {
                return true;
            }
            // Also match the underscore-separated tail (snake_case names):
            // `apply_scale` should be found by a `scale(` claim.
            if let Some(seg) = token.rsplit('_').next() {
                if seg.eq_ignore_ascii_case(target_lower.as_str()) && target.len() >= 3 {
                    return true;
                }
            }
        }
    }
    false
}

/// Levenshtein distance capped at `max_dist`. Returns `max_dist + 1` if the
/// distance exceeds the cap (early exit).
pub(crate) fn levenshtein_capped(a: &str, b: &str, max_dist: usize) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let a_len = a_bytes.len();
    let b_len = b_bytes.len();
    if a_len.abs_diff(b_len) > max_dist {
        return max_dist + 1;
    }
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr: Vec<usize> = vec![0; b_len + 1];
    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        if curr.iter().min().copied().unwrap_or(0) > max_dist {
            return max_dist + 1;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_len]
}

/// Find the closest indexed name to `claim`, using a two-tier heuristic:
///   1. **Typo tier**: Levenshtein distance ≤ 2 — catches `fit_tranform`
///      vs `fit_transform`.
///   2. **Wrong-suffix tier**: same length-class (within 3) AND share a
///      common prefix of ≥ 4 chars — catches `PolynomialTransformer` vs
///      `PolynomialFeatures`.
///
/// Returns the suggested name if a close match is found, else None.
/// Used by the L1 hallucination guard to flag only near-miss claims
/// (strong signal) and stay silent on completely-fabricated names
/// (might be real external APIs the index doesn't know about).
pub(crate) fn find_close_match_in_index(claim: &str, index: &str) -> Option<String> {
    let target = if let Some(dot_pos) = claim.rfind('.') {
        claim[dot_pos + 1..].trim_end_matches('(')
    } else {
        claim.trim_end_matches('(')
    };
    if target.len() < 3 {
        return None;
    }

    // Bundle-first check: if the target name exists in ANY library in the
    // symbol bundle, it's a known API name — don't fuzzy-match against
    // project_index (would produce FPs on real APIs that happen to have
    // similar names to project-local identifiers).
    // This makes the bundle the primary source of truth for "is this a real
    // API name?" — COMMON_NAMES below is only a fallback for names NOT in
    // the bundle (language keywords, builtins, truly universal methods).
    if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
        if !cache.lookup_global(target).is_empty() {
            return None;
        }
    }

    // Skip import-style claims (from 'module' or from "module") — these are
    // relative/package imports, not function calls. Fuzzy matching on them
    // produces FPs like from 'sales_analyzer.forecasting'() → forecasting.
    if claim.contains('\'') || claim.contains('"') {
        return None;
    }

    // Skip extremely common keywords and method names — these are never
    // hallucinations and their short length produces spurious fuzzy matches
    // (add→all, now→pos, pub→mut, complete→Completed, etc.).
    // Framework-specific entries (SQLAlchemy, pandas, Flask, etc.) are NOT
    // listed here — they're handled by the bundle-first check above. Only
    // truly universal/ambiguous names stay.
    // Council A7: COMMON_NAMES moved to module-level helper
    // is_common_l1_skip_name(). The list is shared between built-in
    // (Rust keywords + common verbs) and user-extendable
    // EXTRA_L1_SKIP_NAMES OnceCell (fed from
    // ScannerConfig.extra_l1_skip_names at daemon startup).
    if is_common_l1_skip_name(target) {
        return None;
    }

    // For short names (3-4 chars), require exact prefix match of 3+ chars
    // to prevent false matches between unrelated short tokens.
    let min_lev = if target.len() <= 4 { 1 } else { 2 };

    let mut best: Option<(String, usize)> = None;
    for line in index.lines() {
        for token in line.split(|c: char| c.is_whitespace() || c == ':') {
            let token = token.trim();
            if token.len() < 3 {
                continue;
            }
            // Skip on identical — that's check_claim_in_index's job.
            if token.eq_ignore_ascii_case(target) {
                continue;
            }

            // Tier 1: typo (Levenshtein ≤ min_lev — stricter for short names)
            let lev = levenshtein_capped(target, token, min_lev);
            if lev <= min_lev {
                // Similarity ratio gate: reject matches where the edit distance
                // is too high relative to name length. Prevents false matches
                // like react→rest (dist 2, ratio 0.40), chr→cur (dist 1, ratio 0.33).
                // Real typos like fit_tranform→fit_transform have ratio <0.15.
                let max_len = target.len().max(token.len());
                let ratio = lev as f64 / max_len as f64;
                if ratio <= 0.20 {
                    match &best {
                        Some((_, d)) if *d <= lev => {}
                        _ => best = Some((token.to_string(), lev)),
                    }
                    continue;
                }
                // Ratio too high — fall through to Tier 2 check below
            }

            // Tier 2: wrong-suffix — share ≥ 4 char prefix + similar length
            // + actual full-name distance ≤ 3. The distance check prevents
            // matches like export_json↔export_name (prefix=7, but suffix
            // distance=4 — completely different suffixes).
            let prefix_len = target
                .char_indices()
                .zip(token.char_indices())
                .take_while(|((_, a), (_, b))| a.eq_ignore_ascii_case(b))
                .count();
            let len_diff = target.len().abs_diff(token.len());
            if prefix_len >= 4 && len_diff <= 3 && target.len() >= prefix_len + 3 {
                // Compute actual distance — reject if suffixes are too different.
                let full_dist = levenshtein_capped(target, token, 4);
                if full_dist <= 3 {
                    match &best {
                        Some((_, d)) if *d <= 2 => {}
                        _ => {
                            if best.is_none() {
                                best = Some((token.to_string(), 3));
                            }
                        }
                    }
                }
            }
        }
    }
    best.map(|(name, _)| name)
}

// ---------------------------------------------------------------------------
// Diff scanning — track last verified content per project root
//
