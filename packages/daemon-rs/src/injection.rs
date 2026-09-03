// Auto-doc injection: parse request body for library references, query
// cached docs/symbols, inject focused reference into the request as a
// system message BEFORE forwarding upstream.
//
// Goal: prevent hallucinations at the source by giving the LLM current
// API reference for libraries it's about to use. Distinct from FORGE
// detection (catches hallucinations after) — injection prevents them.
//
// Opt-in via config.scanner.auto_inject_docs.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::{Symbol, SymbolKind};

// ──────────────────────────────────────────────────────────────────────
// Detected library
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DetectedLibrary {
    /// Normalized name suitable for cache lookup: "numpy", "tokio", "godot".
    pub name: String,
    /// Source language: "python", "rust", "ts", "go", "cpp", "csharp", "java", "gdscript".
    pub language: String,
}

impl DetectedLibrary {
    fn new(name: impl Into<String>, language: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            language: language.into(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Library detector
// ──────────────────────────────────────────────────────────────────────
//
// Scans request content for import/use/require/include statements across
// supported languages. Returns deduplicated list of libraries to look up
// in the symbol cache.
//
// IMPORTANT: this runs on the request hot path. Keep it cheap:
//   - One regex pass per language
//   - Skip obvious stdlib (std::, java.util, fmt, fs, path, etc.)
//   - Dedupe by normalized name

/// Standard libraries to skip — present in every project, no value
/// re-injecting (and they bloat the context).
const STDLIB_PYTHON: &[&str] = &[
    "os", "sys", "pathlib", "typing", "collections", "functools", "itertools",
    "json", "re", "io", "abc", "asyncio", "logging", "datetime", "time",
    "math", "random", "subprocess", "threading", "multiprocessing", "queue",
    "socket", "ssl", "http", "urllib", "email", "csv", "sqlite3", "hashlib",
    "base64", "struct", "enum", "dataclasses", "contextlib", "weakref",
    "copy", "pickle", "shutil", "tempfile", "glob", "argparse", "unittest",
    "traceback", "warnings", "inspect", "string", "textwrap", "operator",
];

const STDLIB_TS: &[&str] = &[
    "fs", "path", "os", "http", "https", "url", "crypto", "util", "stream",
    "events", "buffer", "child_process", "net", "tls", "zlib", "querystring",
    "assert", "process", "console", "worker_threads", "perf_hooks",
];

const STDLIB_GO: &[&str] = &[
    "fmt", "os", "io", "strings", "strconv", "errors", "context", "sync",
    "time", "net", "net/http", "encoding/json", "encoding/xml", "encoding/binary",
    "sort", "math", "math/rand", "crypto", "database/sql", "log", "bytes",
    "bufio", "regexp", "path", "path/filepath", "reflect", "runtime", "unsafe",
    "testing", "flag", "os/exec", "syscall", "unicode", "unicode/utf8",
];

const STDLIB_JAVA: &[&str] = &[
    "java.lang", "java.util", "java.io", "java.net", "java.nio", "java.time",
    "java.math", "java.sql", "java.text", "java.security", "javax",
];

/// Detect libraries referenced in the given content.
///
/// `content` is the concatenation of message bodies from the request.
/// Single-pass per-language regex; cheap even on large contexts.
pub fn detect_libraries(content: &str) -> Vec<DetectedLibrary> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<DetectedLibrary> = Vec::new();

    let push = |out: &mut Vec<_>, seen: &mut HashSet<_>, name: &str, lang: &str| {
        let norm = normalize_library_name(name, lang);
        if norm.is_empty() {
            return;
        }
        if is_stdlib(&norm, lang) {
            return;
        }
        let key = (norm.clone(), lang.to_string());
        if seen.insert(key) {
            out.push(DetectedLibrary::new(norm, lang));
        }
    };

    // ── Python: `import X` / `import X.Y` / `from X import Y` / `from X.Y import Z`
    //
    // IMPORTANT: the bare `import X` pattern also matches TypeScript's
    // `import X from 'Y'`. We filter those out by checking if the matched
    // line contains `from '...'` or `from "..."` (TS-style module specifier).
    static PY_IMPORT: OnceLock<Regex> = OnceLock::new();
    static PY_FROM: OnceLock<Regex> = OnceLock::new();
    static TS_FROM_CHECK: OnceLock<Regex> = OnceLock::new();
    let py_import = PY_IMPORT.get_or_init(|| Regex::new(r"(?m)^\s*import\s+([\w.]+)").unwrap());
    let py_from = PY_FROM.get_or_init(|| Regex::new(r"(?m)^\s*from\s+([\w.]+)\s+import").unwrap());
    let ts_check = TS_FROM_CHECK.get_or_init(|| Regex::new(r#"from\s+['"]"#).unwrap());
    for cap in py_import.captures_iter(content) {
        // Skip if this line is actually a TS-style import (has `from '...'`)
        let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let line_end = content[match_start..]
            .find('\n')
            .map(|p| match_start + p)
            .unwrap_or(content.len());
        let line = &content[match_start..line_end];
        if ts_check.is_match(line) {
            continue;
        }
        push(&mut out, &mut seen, &cap[1], "python");
    }
    for cap in py_from.captures_iter(content) {
        push(&mut out, &mut seen, &cap[1], "python");
    }

    // ── TypeScript/JavaScript: `import ... from 'X'` / `require('X')` / `import 'X'`
    static TS_FROM: OnceLock<Regex> = OnceLock::new();
    static TS_REQUIRE: OnceLock<Regex> = OnceLock::new();
    let ts_from = TS_FROM.get_or_init(|| Regex::new(r#"from\s+['"]([\w@/-]+)['"]"#).unwrap());
    let ts_require = TS_REQUIRE.get_or_init(|| Regex::new(r#"require\s*\(\s*['"]([\w@/-]+)['"]\s*\)"#).unwrap());
    for cap in ts_from.captures_iter(content) {
        push(&mut out, &mut seen, &cap[1], "ts");
    }
    for cap in ts_require.captures_iter(content) {
        push(&mut out, &mut seen, &cap[1], "ts");
    }

    // ── Rust: `use X::Y` / `extern crate X`
    static RS_USE: OnceLock<Regex> = OnceLock::new();
    static RS_EXTERN: OnceLock<Regex> = OnceLock::new();
    let rs_use = RS_USE.get_or_init(|| Regex::new(r"(?m)^\s*use\s+([\w:]+)::").unwrap());
    let rs_extern = RS_EXTERN.get_or_init(|| Regex::new(r"(?m)^\s*extern\s+crate\s+(\w+)").unwrap());
    for cap in rs_use.captures_iter(content) {
        push(&mut out, &mut seen, &cap[1], "rust");
    }
    for cap in rs_extern.captures_iter(content) {
        push(&mut out, &mut seen, &cap[1], "rust");
    }

    // ── Go: import blocks. Go imports use the last path segment as the
    // library name in user code, but for cache lookup we want the full path
    // (e.g. "github.com/user/repo" → library "user/repo" or just "repo").
    static GO_IMPORT: OnceLock<Regex> = OnceLock::new();
    let go_import = GO_IMPORT.get_or_init(|| Regex::new(r#""([\w./-]+)""#).unwrap());
    // Only scan lines inside an import block — otherwise we'd match any
    // quoted string. Quick heuristic: only consider imports if a Go file
    // pattern is present (`package X` or `func main`).
    let looks_like_go = content.contains("package ") && content.contains("func ");
    if looks_like_go {
        // Find import blocks: `import (...)` or single-line `import "..."`
        static GO_IMPORT_BLOCK: OnceLock<Regex> = OnceLock::new();
        let block_re = GO_IMPORT_BLOCK.get_or_init(|| {
            Regex::new(r"import\s*\(([^)]*)\)").unwrap()
        });
        for block_cap in block_re.captures_iter(content) {
            let block = &block_cap[1];
            for cap in go_import.captures_iter(block) {
                push(&mut out, &mut seen, &cap[1], "go");
            }
        }
        // Single-line imports
        static GO_SINGLE: OnceLock<Regex> = OnceLock::new();
        let single_re = GO_SINGLE.get_or_init(|| {
            Regex::new(r#"(?m)^\s*import\s+"([\w./-]+)""#).unwrap()
        });
        for cap in single_re.captures_iter(content) {
            push(&mut out, &mut seen, &cap[1], "go");
        }
    }

    // ── C/C++: `#include <X>` or `#include "X"`. Skip system headers
    // (angle brackets for standard names) — focus on third-party libs
    // like boost/Qt/OpenCV that use subdirectories.
    static CPP_INCLUDE: OnceLock<Regex> = OnceLock::new();
    let cpp_include = CPP_INCLUDE.get_or_init(|| {
        Regex::new(r#"#include\s+[<"]([\w./-]+)[>"]"#).unwrap()
    });
    for cap in cpp_include.captures_iter(content) {
        let inc = &cap[1];
        // Heuristic: only consider includes with a subdirectory (e.g.
        // `boost/asio.hpp`, `opencv2/core.hpp`, `godot_cpp/variant.hpp`).
        // Plain headers like `stdio.h`, `vector`, `string` are either
        // system headers or stdlib — no value injecting.
        if !inc.contains('/') {
            continue;
        }
        push(&mut out, &mut seen, inc, "cpp");
    }

    // ── C#: `using X.Y.Z;`. Skip System.* (BCL).
    static CS_USING: OnceLock<Regex> = OnceLock::new();
    let cs_using = CS_USING.get_or_init(|| {
        Regex::new(r"(?m)^\s*using\s+([\w.]+)\s*;").unwrap()
    });
    for cap in cs_using.captures_iter(content) {
        push(&mut out, &mut seen, &cap[1], "csharp");
    }

    // ── Java: `import X.Y.Z;`. Skip java.* and javax.*.
    static JAVA_IMPORT: OnceLock<Regex> = OnceLock::new();
    let java_import = JAVA_IMPORT.get_or_init(|| {
        Regex::new(r"(?m)^\s*import\s+(?:static\s+)?([\w.]+)\s*;").unwrap()
    });
    for cap in java_import.captures_iter(content) {
        push(&mut out, &mut seen, &cap[1], "java");
    }

    // ── GDScript: `extends X` always implies godot library
    static GD_EXTENDS: OnceLock<Regex> = OnceLock::new();
    let gd_extends = GD_EXTENDS.get_or_init(|| {
        Regex::new(r"(?m)^\s*extends\s+(\w+)").unwrap()
    });
    if gd_extends.is_match(content) {
        push(&mut out, &mut seen, "godot", "gdscript");
    }

    // ── Stdlib detection: when code uses language primitives but no imports,
    // still inject stdlib docs so L3 has ground truth for method verification.
    // This catches semantic hallucinations about stdlib methods (sorted returns
    // new list, Array.sort mutates in place, push_str returns (), etc.) that
    // can only be verified with doc context.
    //
    // Only fires when NO other libraries were detected — avoids redundant
    // injection when third-party libs are already present.
    if out.is_empty() {
        // Rust stdlib: match common patterns in code snippets (not full programs)
        if content.contains("vec!")
            || content.contains("String::")
            || content.contains("Vec::")
            || content.contains("Option::")
            || content.contains("HashMap::")
            || content.contains("let ")
            || content.contains("fn ")
            || content.contains("usize")
            || content.contains("iter()")
            || content.contains("println!")
        {
            push(&mut out, &mut seen, "tokio", "rust"); // stdlib.md lives in tokio dir
        }
        // Python stdlib: match common patterns
        else if content.contains("def ")
            || content.contains("print(")
            || content.contains("sorted(")
            || content.contains("dict.")
            || content.contains("list.")
            || content.contains("str.")
            || content.contains("import ")
            || content.contains("json.")
        {
            push(&mut out, &mut seen, "pandas", "python"); // stdlib.md lives in pandas dir
        }
        // TypeScript/JS stdlib: match common patterns
        else if content.contains("const ")
            || content.contains("function ")
            || content.contains("Array.")
            || content.contains("Promise.")
            || content.contains("Object.")
            || content.contains("JSON.")
            || content.contains("console.")
            || content.contains("fs.")
        {
            push(&mut out, &mut seen, "react", "ts"); // stdlib.md lives in react dir
        }
    }

    out
}

/// Normalize a library reference to a cache-friendly name.
///
/// Examples:
///   python: "pandas.DataFrame" → "pandas"
///   python: "package.module"    → "package"
///   ts:      "@scope/pkg"        → "pkg"  (scoped packages use basename)
///   ts:      "react-dom/client"  → "react-dom"
///   rust:    "tokio::sync"       → "tokio"
///   go:      "github.com/user/repo" → "repo"
///   go:      "github.com/user/repo/v2" → "repo"
///   cpp:     "boost/asio.hpp"    → "boost"
///   csharp:  "Newtonsoft.Json"   → "Newtonsoft.Json"
///   java:    "com.google.common" → "com.google.common"
fn normalize_library_name(raw: &str, language: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }

    match language {
        "python" => {
            // Take first dotted segment (top-level package)
            raw.split('.').next().unwrap_or("").to_string()
        }
        "ts" => {
            // Strip @scope/ prefix
            let stripped = raw.strip_prefix('@').unwrap_or(raw);
            // Strip subpath: @scope/pkg/sub → pkg/sub → take first segment
            // Actually keep multi-segment packages like "react-dom"
            let after_scope = stripped.split('/').next().unwrap_or(stripped);
            // For scoped: stripped is "scope/pkg/sub", first segment is "scope"
            // We want "pkg" — re-handle:
            if raw.starts_with('@') {
                let parts: Vec<&str> = raw.split('/').collect();
                if parts.len() >= 2 {
                    return parts[1].to_string();
                }
            }
            after_scope.to_string()
        }
        "rust" => {
            // Take first :: segment (top-level crate)
            raw.split("::").next().unwrap_or("").to_string()
        }
        "go" => {
            // github.com/user/repo[/vN][/subpackage]
            // Take last meaningful segment: skip vN version suffix
            let segments: Vec<&str> = raw.split('/').collect();
            let last = segments.last().copied().unwrap_or("");
            // Skip pure version segments like "v2", "v3"
            if last.starts_with('v') && last.len() <= 3 && last[1..].chars().all(|c| c.is_ascii_digit()) {
                if segments.len() >= 2 {
                    return segments[segments.len() - 2].to_string();
                }
                return String::new();
            }
            last.to_string()
        }
        "cpp" => {
            // boost/asio.hpp → boost
            // opencv2/core.hpp → opencv2
            // godot_cpp/variant.hpp → godot_cpp
            raw.split('/').next().unwrap_or("").to_string()
        }
        "csharp" => {
            // Keep full namespace — symbol cache stores C# as namespace.method
            // For injection, just use the top-level namespace
            raw.split('.').next().unwrap_or("").to_string()
        }
        "java" => {
            // Keep full package — com.google.common is the meaningful unit
            raw.to_string()
        }
        "gdscript" => {
            // Always "godot" for cache lookup
            "godot".to_string()
        }
        _ => raw.to_string(),
    }
}

/// Check if a normalized name is a known standard library we should skip.
fn is_stdlib(name: &str, language: &str) -> bool {
    let name_lower = name.to_lowercase();
    match language {
        "python" => STDLIB_PYTHON.iter().any(|s| *s == name_lower),
        "ts" => STDLIB_TS.iter().any(|s| *s == name_lower),
        "go" => STDLIB_GO.iter().any(|s| *s == name_lower || s.ends_with(name_lower.as_str())),
        "rust" => name == "std" || name == "core" || name == "alloc" || name == "proc_macro",
        "java" => STDLIB_JAVA.iter().any(|s| name_lower.starts_with(s)),
        "csharp" => name_lower == "system",
        _ => false,
    }
}

// ──────────────────────────────────────────────────────────────────────
// Doc snippet builder
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DocSnippet {
    pub library: String,
    pub version: Option<String>,
    pub text: String,
    pub estimated_tokens: usize,
}

impl DocSnippet {
    fn estimate_tokens(text: &str) -> usize {
        // CJK-aware estimate (council A13). Prior len()/4 underestimated
        // CJK content ~3x — caused over-allocation of doc snippets in the
        // budget for Korean/Chinese/Japanese users. Reuse scanner helper
        // for consistency with the scan token gate.
        crate::scanner::estimate_tokens(text).max(1)
    }
}

/// Build doc snippets for detected libraries, respecting a total token budget.
///
/// Strategy per library:
///   1. lookup_prefix(library, "") → all cached symbols for that library
///   2. Group by kind (Function/Class/Type/Method)
///   3. Prioritize: top-level Function + Class + Type > Methods on Classes
///   4. Take up to max_per_lib symbols
///   5. Format as: `library (version): symbol1(args), symbol2(args), ...`
///
/// Stops adding libraries once total token budget is exhausted.
pub fn build_doc_snippets(
    libraries: &[DetectedLibrary],
    cache: &SymbolCache,
    max_total_tokens: usize,
    max_per_lib: usize,
) -> Vec<DocSnippet> {
    let mut snippets: Vec<DocSnippet> = Vec::new();
    let mut total_tokens = 0usize;

    for lib in libraries {
        if total_tokens >= max_total_tokens {
            break;
        }

        let symbols = {
            let raw = cache.lookup_prefix(&lib.name, "");
            if raw.is_empty() {
                continue;
            }
            raw
        };

        // Group + prioritize
        let prioritized = prioritize_symbols(&symbols, max_per_lib);
        if prioritized.is_empty() {
            continue;
        }

        // Detect version (most common in results)
        let version = symbols
            .first()
            .map(|s| s.version.clone())
            .filter(|v| !v.is_empty());

        // Format snippet
        let mut lines = String::new();
        let header = match &version {
            Some(v) => format!("# {} (v{})", lib.name, v),
            None => format!("# {}", lib.name),
        };
        lines.push_str(&header);
        lines.push_str("\n\nCached API symbols (signatures verbatim):\n");

        for sym in &prioritized {
            let line = format_symbol_line(sym);
            lines.push_str("- ");
            lines.push_str(&line);
            lines.push('\n');
        }

        let text = lines;
        let tokens = DocSnippet::estimate_tokens(&text);

        if total_tokens + tokens > max_total_tokens {
            // Adding this library would bust the budget — try a smaller slice
            // by truncating to remaining tokens. If too small, skip.
            let remaining = max_total_tokens.saturating_sub(total_tokens);
            if remaining < 50 {
                break;
            }
            let char_budget = remaining * 4;
            let truncated: String = text.chars().take(char_budget).collect();
            let trunc_tokens = DocSnippet::estimate_tokens(&truncated);
            snippets.push(DocSnippet {
                library: lib.name.clone(),
                version,
                text: truncated,
                estimated_tokens: trunc_tokens,
            });
            total_tokens += trunc_tokens;
            break;
        }

        total_tokens += tokens;
        snippets.push(DocSnippet {
            library: lib.name.clone(),
            version,
            text,
            estimated_tokens: tokens,
        });
    }

    snippets
}

/// Prioritize symbols: top-level Function/Class/Type first, then Methods
/// (which are tied to a parent class). Cap at `max`.
fn prioritize_symbols(symbols: &[Symbol], max: usize) -> Vec<Symbol> {
    use crate::symbols::types::SymbolKind;

    // Bucket by kind
    let mut top_level: Vec<&Symbol> = Vec::new();
    let mut methods: Vec<&Symbol> = Vec::new();

    for s in symbols {
        match s.kind {
            SymbolKind::Function | SymbolKind::Class | SymbolKind::Enum
            | SymbolKind::Interface | SymbolKind::TypeAlias | SymbolKind::Constant => top_level.push(s),
            SymbolKind::Method | SymbolKind::Constructor | SymbolKind::Property
            | SymbolKind::Signal => methods.push(s),
            _ => {}
        }
    }

    let mut out: Vec<Symbol> = Vec::with_capacity(max.min(symbols.len()));

    // Top-level first (most useful for "what does this library export?")
    for s in &top_level {
        if out.len() >= max {
            return out;
        }
        out.push((*s).clone());
    }

    // Then methods, capped at remaining budget
    for s in &methods {
        if out.len() >= max {
            return out;
        }
        out.push((*s).clone());
    }

    out
}

/// Format a single symbol as a one-line reference.
fn format_symbol_line(sym: &Symbol) -> String {
    use crate::symbols::types::SymbolKind;

    let name = if sym.path.is_empty() {
        sym.name.clone()
    } else {
        sym.path.clone()
    };

    // signature is Option<String> — pull out the inner string or "()"
    let sig_str = sym.signature.as_deref().filter(|s| !s.is_empty()).unwrap_or("()");

    match sym.kind {
        SymbolKind::Function | SymbolKind::Method | SymbolKind::Constructor => {
            format!("`{}{}`", name, extract_param_list(sig_str))
        }
        SymbolKind::Class | SymbolKind::Enum | SymbolKind::Interface | SymbolKind::TypeAlias => {
            format!("type `{}`", name)
        }
        SymbolKind::Constant | SymbolKind::Property | SymbolKind::Signal
        | SymbolKind::EnumMember | SymbolKind::Annotation | SymbolKind::Module => {
            format!("`{}`", name)
        }
    }
}

/// Extract just the parameter list portion from a signature.
/// `fn foo(a: i32, b: &str) -> bool` → `(a, b)`
/// Falls back to full signature if extraction fails.
fn extract_param_list(sig: &str) -> String {
    // Find first '(' and matching ')'
    if let Some(start) = sig.find('(') {
        let mut depth = 0;
        let mut end = sig.len();
        for (i, c) in sig[start..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let raw = &sig[start..end];
        // Split params respecting nested parens/brackets so that
        // `foo(a, bar(b, c), d)` → ["a", "bar(b, c)", "d"].
        let params = split_params_balanced(raw.trim_start_matches('(').trim_end_matches(')'));

        let names: Vec<String> = params
            .iter()
            .filter_map(|p| {
                let p = p.trim();
                if p.is_empty() {
                    return None;
                }
                // Take part before ':' (type annotation) or ' =' (default value)
                let name = p
                    .split(':')
                    .next()
                    .unwrap_or(p)
                    .split('=')
                    .next()
                    .unwrap_or(p)
                    .trim();
                if name.is_empty() {
                    return None;
                }
                // Strip leading * (variadic args: *args, **kwargs)
                let cleaned = name.trim_start_matches('*').trim();
                if cleaned.is_empty() {
                    None
                } else {
                    Some(cleaned.to_string())
                }
            })
            .collect();
        if names.is_empty() {
            return "()".to_string();
        }
        format!("({})", names.join(", "))
    } else {
        // No parens — fall back to empty
        "()".to_string()
    }
}

/// Split a comma-separated param list, respecting nested parens/brackets.
/// `"a, bar(b, c), d"` → `["a", "bar(b, c)", "d"]`
fn split_params_balanced(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '(' | '[' | '<' => depth += 1,
            ')' | ']' | '>' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        parts.push(&s[start..]);
    }
    parts
}

// ──────────────────────────────────────────────────────────────────────
// Request injection
// ──────────────────────────────────────────────────────────────────────

/// Inject doc snippets into a request body before forwarding upstream.
///
/// OpenAI format: prepend a system message to `messages` array.
/// Anthropic format: append to `system` field (or create it).
///
/// Returns true if the body was modified. Caller is responsible for
/// re-serializing the modified body_json before forwarding.
pub fn inject_into_request(
    body_json: &mut serde_json::Value,
    snippets: &[DocSnippet],
    _is_anthropic: bool, // No longer branched — both providers use user-append
) -> bool {
    if snippets.is_empty() {
        return false;
    }

    let injection_text = build_injection_text(snippets);
    if injection_text.is_empty() {
        return false;
    }

    // Method 3: Append as user message at END of messages array.
    //
    // Why not system-prepend (old approach):
    //   - System message is index 0 → modifying it invalidates the ENTIRE KV
    //     cache (every subsequent token's attention shifts).
    //   - System role has weaker steering than user role for compliance-biased
    //     models (Constitutional AI training: user > system for instruction
    //     weight).
    //
    // Why append at end:
    //   - Additive: nothing before the new message changes → KV cache for all
    //     prior messages stays valid.
    //   - End-position: gets recency-attention bonus (Lost-in-Middle effect —
    //     models attend most to start + end, least to middle).
    //   - User role: architecturally correct for third-party feedback that
    //     needs the model to ACT, not just contextually know.
    //
    // See docs/STREAMING_SCHEMA_REFERENCE.md §4.6 + Oracle LSP-injection eval.
    let obj = match body_json.as_object_mut() {
        Some(o) => o,
        None => return false,
    };

    let messages = match obj.get_mut("messages").and_then(|m| m.as_array_mut()) {
        Some(arr) => arr,
        None => {
            obj.insert(
                "messages".to_string(),
                serde_json::json!([{"role": "user", "content": injection_text}]),
            );
            return true;
        }
    };
    messages.push(serde_json::json!({"role": "user", "content": injection_text}));

    true
}

fn build_injection_text(snippets: &[DocSnippet]) -> String {
    if snippets.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(
        "Anubis auto-injected reference: cached API symbols for libraries referenced in your context. \
         Use these signatures verbatim — they are extracted from the project's symbol cache. \
         If a symbol is missing, it may not exist in the cached version.\n\n",
    );

    for s in snippets {
        out.push_str(&s.text);
        out.push_str("\n\n");
    }

    out
}

// ──────────────────────────────────────────────────────────────────────
// High-level entry point
// ──────────────────────────────────────────────────────────────────────

/// Top-level orchestration: detect libraries in body, build snippets,
/// inject into request. Called by proxy_handler when
/// `cfg.scanner.auto_inject_docs` is true.
///
/// Doc resolution routes through [`crate::doc_provider::LocalSymbolCacheProvider`]
/// — the shared provider abstraction that the detective path
/// (`scanner::build_library_docs_fallback`) also consumes. P0 keeps
/// behavior identical to the inline `SymbolCache::open()` + `build_doc_snippets`
/// chain it replaces; P1+ swaps the concrete provider for a cascade
/// (cache → markdown → remote) without touching this function.
///
/// Returns true if the body was modified (caller re-serializes).
pub async fn maybe_inject_docs(
    body_json: &mut serde_json::Value,
    is_anthropic: bool,
    max_total_tokens: usize,
) -> bool {
    // ── Extract content from messages for library detection ────────────
    //
    // We deliberately scan ALL messages (system/user/assistant/tool) —
    // the conversation history often contains the relevant imports,
    // and a future tool call may reference libraries discussed earlier.
    let content = extract_message_content(body_json);
    if content.is_empty() {
        return false;
    }

    let libraries = detect_libraries(&content);
    if libraries.is_empty() {
        return false;
    }

    tracing::info!(
        target: "injection",
        count = libraries.len(),
        libs = ?libraries.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
        "auto-inject: detected libraries"
    );

    // ── Open provider, fetch snippets ──────────────────────────────────
    //
    // Provider trait lets the cascade (P1) slot in markdown + remote
    // sources without changing this call site. For P0 the concrete impl
    // is LocalSymbolCacheProvider, which is byte-for-byte equivalent to
    // the prior inline SymbolCache::open() + build_doc_snippets() chain.
    let provider = match crate::doc_provider::LocalSymbolCacheProvider::open() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "injection",
                error = %e,
                "auto-inject: doc provider open failed, skipping injection"
            );
            return false;
        }
    };

    use crate::doc_provider::{DocProvider, Focus, TokenBudget};

    let snippets = provider
        .snippets(
            &libraries,
            TokenBudget(max_total_tokens),
            Focus::TopLevelAPI,
        )
        .await;

    if snippets.is_empty() {
        tracing::info!(
            target: "injection",
            libs = ?libraries.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(),
            "auto-inject: no cached symbols found for detected libraries"
        );
        return false;
    }

    tracing::info!(
        target: "injection",
        count = snippets.len(),
        libs = ?snippets.iter().map(|s| s.library.as_str()).collect::<Vec<_>>(),
        total_tokens = snippets.iter().map(|s| s.estimated_tokens).sum::<usize>(),
        "auto-inject: injecting doc snippets"
    );

    inject_into_request(body_json, &snippets, is_anthropic)
}

// ──────────────────────────────────────────────────────────────────────
// Cold-cache detection + one-shot system notice injection
// ──────────────────────────────────────────────────────────────────────

static COLD_CACHE_WARNED: AtomicBool = AtomicBool::new(false);

/// Check whether the symbol cache is cold (empty or inaccessible).
/// When cold, detection quality degrades: namespace import verification
/// can't fuzzy-match, auto-doc injection can't provide reference, and
/// GDScript extends verification lacks Godot XML docs.
pub fn is_cache_cold() -> bool {
    match SymbolCache::open() {
        Ok(c) => c.count().unwrap_or(0) == 0,
        Err(_) => true,
    }
}

/// Inject a one-shot cold-cache notice into the FIRST LLM request per process.
/// Tells the user (via the AI agent seeing the system message) how to fix it.
/// Returns true if a message was injected, false if already warned or injection failed.
pub fn inject_cold_cache_notice(
    body_json: &mut serde_json::Value,
    is_anthropic: bool,
) -> bool {
    if COLD_CACHE_WARNED.swap(true, Ordering::SeqCst) {
        return false;
    }

    let content = extract_message_content(body_json);
    let libraries = detect_libraries(&content);
    let has_gdscript = libraries.iter().any(|l| l.language == "gdscript");

    let mut msg = String::from(
        "[Anubis] Symbol cache is cold. Hallucination detection is running in degraded mode \
         — method verification, namespace import checks, and API doc injection are limited.\n",
    );
    msg.push_str(
        "Run `anubis symbols fetch` in your project directory to fetch dependency symbols.\n",
    );
    if has_gdscript {
        msg.push_str(
            "For Godot/GDScript, also run `anubis symbols add godot` to fetch engine class documentation.\n",
        );
    }

    inject_plain_system_message(body_json, &msg, is_anthropic)
}

/// Inject a plain-text system message into the request body (OpenAI or Anthropic format).
fn inject_plain_system_message(
    body_json: &mut serde_json::Value,
    text: &str,
    is_anthropic: bool,
) -> bool {
    let obj = match body_json.as_object_mut() {
        Some(o) => o,
        None => return false,
    };

    if is_anthropic {
        if let Some(existing) = obj.get_mut("system") {
            match existing {
                serde_json::Value::String(s) => {
                    let mut combined = text.to_string();
                    combined.push_str("\n\n");
                    combined.push_str(s);
                    *existing = serde_json::Value::String(combined);
                }
                serde_json::Value::Array(arr) => {
                    arr.insert(0, serde_json::json!({"type": "text", "text": text}));
                }
                _ => {
                    *existing = serde_json::Value::String(text.to_string());
                }
            }
        } else {
            obj.insert("system".to_string(), serde_json::Value::String(text.to_string()));
        }
    } else {
        let messages = match obj.get_mut("messages").and_then(|m| m.as_array_mut()) {
            Some(arr) => arr,
            None => {
                obj.insert(
                    "messages".to_string(),
                    serde_json::json!([{"role": "system", "content": text}]),
                );
                return true;
            }
        };

        let first_is_system = messages
            .first()
            .and_then(|m| m.get("role"))
            .and_then(|r| r.as_str())
            .map(|r| r == "system")
            .unwrap_or(false);

        if first_is_system {
            if let Some(content) = messages.get_mut(0).and_then(|m| m.get_mut("content")) {
                match content {
                    serde_json::Value::String(s) => {
                        let mut combined = text.to_string();
                        combined.push_str("\n\n");
                        combined.push_str(s);
                        *content = serde_json::Value::String(combined);
                    }
                    serde_json::Value::Array(arr) => {
                        arr.insert(0, serde_json::json!({"type": "text", "text": text}));
                    }
                    _ => {
                        *content = serde_json::Value::String(text.to_string());
                    }
                }
            }
        } else {
            messages.insert(0, serde_json::json!({"role": "system", "content": text}));
        }
    }

    true
}

/// Concatenate all text content from a request body's messages.
/// Handles both OpenAI and Anthropic message formats.
fn extract_message_content(body_json: &serde_json::Value) -> String {
    let mut out = String::new();

    // OpenAI: messages: [{role, content: string | array}]
    if let Some(messages) = body_json.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            append_message_content(&mut out, msg);
        }
    }

    // Anthropic top-level system field
    if let Some(system) = body_json.get("system") {
        append_anthropic_system(&mut out, system);
    }

    out
}

fn append_message_content(out: &mut String, msg: &serde_json::Value) {
    let content = match msg.get("content") {
        Some(c) => c,
        None => return,
    };

    match content {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        serde_json::Value::Array(arr) => {
            for block in arr {
                if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                    out.push_str(text);
                    out.push('\n');
                }
                // Anthropic tool_use blocks include input JSON which may
                // reference files/code worth scanning.
                if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    if let Some(input) = block.get("input") {
                        let serialized = serde_json::to_string(input).unwrap_or_default();
                        out.push_str(&serialized);
                        out.push('\n');
                    }
                }
                // OpenAI tool calls
                if let Some(tool) = block.get("function") {
                    if let Some(args) = tool.get("arguments").and_then(|a| a.as_str()) {
                        out.push_str(args);
                        out.push('\n');
                    }
                }
            }
        }
        _ => {}
    }
}

fn append_anthropic_system(out: &mut String, system: &serde_json::Value) {
    match system {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        serde_json::Value::Array(arr) => {
            for block in arr {
                if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                    out.push_str(text);
                    out.push('\n');
                }
            }
        }
        _ => {}
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Library detection ─────────────────────────────────────────────

    #[test]
    fn detect_python_import() {
        let libs = detect_libraries("import numpy as np\nimport pandas");
        assert!(libs.iter().any(|l| l.name == "numpy" && l.language == "python"));
        assert!(libs.iter().any(|l| l.name == "pandas" && l.language == "python"));
    }

    #[test]
    fn detect_python_from_import() {
        let libs = detect_libraries("from pandas import DataFrame\nfrom package.module import thing");
        assert!(libs.iter().any(|l| l.name == "pandas"));
        assert!(libs.iter().any(|l| l.name == "package"));
    }

    #[test]
    fn detect_python_skips_stdlib() {
        let libs = detect_libraries("import os\nimport sys\nfrom typing import List\nimport json");
        assert!(libs.is_empty(), "stdlib should be skipped, got {:?}", libs);
    }

    #[test]
    fn detect_python_dedupes() {
        let libs = detect_libraries("import numpy\nimport numpy as np\nfrom numpy import array");
        let numpy_count = libs.iter().filter(|l| l.name == "numpy").count();
        assert_eq!(numpy_count, 1, "should dedupe, got {:?}", libs);
    }

    #[test]
    fn detect_ts_from_import() {
        let libs = detect_libraries("import React from 'react';\nimport { useState } from 'react';");
        assert!(libs.iter().any(|l| l.name == "react" && l.language == "ts"));
    }

    #[test]
    fn detect_ts_require() {
        let libs = detect_libraries("const express = require('express');");
        assert!(libs.iter().any(|l| l.name == "express"));
    }

    #[test]
    fn detect_ts_scoped_package() {
        let libs = detect_libraries("import { x } from '@babel/core';");
        // @babel/core normalizes to "core" (the package name after scope)
        assert!(
            libs.iter().any(|l| l.name == "core"),
            "scoped name should be extracted, got {:?}",
            libs
        );
    }

    #[test]
    fn detect_ts_skips_node_builtins() {
        let libs = detect_libraries("import fs from 'fs';\nimport path from 'path';\nconst http = require('http');");
        assert!(libs.is_empty(), "node builtins should be skipped, got {:?}", libs);
    }

    #[test]
    fn detect_rust_use() {
        let libs = detect_libraries("use serde::Serialize;\nuse tokio::sync::Mutex;");
        assert!(libs.iter().any(|l| l.name == "serde" && l.language == "rust"));
        assert!(libs.iter().any(|l| l.name == "tokio"));
    }

    #[test]
    fn detect_rust_skips_std() {
        let libs = detect_libraries("use std::collections::HashMap;\nuse std::path::PathBuf;");
        assert!(libs.is_empty(), "std should be skipped, got {:?}", libs);
    }

    #[test]
    fn detect_rust_extern_crate() {
        let libs = detect_libraries("extern crate regex;");
        assert!(libs.iter().any(|l| l.name == "regex"));
    }

    #[test]
    fn detect_go_imports() {
        let content = r#"
package main

import (
    "fmt"
    "github.com/user/repo"
    "github.com/sirupsen/logrus"
)

func main() {}
"#;
        let libs = detect_libraries(content);
        // fmt is stdlib, should be skipped
        // github.com/user/repo → "repo"
        // github.com/sirupsen/logrus → "logrus"
        assert!(libs.iter().any(|l| l.name == "repo"), "got {:?}", libs);
        assert!(libs.iter().any(|l| l.name == "logrus"), "got {:?}", libs);
        assert!(!libs.iter().any(|l| l.name == "fmt"), "stdlib should be skipped");
    }

    #[test]
    fn detect_go_skips_stdlib() {
        let content = r#"
package main

import (
    "fmt"
    "os"
    "strings"
)

func main() {}
"#;
        let libs = detect_libraries(content);
        assert!(libs.is_empty(), "go stdlib should be skipped, got {:?}", libs);
    }

    #[test]
    fn detect_cpp_third_party_includes() {
        let libs = detect_libraries(
            "#include <boost/asio.hpp>\n#include <opencv2/core.hpp>\n#include <stdio.h>"
        );
        assert!(libs.iter().any(|l| l.name == "boost"));
        assert!(libs.iter().any(|l| l.name == "opencv2"));
        // stdio.h is plain (no subdir) — skipped
        assert!(!libs.iter().any(|l| l.name == "stdio.h"));
    }

    #[test]
    fn detect_csharp_using() {
        let libs = detect_libraries("using Newtonsoft.Json;\nusing System.IO;");
        assert!(libs.iter().any(|l| l.name == "Newtonsoft"));
        // System.* is BCL, should be skipped
        assert!(!libs.iter().any(|l| l.name == "System"));
    }

    #[test]
    fn detect_java_imports() {
        let libs = detect_libraries(
            "import com.google.common.collect.Lists;\nimport java.util.List;"
        );
        assert!(libs.iter().any(|l| l.name == "com.google.common.collect.Lists"));
        // java.* is stdlib
        assert!(!libs.iter().any(|l| l.name == "java.util.List"));
    }

    #[test]
    fn detect_gdscript_extends() {
        let libs = detect_libraries("extends Node2D\nfunc _ready(): pass");
        assert!(libs.iter().any(|l| l.name == "godot" && l.language == "gdscript"));
    }

    #[test]
    fn detect_mixed_languages() {
        let content = r#"
import numpy as np
from pandas import DataFrame
use serde::Serialize;
import React from 'react';
"#;
        let libs = detect_libraries(content);
        let names: Vec<_> = libs.iter().map(|l| l.name.as_str()).collect();
        assert!(names.contains(&"numpy"));
        assert!(names.contains(&"pandas"));
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"react"));
    }

    // ── Normalization ──────────────────────────────────────────────────

    #[test]
    fn normalize_python_dotted() {
        assert_eq!(normalize_library_name("pandas.DataFrame", "python"), "pandas");
        assert_eq!(normalize_library_name("package.sub.module", "python"), "package");
    }

    #[test]
    fn normalize_ts_scoped() {
        // @babel/core normalizes to "core" (package name after scope)
        // since the symbol cache stores under the short package name
        assert_eq!(normalize_library_name("@babel/core", "ts"), "core");
        assert_eq!(normalize_library_name("@scope/pkg/sub", "ts"), "pkg");
        assert_eq!(normalize_library_name("react", "ts"), "react");
    }

    #[test]
    fn normalize_rust_path() {
        assert_eq!(normalize_library_name("tokio::sync::Mutex", "rust"), "tokio");
        assert_eq!(normalize_library_name("serde::Serialize", "rust"), "serde");
    }

    #[test]
    fn normalize_go_full_path() {
        assert_eq!(normalize_library_name("github.com/user/repo", "go"), "repo");
        assert_eq!(normalize_library_name("github.com/user/repo/v2", "go"), "repo");
        assert_eq!(normalize_library_name("github.com/user/repo/v2/sub", "go"), "sub");
    }

    #[test]
    fn normalize_cpp_subdir() {
        assert_eq!(normalize_library_name("boost/asio.hpp", "cpp"), "boost");
        assert_eq!(normalize_library_name("opencv2/core.hpp", "cpp"), "opencv2");
    }

    // ── extract_param_list ─────────────────────────────────────────────

    #[test]
    fn extract_params_from_rust_sig() {
        assert_eq!(extract_param_list("fn foo(a: i32, b: &str) -> bool"), "(a, b)");
    }

    #[test]
    fn extract_params_from_python_sig() {
        assert_eq!(extract_param_list("foo(x, y=10, **kwargs)"), "(x, y, kwargs)");
    }

    #[test]
    fn extract_params_no_parens() {
        assert_eq!(extract_param_list("X"), "()");
    }

    #[test]
    fn extract_params_empty() {
        assert_eq!(extract_param_list("fn foo()"), "()");
    }

    #[test]
    fn extract_params_nested_call() {
        // Nested calls: bar(b, c) should be collapsed to just "bar"
        // (we only extract the outermost param names, not inner expressions)
        assert_eq!(
            extract_param_list("foo(a, bar(b, c), d)"),
            "(a, bar(b, c), d)"
        );
    }

    // ── Injection (Method 3: user-append at END of messages array) ─────

    #[test]
    fn inject_appends_user_message_at_end() {
        let mut body = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        });
        let snippets = vec![DocSnippet {
            library: "numpy".to_string(),
            version: Some("1.24".to_string()),
            text: "# numpy\n\n- `array(source)`".to_string(),
            estimated_tokens: 10,
        }];
        let modified = inject_into_request(&mut body, &snippets, false);
        assert!(modified);
        let messages = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 2); // one new user message added
        assert_eq!(messages[1].get("role").unwrap().as_str(), Some("user"));
        assert!(messages[1].get("content").unwrap().as_str().unwrap().contains("numpy"));
    }

    #[test]
    fn inject_preserves_existing_system_message() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "system", "content": "you are helpful"},
                {"role": "user", "content": "hello"}
            ]
        });
        let snippets = vec![DocSnippet {
            library: "numpy".to_string(),
            version: None,
            text: "# numpy\n- array".to_string(),
            estimated_tokens: 5,
        }];
        let modified = inject_into_request(&mut body, &snippets, false);
        assert!(modified);
        let messages = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 3); // system + user + new injected user
        // System message UNCHANGED (cache preserved)
        let sys_content = messages[0].get("content").unwrap().as_str().unwrap();
        assert_eq!(sys_content, "you are helpful");
        // Injection is LAST message (end position for recency attention)
        assert_eq!(messages[2].get("role").unwrap().as_str(), Some("user"));
        assert!(messages[2].get("content").unwrap().as_str().unwrap().contains("numpy"));
    }

    #[test]
    fn inject_anthropic_preserves_system_field() {
        let mut body = serde_json::json!({
            "model": "claude-3",
            "system": "you are helpful",
            "messages": [
                {"role": "user", "content": "hi"}
            ]
        });
        let snippets = vec![DocSnippet {
            library: "numpy".to_string(),
            version: None,
            text: "# numpy".to_string(),
            estimated_tokens: 5,
        }];
        let modified = inject_into_request(&mut body, &snippets, true);
        assert!(modified);
        // System field UNCHANGED (cache preserved)
        let system = body.get("system").unwrap().as_str().unwrap();
        assert_eq!(system, "you are helpful");
        // Injection appended to messages array as user role
        let messages = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1].get("role").unwrap().as_str(), Some("user"));
        assert!(messages[1].get("content").unwrap().as_str().unwrap().contains("numpy"));
    }

    #[test]
    fn inject_anthropic_no_system_appends_user() {
        let mut body = serde_json::json!({
            "model": "claude-3",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let snippets = vec![DocSnippet {
            library: "numpy".to_string(),
            version: None,
            text: "# numpy".to_string(),
            estimated_tokens: 5,
        }];
        let modified = inject_into_request(&mut body, &snippets, true);
        assert!(modified);
        // No system field created
        assert!(body.get("system").is_none());
        let messages = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1].get("role").unwrap().as_str(), Some("user"));
    }

    #[test]
    fn inject_no_snippets_returns_false() {
        let mut body = serde_json::json!({"messages": []});
        let modified = inject_into_request(&mut body, &[], false);
        assert!(!modified);
    }

    #[test]
    fn inject_array_system_message_preserved() {
        let mut body = serde_json::json!({
            "messages": [
                {"role": "system", "content": [{"type": "text", "text": "you are helpful"}]},
                {"role": "user", "content": "hi"}
            ]
        });
        let snippets = vec![DocSnippet {
            library: "numpy".to_string(),
            version: None,
            text: "# numpy".to_string(),
            estimated_tokens: 5,
        }];
        let modified = inject_into_request(&mut body, &snippets, false);
        assert!(modified);
        let messages = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 3);
        // Array system message UNCHANGED
        let sys_content = messages[0].get("content").unwrap().as_array().unwrap();
        assert_eq!(sys_content.len(), 1); // original only, no insertion
        // Injection at END
        assert_eq!(messages[2].get("role").unwrap().as_str(), Some("user"));
        assert!(messages[2].get("content").unwrap().as_str().unwrap().contains("numpy"));
    }

    // ── extract_message_content ────────────────────────────────────────

    #[test]
    fn extract_content_from_openai_messages() {
        let body = serde_json::json!({
            "messages": [
                {"role": "system", "content": "import numpy"},
                {"role": "user", "content": "use pandas"},
            ]
        });
        let content = extract_message_content(&body);
        assert!(content.contains("numpy"));
        assert!(content.contains("pandas"));
    }

    #[test]
    fn extract_content_from_anthropic_system_field() {
        let body = serde_json::json!({
            "system": "use tokio",
            "messages": [{"role": "user", "content": "hi"}]
        });
        let content = extract_message_content(&body);
        assert!(content.contains("tokio"));
    }

    #[test]
    fn extract_content_from_array_content_blocks() {
        let body = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "use serde"},
                    {"type": "text", "text": "use tokio"}
                ]
            }]
        });
        let content = extract_message_content(&body);
        assert!(content.contains("serde"));
        assert!(content.contains("tokio"));
    }

    #[test]
    fn extract_content_from_tool_use_blocks() {
        let body = serde_json::json!({
            "messages": [{
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "input": {"file": "main.py", "code": "import numpy"}
                }]
            }]
        });
        let content = extract_message_content(&body);
        assert!(content.contains("numpy"));
    }

    // ── prioritize_symbols ─────────────────────────────────────────────
    //
    // Symbol struct requires many fields; verify the ordering logic in
    // isolation by constructing minimal stubs.

    #[test]
    fn prioritize_caps_at_max() {
        use crate::symbols::types::SymbolKind;
        let mk = |name: &str, kind: SymbolKind| {
            let mut s = Symbol::new("test", "1.0", name);
            s.kind = kind;
            s
        };
        let symbols = vec![
            mk("a", SymbolKind::Function),
            mk("b", SymbolKind::Function),
            mk("c", SymbolKind::Function),
            mk("d", SymbolKind::Method),
            mk("e", SymbolKind::Method),
        ];
        let out = prioritize_symbols(&symbols, 3);
        assert_eq!(out.len(), 3);
        // Functions first
        assert_eq!(out[0].name, "a");
        assert_eq!(out[1].name, "b");
        assert_eq!(out[2].name, "c");
    }

    #[test]
    fn prioritize_functions_before_methods() {
        use crate::symbols::types::SymbolKind;
        let mk = |name: &str, kind: SymbolKind| {
            let mut s = Symbol::new("test", "1.0", name);
            s.kind = kind;
            s
        };
        let symbols = vec![
            mk("method1", SymbolKind::Method),
            mk("func1", SymbolKind::Function),
            mk("method2", SymbolKind::Method),
        ];
        let out = prioritize_symbols(&symbols, 10);
        assert_eq!(out.len(), 3);
        // Function comes first even though it's in the middle of the input
        assert_eq!(out[0].name, "func1");
    }
}
