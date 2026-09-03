//! Go FORGE runner — extracted from forge_pipeline.rs (M1 chunk 7).
//!
//! Verifies Go source for:
//!   1. Module imports — Go proxy lookup (requires domain in first segment)
//!   2. Undefined variables — tree-sitter AST (`go_ast_extractor`)
//!   3. Method calls — receiver map + Go doc introspection
//!   4. Bare function calls — no receiver (e.g. `WrapPointer(...)`)
//!   5. Parameter arity — flag 0-arg methods called with extra args
//!
//! Regex-based scope checker (`extract_go_undefined_variables`) kept as
//! historical reference; the production path uses the tree-sitter AST
//! extractor in `go_ast_extractor.rs`.

use crate::scanner::arity::check_call_arity;
use crate::scanner::forge_types::ForgeResult;
use crate::scanner::package_index::ImportStatus;
use crate::scanner::string_filters::filter_function_calls;

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

// Static regex patterns for extract_go_undefined_variables
static VAR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bvar\s+(\w+)").unwrap());
static SHORT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w+)\s*:=").unwrap());
static FN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bfunc\s+(?:\([^)]*\)\s+)?(\w+)\s*\(([^)]*)\)").unwrap());
static TYPE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\btype\s+(\w+)\s+(?:struct|interface)").unwrap());
static FOR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bfor\s+(\w+)\s+:=\s+range\b").unwrap());
static REF_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([a-zA-Z_]\w*)\b").unwrap());

/// Go FORGE pipeline (partial implementation).
/// Verifies module imports + undefined variable detection.
pub(crate) async fn run_forge_go(content: &str) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();
    let terms = crate::scanner::extract_lookup_terms(content);
    result.claims_extracted = terms.len();
    for pkg in &terms {
        if pkg.starts_with('.') || pkg.starts_with('/') {
            continue;
        }
        // Skip JSON escape artifacts: trailing backslash from tool-call
        // content extraction (e.g. "internal/database\" → "database\").
        if pkg.ends_with('\\') || pkg.ends_with('"') {
            continue;
        }
        // Go modules ALWAYS have a domain in the first path segment
        // (e.g. github.com/..., golang.org/x/...). A bare name like
        // `semver` extracted as the last segment of `golang.org/x/mod/semver`
        // is NOT a valid module path — skip verification to avoid FP.
        // The full path was already verified separately.
        // Also skip prose words ending with dot (e.g. "block." from
        // "code block. Change the function...") — these are NOT domains.
        let first_seg = pkg.split('/').next().unwrap_or("");
        if !first_seg.contains('.')
            || first_seg.ends_with('.')
            || first_seg.len() < 5
        {
            continue;
        }
        let status = crate::scanner::package_index::verify_import_with_language("go", pkg).await;
        match status {
            ImportStatus::NotFound => {
                let mut msg = format!(
                    "hallucinated-import: `{}` — module not found in Go proxy",
                    pkg
                );
                if let Some(suggestion) = crate::scanner::package_index::suggest_correct_import(pkg) {
                    msg.push_str(&format!(" — did you mean `{}`?", suggestion));
                }
                result.warnings.push(msg);
                result.claims_hallucinated += 1;
            }
            ImportStatus::Verified => result.claims_verified += 1,
            _ => result.claims_unknown += 1,
        }
    }

    // Live API verification: fetch pkg.go.dev exports for each verified
    // import and cross-check `alias.Symbol` usages. Catches hallucinated
    // symbols on real packages (e.g. `term.StateRaw` when only `term.State`
    // exists). Source of truth = pkg.go.dev (constraint #8).
    let import_symbol_warnings =
        crate::scanner::go_introspect::verify_go_import_symbols(content).await;
    if !import_symbol_warnings.is_empty() {
        result.claims_extracted += import_symbol_warnings.len();
        result.claims_hallucinated += import_symbol_warnings
            .iter()
            .filter(|w| w.contains("hallucinated"))
            .count();
        result.warnings.extend(import_symbol_warnings);
    }

    // Undefined variable detection via tree-sitter AST (replaces regex).
    let undefined = crate::scanner::go_ast_extractor::extract_undefined_variables(content);
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

    // Method verification via go doc type introspection.
    let go_receiver_map = crate::scanner::go_introspect::build_go_receiver_map(content);
    if !go_receiver_map.is_empty() {
        let method_warnings = crate::scanner::go_introspect::verify_go_methods(content, &go_receiver_map).await;
        result.claims_extracted += method_warnings.len();
        result.claims_hallucinated += method_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(method_warnings);
    }

    // Bare function verification (WrapPointer, etc. — no receiver).
    let bare_warnings = crate::scanner::go_introspect::verify_go_bare_functions(content);
    if !bare_warnings.is_empty() {
        result.claims_extracted += bare_warnings.len();
        result.claims_hallucinated += bare_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(bare_warnings);
    }

    // Parameter arity check: flag calls to 0-arg methods with extra args.
    let arity_warnings = check_call_arity(content);
    if !arity_warnings.is_empty() {
        result.claims_extracted += arity_warnings.len();
        result.claims_hallucinated += arity_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(arity_warnings);
    }

    // go.sum hash fabrication check moved to scan_response (mod.rs) because
    // go.sum content often appears in non-Go code blocks (```text). Running
    // it at scan_response level catches ALL code blocks regardless of tag.

    result.latency_ms = start.elapsed().as_millis() as u64;
    result
}

/// Extract undefined variables from Go source via regex.
///
/// Historical regex scope checker. Superseded by the tree-sitter
/// implementation in `go_ast_extractor::extract_undefined_variables`,
/// which is what `run_forge_go` actually calls. Kept as a reference
/// of the regex approach for benchmarks and fallback.
fn extract_go_undefined_variables(content: &str) -> Vec<String> {
    static GO_KEYWORDS: Lazy<HashSet<&str>> = Lazy::new(|| {
        [
            "var", "func", "type", "struct", "interface", "for", "range", "if",
            "else", "switch", "case", "default", "break", "continue", "return",
            "go", "defer", "chan", "map", "package", "import", "true", "false",
            "nil", "iota", "make", "new", "len", "cap", "append", "copy", "delete",
            "panic", "recover", "print", "println", "close", "complex", "real",
            "imag", "error", "string", "int", "int8", "int16", "int32", "int64",
            "uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64",
            "bool", "byte", "rune", "uintptr", "select", "fallthrough", "goto",
            // Go 1.18+ generics alias.
            "any",
            // Common context names that aren't struct-field aware.
            "ctx", "err", "ok",
        ]
        .iter()
        .copied()
        .collect()
    });

    let mut defined: HashSet<String> = HashSet::new();
    let mut referenced: HashSet<String> = HashSet::new();

    // var X = ..., var X Type
    let var_re = &*VAR_RE;
    for caps in var_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // X := ... (short variable declaration)
    let short_re = &*SHORT_RE;
    for caps in short_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // func X(params) — name + params
    let fn_re = &*FN_RE;
    for caps in fn_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
        if let Some(params) = caps.get(2) {
            for param in params.as_str().split(',') {
                if let Some(name) = param.split(' ').next() {
                    let name = name.trim().trim_start_matches('*');
                    if !name.is_empty() && name.chars().next().map_or(false, |c| c.is_alphabetic()) {
                        defined.insert(name.to_string());
                    }
                }
            }
        }
    }

    // type X struct/interface
    let type_re = &*TYPE_RE;
    for caps in type_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // for X := range ...
    let for_re = &*FOR_RE;
    for caps in for_re.captures_iter(content) {
        if let Some(m) = caps.get(1) { defined.insert(m.as_str().to_string()); }
    }

    // Collect referenced identifiers (not after .)
    // Strip string literals first so words inside import paths like
    // "golang.org/x/mod/semver" don't get treated as referenced
    // identifiers (which would flag `mod`, `semver`, `x` as undefined).
    let stripped = strip_go_string_literals(content);
    let ref_re = &*REF_RE;
    for m in ref_re.find_iter(&stripped) {
        let name = m.as_str();
        let before_pos = m.start();
        if before_pos >= 1 {
            let before1 = stripped.as_bytes()[before_pos - 1];
            if before1 == b'.' { continue; }
        }
        referenced.insert(name.to_string());
    }

    let mut undefined: Vec<String> = referenced
        .iter()
        .filter(|n| !defined.contains(*n) && !GO_KEYWORDS.contains(n.as_str()))
        .filter(|n| n.len() >= 3)
        .cloned()
        .collect();
    undefined = filter_function_calls(content, undefined);
    undefined.sort();
    undefined
}

/// Replace Go string literals with empty space so the scope checker doesn't
/// treat words inside strings (e.g. import paths, error messages) as
/// referenced identifiers. Handles:
///   - Double-quoted interpreted strings: "..."
///   - Backtick raw strings: `...`
///   - Single-rune literals: 'x'
///   - Line comments: // ... (to end of line)
///   - Block comments: /* ... */
///
/// Preserves newlines so line/column math in downstream regexes still
/// produces sensible positions. The result is ONLY for scope scanning —
/// not for re-display to users.
fn strip_go_string_literals(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // Line comment — skip to end of line.
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        // Block comment — skip to */.
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' { out.push('\n'); } else { out.push(' '); }
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(' ');
                out.push(' ');
                i += 2;
            }
            continue;
        }
        // Raw string literal — backtick to backtick.
        if b == b'`' {
            out.push(' ');
            i += 1;
            while i < bytes.len() && bytes[i] != b'`' {
                if bytes[i] == b'\n' { out.push('\n'); } else { out.push(' '); }
                i += 1;
            }
            if i < bytes.len() { out.push(' '); i += 1; }
            continue;
        }
        // Double-quoted interpreted string. Handles \" escapes.
        if b == b'"' {
            out.push(' ');
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(' ');
                    if bytes[i + 1] == b'\n' { out.push('\n'); } else { out.push(' '); }
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' {
                    // Interpreted strings can't span raw newlines, but be safe.
                    break;
                }
                out.push(' ');
                i += 1;
            }
            if i < bytes.len() { out.push(' '); i += 1; }
            continue;
        }
        // Single-rune literal: 'x' or '\n' etc.
        if b == b'\'' {
            out.push(' ');
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(' '); out.push(' ');
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\n' { break; }
                out.push(' ');
                i += 1;
            }
            if i < bytes.len() { out.push(' '); i += 1; }
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// go.sum hash fabrication detection
// ---------------------------------------------------------------------------
//
// Benchmark miss (task-04-go-grpc): LLM generated a go.sum file with
// fabricated h1: hashes. Real go.sum hashes are SHA-256 of the module zip,
// encoded as 43 base64 chars + `=` padding. The benchmark's fabrication had
// two different modules (grpc, protobuf) sharing an identical 28-char hash
// suffix — statistically impossible for real hashes (~1/2^168).
//
// Detection (all deterministic, no network):
//   1. Parse `MODULE VERSION h1:HASH=` lines.
//   2. Length check: real h1: hashes are exactly 44 chars (43 + `=`).
//   3. Exact-duplicate hash across DIFFERENT modules → fabrication.
//   4. Shared suffix (≥20 chars) across different modules → fabrication.

static GOSUM_H1_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    // Matches: `MODULE VERSION h1:HASH=` (HASH is base64 + optional padding).
    // Multiline so ^/$ match line boundaries. Module can contain dots/dashes.
    regex::Regex::new(
        r#"(?m)^\s*([A-Za-z0-9][\w./-]+)\s+(\S+)\s+h1:([A-Za-z0-9+/]+={0,2})\s*$"#,
    )
    .unwrap()
});

const EXPECTED_H1_LEN: usize = 44; // 43 base64 chars + '='
const SUSPICIOUS_SUFFIX_LEN: usize = 20; // last N chars to compare for duplication

pub(crate) fn detect_gosum_hash_fabrication(content: &str) -> Vec<String> {
    let mut entries: Vec<(String, String)> = Vec::new(); // (module, hash)
    for caps in GOSUM_H1_RE.captures_iter(content) {
        let module = caps.get(1).map(|m| m.as_str().to_string());
        let hash = caps.get(3).map(|m| m.as_str().to_string());
        if let (Some(module), Some(hash)) = (module, hash) {
            entries.push((module, hash));
        }
    }
    if entries.len() < 2 {
        return Vec::new(); // need ≥2 entries to detect duplication
    }

    let mut warnings = Vec::new();

    // Check 1: wrong-length hashes.
    for (module, hash) in &entries {
        if hash.len() != EXPECTED_H1_LEN {
            warnings.push(format!(
                "gosum-hash-fabrication: `{}` h1 hash has wrong length {} (expected {} chars for SHA-256)",
                module,
                hash.len(),
                EXPECTED_H1_LEN
            ));
        }
    }

    // Check 2: exact-duplicate hash across different modules.
    use std::collections::HashMap;
    let mut by_hash: HashMap<&str, Vec<&str>> = HashMap::new();
    for (module, hash) in &entries {
        by_hash.entry(hash.as_str()).or_default().push(module.as_str());
    }
    for (hash, modules) in &by_hash {
        let unique: std::collections::HashSet<&&str> = modules.iter().collect();
        if unique.len() > 1 {
            warnings.push(format!(
                "gosum-hash-fabrication: identical h1 hash `{}` shared across different modules: {}",
                hash,
                modules.join(", ")
            ));
        }
    }

    // Check 3: shared long suffix across different modules.
    let mut by_suffix: HashMap<String, Vec<&str>> = HashMap::new();
    for (module, hash) in &entries {
        if hash.len() >= SUSPICIOUS_SUFFIX_LEN {
            let suffix = hash[hash.len() - SUSPICIOUS_SUFFIX_LEN..].to_string();
            by_suffix.entry(suffix).or_default().push(module.as_str());
        }
    }
    for (suffix, modules) in &by_suffix {
        let unique: std::collections::HashSet<&&str> = modules.iter().collect();
        if unique.len() > 1 {
            // Only flag if we haven't already flagged these modules via exact dup.
            let already_exact = by_hash.values().any(|mods| {
                let u: std::collections::HashSet<&&str> = mods.iter().collect();
                u.len() > 1 && modules.iter().all(|m| u.contains(m))
            });
            if !already_exact {
                warnings.push(format!(
                    "gosum-hash-fabrication: different modules share identical hash suffix `...{}` ({}-char overlap is statistically impossible for real SHA-256): {}",
                    suffix,
                    SUSPICIOUS_SUFFIX_LEN,
                    modules.join(", ")
                ));
            }
        }
    }

    warnings
}

#[cfg(test)]
mod gosum_hash_tests {
    use super::detect_gosum_hash_fabrication;

    #[test]
    fn benchmark_fabricated_suffix_flagged() {
        // Exact benchmark task-04-go-grpc pattern: two modules share suffix.
        let content = r#"
google.golang.org/grpc v1.43.0 h1:VnZvzQZqYR9J5L7pXlFyIYWUOeZCwP8NjKtDmZJ6kxg=
google.golang.org/protobuf v1.28.0 h1:3u0+4rVZvZqYR9J5L7pXlFyIYWUOeZCwP8NjKtDmZJ6kxg=
"#;
        let w = detect_gosum_hash_fabrication(content);
        assert!(
            w.iter().any(|x| x.contains("suffix")),
            "expected suffix-fabrication warning, got: {:?}",
            w
        );
    }

    #[test]
    fn exact_duplicate_hash_flagged() {
        let content = r#"
example.com/modA v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
example.com/modB v2.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
"#;
        let w = detect_gosum_hash_fabrication(content);
        assert!(
            w.iter().any(|x| x.contains("identical")),
            "expected exact-duplicate warning, got: {:?}",
            w
        );
    }

    #[test]
    fn wrong_length_hash_flagged() {
        let content = "example.com/mod v1.0.0 h1:short=";
        let w = detect_gosum_hash_fabrication(content);
        // Single entry → no duplication check, but length check may fire.
        // Actually single entry returns early. Use two entries.
        let content = r#"
example.com/modA v1.0.0 h1:short=
example.com/modB v1.0.0 h1:alsoshort=
"#;
        let w = detect_gosum_hash_fabrication(content);
        assert!(
            w.iter().any(|x| x.contains("wrong length")),
            "expected wrong-length warning, got: {:?}",
            w
        );
    }

    #[test]
    fn distinct_real_hashes_not_flagged() {
        // Exactly 44 chars (43 base64 + '='), distinct, no shared suffix.
        let content = r#"
google.golang.org/grpc v1.43.0 h1:abc1def2ghi3jkl4mno5pqr6stu7vwx8yz9ABC0DEF1=
google.golang.org/protobuf v1.28.0 h1:JKL3MNO4PQR5STU6VWX7YZ8abc9def0ghi1jkl2mno3=
"#;
        let w = detect_gosum_hash_fabrication(content);
        assert!(
            w.is_empty(),
            "distinct valid-length hashes should not be flagged, got: {:?}",
            w
        );
    }

    #[test]
    fn single_entry_not_flagged() {
        let content = "google.golang.org/grpc v1.43.0 h1:shortandinvalid=";
        let w = detect_gosum_hash_fabrication(content);
        assert!(w.is_empty(), "single entry should not be flagged, got: {:?}", w);
    }
}
