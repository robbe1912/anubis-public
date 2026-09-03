//! Generic scope-based undefined-variable extraction.
//!
//! Shared driver for the regex-based FORGE extractors (C++, C#, Java).
//! Each language implements [`ScopeExtractor`] to plug in its keyword list,
//! identifier pattern, and per-language quirks (string stripping, qualified
//! access rules, parameter normalization). Tree-sitter/AST-based extractors
//! (Rust, Python, TS, Go, GDScript) follow a different pattern and are not
//! unified here.
//!
//! See council #3 finding #9.

use crate::scanner::string_filters::{filter_function_calls, strip_c_style_string_literals};

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Per-language scope extraction logic. Each regex-based language implements
/// this to plug into the shared [`extract_undefined`] driver.
pub trait ScopeExtractor {
    /// Keywords/builtins excluded from the "referenced" set.
    fn keywords(&self) -> &'static Lazy<HashSet<&'static str>>;

    /// Identifier regex; capture group 1 is the identifier itself.
    fn ident_regex(&self) -> &'static Lazy<Regex>;

    /// Additional declaration regexes (beyond the shared DECL_RE + PARAMS_RE).
    /// Each pattern's capture group 1 is the declared name.
    fn decl_regexes(&self) -> &'static [&'static Lazy<Regex>] {
        &[]
    }

    /// Strip C-style string literals before scanning identifiers.
    fn strip_strings(&self) -> bool {
        false
    }

    /// Return true if the identifier at `match_start` should be skipped
    /// (e.g. property access via `.`, namespace qualifier via `::`, or a
    /// qualified suffix following an alphanumeric byte).
    fn skip_match(&self, content: &str, match_start: usize) -> bool;

    /// Extract the declared name from a parameter's whitespace-split tokens,
    /// or `None` if this isn't a parameter binding.
    fn collect_param(&self, parts: &[&str]) -> Option<String>;
}

// Shared declaration regexes — identical patterns were duplicated across all
// three regex-based extractors.
static DECL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:\w+)\s+(\w+)\s*[=;]").unwrap()
});
static PARAMS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\(([^)]*)\)").unwrap()
});

/// Generic undefined-variable extraction. Mirrors the previous per-language
/// `extract_*_undefined_variables` functions: collect declared names
/// (declarations, params, language-specific extras), collect referenced names
/// (identifiers minus keywords and qualified accesses), return the difference
/// filtered through `filter_function_calls`.
pub fn extract_undefined<E: ScopeExtractor>(content: &str, extractor: &E) -> Vec<String> {
    let keywords = extractor.keywords();
    let mut defined: HashSet<String> = HashSet::new();
    let mut referenced: HashSet<String> = HashSet::new();

    for caps in DECL_RE.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            defined.insert(m.as_str().to_string());
        }
    }
    for re in extractor.decl_regexes() {
        for caps in re.captures_iter(content) {
            if let Some(m) = caps.get(1) {
                defined.insert(m.as_str().to_string());
            }
        }
    }
    for caps in PARAMS_RE.captures_iter(content) {
        if let Some(p) = caps.get(1) {
            for param in p.as_str().split(',') {
                let parts: Vec<&str> = param.trim().split_whitespace().collect();
                if let Some(name) = extractor.collect_param(&parts) {
                    defined.insert(name);
                }
            }
        }
    }

    let stripped;
    let scan_str: &str = if extractor.strip_strings() {
        stripped = strip_c_style_string_literals(content);
        &stripped
    } else {
        content
    };

    let ident_re = extractor.ident_regex();
    for caps in ident_re.captures_iter(scan_str) {
        if let Some(m) = caps.get(1) {
            let start = m.start();
            if extractor.skip_match(scan_str, start) {
                continue;
            }
            let name = m.as_str();
            if !keywords.contains(name) && name.len() >= 2 && !name.chars().all(|c| c.is_ascii_digit()) {
                referenced.insert(name.to_string());
            }
        }
    }

    let mut undefined: Vec<String> = referenced.difference(&defined).cloned().collect();
    undefined = filter_function_calls(content, undefined);
    undefined.sort();
    undefined
}
