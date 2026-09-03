//! C++ introspection via symbol cache (no runtime introspection possible).
//!
//! C++ has no runtime reflection. We use the pre-populated symbol cache
//! (from symbol_bundle.jsonl + dynamic fetchers) to verify:
//!   1. `#include` headers against a known headers list
//!   2. method calls on typed receivers
//!   3. method calls on container elements (`vec[i].method()`)
//!   4. bare function calls against cached functions

use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

/// Map C++ receiver names to types from declarations.
/// Handles: `Type var;`, `Type var = ...`, `Type* var = ...`, `auto var = Type::...`,
/// and function parameters like `Type& var,` / `Type var)`.
pub fn build_cpp_receiver_map(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // Type var = ...  / Type var;  (handles namespace::type like arma::mat, std::vector)
    let decl_re = Regex::new(
        r"\b(\w+::[A-Za-z_]\w*|[A-Z]\w*)\s+(\*?\w+)\s*[=;]"
    ).unwrap();
    for caps in decl_re.captures_iter(content) {
        let type_name = caps.get(1).unwrap().as_str().to_string();
        let raw_receiver = caps.get(2).unwrap().as_str();
        let receiver = raw_receiver.trim_start_matches('*').to_string();
        if receiver.len() > 1 && !is_cpp_keyword(&type_name) {
            map.insert(receiver, type_name);
        }
    }

    // Function parameters: `Type& var,` or `Type var,` or `Type& var)` or `Type var)`.
    // Skips entries already declared via `decl_re`. Catches params inside
    // function signatures like `void Func(arma::cube& upstreamGradient, int n)`.
    let param_re = Regex::new(
        r"\b(\w+::[A-Za-z_]\w*|[A-Z][a-zA-Z_]\w*)\s*&?\s*(\w+)\s*[,)]"
    ).unwrap();
    for caps in param_re.captures_iter(content) {
        let type_name = caps.get(1).unwrap().as_str().to_string();
        let receiver = caps.get(2).unwrap().as_str().to_string();
        if receiver.len() <= 1 || is_cpp_keyword(&type_name) { continue; }
        if map.contains_key(&receiver) { continue; }
        // Skip numeric receivers (matches like `5)` from `arma::vec(5)`).
        if receiver.chars().all(|c| c.is_ascii_digit()) { continue; }
        // Skip C++ primitive-ish type names that shouldn't bind a receiver.
        const PRIMITIVES: &[&str] = &[
            "Int", "Uint", "Float", "Double", "Bool", "Char", "Byte",
            "Short", "Long", "Size", "Void",
        ];
        if PRIMITIVES.contains(&type_name.as_str()) { continue; }
        map.insert(receiver, type_name);
    }

    // auto var = Namespace::Type::method() — infer type from constructor
    let auto_re = Regex::new(
        r"\bauto\s+(\w+)\s*=\s*(\w+)::"
    ).unwrap();
    for caps in auto_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let type_name = caps.get(2).unwrap().as_str().to_string();
        map.insert(receiver, type_name);
    }

    map
}

/// Map container variable names to their element types.
///
/// Parses STL container declarations to recover the inner type so we can
/// verify methods on `container[idx].method()` chains.
///
/// Handles:
///   - `std::vector<Type> name`
///   - `std::vector<ns::Type> name`
///   - `std::list<Type> name`, `std::deque<Type> name`, `std::set<Type> name`
///   - `std::shared_ptr<Type> name`, `std::unique_ptr<Type> name`
///   - Also without `std::` prefix: `vector<Type> name`
///
/// Returns a map: container_name → element_type_name (without template params
/// or namespaces — e.g. `arma::cube` → `cube`).
pub fn build_cpp_container_map(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    // Match container declarations. Greedy match inside <> to handle
    // nested templates like vector<vector<int>>.
    let container_re = Regex::new(
        r"\b(?:std::)?(?:vector|list|deque|set|unordered_set|map|unordered_map|shared_ptr|unique_ptr|weak_ptr)\s*<\s*([\w:]+)\s*>\s+(\w+)\s*[=;\(\{]"
    ).unwrap();
    for caps in container_re.captures_iter(content) {
        let full_type = caps.get(1).unwrap().as_str();
        let container = caps.get(2).unwrap().as_str().to_string();
        // Strip namespace: "arma::cube" → "cube".
        let element_type = full_type.rsplit("::").next().unwrap_or(full_type).to_string();
        if container.len() > 1 && element_type.len() > 1 {
            map.insert(container, element_type);
        }
    }
    map
}

fn is_cpp_keyword(s: &str) -> bool {
    matches!(s, "If" | "For" | "While" | "Switch" | "Return" | "Class"
        | "Struct" | "Enum" | "Namespace" | "Template" | "Typedef"
        | "Using" | "Public" | "Private" | "Protected" | "Virtual"
        | "Override" | "Static" | "Const" | "Mutable" | "Inline"
        | "Explicit" | "Friend" | "Operator" | "New" | "Delete"
        | "This" | "True" | "False" | "Null" | "Sizeof")
}

/// Verify C++ method calls against the symbol cache.
/// Uses crate::symbols::cache::SymbolCache for type + method lookups.
///
/// Handles three receiver patterns:
///   - direct: `receiver.method()` where `receiver` is in `receiver_map`
///   - subscript: `container[idx].method()` and `container.at(idx).method()`
///     where `container` is in `container_map`
///   - chained: `receiver.method1().method2()` where method1's return_type
///     is tracked through the chain (e.g. `cube.slice(0).row(0)` — slice
///     returns mat, row is checked against mat's methods)
pub async fn verify_cpp_methods(
    content: &str,
    receiver_map: &HashMap<String, String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if receiver_map.is_empty() {
        return warnings;
    }

    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return warnings,
    };

    let container_map = build_cpp_container_map(content);

    // Build a return-type lookup from cached method symbols.
    // Key: "TypeName.method_name" → return_type (stripped of &, *, const).
    // Used to traverse chains like `cube.slice().row()`.
    let mut return_type_map: HashMap<String, String> = HashMap::new();
    for (lib, _ver, _count) in cache.list_libraries() {
        // Limit scan to cpp. libraries to avoid blowing up on every fetch.
        if !lib.starts_with("cpp.") { continue; }
        // We can't iterate all symbols cheaply, so iterate types we care about
        // (those in the receiver_map values and container_map values).
    }
    let relevant_types: HashSet<String> = receiver_map.values()
        .map(|v| v.rsplit("::").next().unwrap_or(v).to_string())
        .chain(container_map.values().cloned())
        .collect();
    for type_name in &relevant_types {
        let type_syms = cache.lookup_global(type_name);
        for sym in &type_syms {
            let prefix = format!("{}.", type_name);
            for m in cache.lookup_prefix(&sym.library, &prefix) {
                if let Some(rt) = &m.return_type {
                    let cleaned = clean_cpp_type(rt);
                    if cleaned.is_empty() { continue; }
                    // Extract the bare method name from the path. Bundle
                    // entries for methods sometimes store the full dotted
                    // path in `name` (e.g. "cube.slice") — taking the last
                    // segment normalises to "slice".
                    let method_name = m.path.rsplit('.').next().unwrap_or(&m.path);
                    return_type_map.insert(
                        format!("{}.{}", type_name, method_name),
                        cleaned,
                    );
                }
            }
        }
    }

    // Direct: receiver.method(
    let method_re = Regex::new(
        r"(?:^|[^a-zA-Z0-9_>])(\w+)\.(\w+)\s*\("
    ).unwrap();

    // Subscript: container[idx].method(  OR  container.at(idx).method(
    // The `[^.]*?\]` consumes the bracket expression without crossing a dot.
    let subscript_re = Regex::new(
        r"(?:^|[^a-zA-Z0-9_>])(\w+)(?:\[[^\]]*\]|\.at\([^)]*\))\.(\w+)\s*\("
    ).unwrap();

    // Chained: receiver.method1(...).method2(
    // Catches `cube.slice(0).fetchElement(r,c)` and similar.
    // Receiver resolves through chain: receiver_type → method1.return_type →
    // verify method2 against that.
    let chain_re = Regex::new(
        r"(?:^|[^a-zA-Z0-9_>])(\w+)\.(\w+)\s*\([^)]*\)\.(\w+)\s*\("
    ).unwrap();

    let mut checked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    // Track receivers already handled by subscript / chain patterns so the
    // direct-pattern pass doesn't double-report.
    let mut handled_receivers: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Chain pass: receiver.method1(...).method2(
    for caps in chain_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method1 = caps.get(2).unwrap().as_str().to_string();
        let method2 = caps.get(3).unwrap().as_str().to_string();
        // Don't mark receiver as handled globally — only for this specific
        // method2 lookup. Other .methodX calls on same receiver still get
        // checked by the direct pass.

        // Resolve receiver type. Try direct receiver_map first, then
        // container_map (for `container[idx].slice().row()` patterns where
        // the subscript precedes the chain — but chain_re only matches
        // word.method1 so subscript patterns aren't caught here).
        let type_name = if let Some(t) = receiver_map.get(&receiver) {
            t.rsplit("::").next().unwrap_or(t).to_string()
        } else if let Some(t) = container_map.get(&receiver) {
            t.clone()
        } else {
            continue;
        };

        // Look up method1's return type.
        let rt_key = format!("{}.{}", type_name, method1);
        let return_type = match return_type_map.get(&rt_key) {
            Some(rt) => rt.clone(),
            None => continue,  // Can't verify — method1 unknown.
        };

        if !checked.insert((format!("{}::{}", receiver, method1), method2.clone())) {
            continue;
        }

        if let Some(w) = check_method_against_type(&cache, &format!("{}.{}()", receiver, method1), &method2, &return_type) {
            warnings.push(w);
        }
        handled_receivers.insert(format!("{}.{}", receiver, method2));
    }

    // Subscript pass: container[idx].method(
    for caps in subscript_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method = caps.get(2).unwrap().as_str().to_string();
        handled_receivers.insert(format!("{}.{}", receiver, method));

        let type_name = match container_map.get(&receiver) {
            Some(t) => t.clone(),
            None => continue,
        };

        if !checked.insert((receiver.clone(), method.clone())) {
            continue;
        }

        if let Some(w) = check_method_against_type(&cache, &receiver, &method, &type_name) {
            warnings.push(w);
        }
    }

    // Direct pass: receiver.method(
    for caps in method_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method = caps.get(2).unwrap().as_str().to_string();

        // Skip if handled by chain or subscript pass.
        if handled_receivers.contains(&format!("{}.{}", receiver, method)) {
            continue;
        }
        // Skip if receiver is a container — subscript pass owns it.
        if container_map.contains_key(&receiver) {
            continue;
        }

        let type_name = match receiver_map.get(&receiver) {
            Some(t) => t.clone(),
            None => continue,
        };

        if !checked.insert((receiver.clone(), method.clone())) {
            continue;
        }

        // Strip namespace for method lookup: arma::cube → cube.
        let bare_type = type_name.rsplit("::").next().unwrap_or(&type_name).to_string();

        if let Some(w) = check_method_against_type(&cache, &receiver, &method, &bare_type) {
            warnings.push(w);
        }
    }

    warnings
}

/// Strip C++ type qualifiers/punctuation from a return-type string for
/// cache lookup: `const mat&` → `mat`, `cube*` → `cube`, `subview_row` →
/// `subview_row`. Leaves the core typename only.
fn clean_cpp_type(s: &str) -> String {
    s.trim()
        .trim_start_matches("const ")
        .trim_start_matches("const& ")
        .trim_matches('&')
        .trim_matches('*')
        .trim()
        .to_string()
}

/// Check whether `method` exists on `type_name` in the cache. Returns a
/// warning string if hallucinated, None if verified or unverifiable.
fn check_method_against_type(
    cache: &crate::symbols::cache::SymbolCache,
    receiver: &str,
    method: &str,
    type_name: &str,
) -> Option<String> {
    // Language filter: only match symbols from C++ libraries.
    // Without this, `cache.lookup_global("mutex")` returns Go's sync.Mutex
    // and `lock()` gets flagged with `Lock` as suggestion — cross-language
    // cache contamination. Every other language introspect already filters.
    let type_symbols: Vec<_> = cache
        .lookup_global(type_name)
        .into_iter()
        .filter(|s| crate::symbols::library_to_language(&s.library) == "cpp")
        .collect();
    if type_symbols.is_empty() {
        return None; // Type not in cpp cache — can't verify.
    }

    let mut found = false;
    let mut all_methods: Vec<String> = Vec::new();
    for sym in &type_symbols {
        let prefix = format!("{}.", type_name);
        let methods = cache.lookup_prefix(&sym.library, &prefix);
        for m in &methods {
            // Bundle entries inconsistently store either the bare method
            // name (e.g. "rows") or the full path (e.g. "cube.slice") in
            // the `name` field. Normalise by extracting the last path
            // segment so comparison + suggestion logic works on bare names.
            let bare_name = m.path.rsplit('.').next().unwrap_or(&m.name).to_string();
            all_methods.push(bare_name.clone());
            if bare_name == method {
                found = true;
            }
        }
    }

    if !found && !all_methods.is_empty() {
        let closest = all_methods.iter()
            .map(|m| (levenshtein(method, m), m))
            .filter(|(d, _)| *d <= 3)
            .min_by_key(|(d, _)| *d);

        return Some(match closest {
            Some((_, suggestion)) => format!(
                "hallucinated-method: `{}.{}` — `{}` not a method on `{}`. Did you mean `{}`?",
                receiver, method, method, type_name, suggestion
            ),
            None => format!(
                "hallucinated-method: `{}.{}` — `{}` not a method on `{}`",
                receiver, method, method, type_name
            ),
        });
    }

    None
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 { return n; }
    if n == 0 { return m; }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

static BARE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:^|[^.\w:])([a-z_]\w{2,})\s*\(").unwrap()
});
static NS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([a-zA-Z_]\w*)::([a-z_]\w{2,})\s*\(").unwrap()
});

/// Verify bare function calls against SymbolCache.
/// General-purpose: catches hallucinated functions like `rescale()` that
/// don't exist in any cached library. Only flags lowercase names ≥4 chars
/// (C++ convention — stdlib functions are lowercase).
///
/// Suggestion search uses ALL symbol kinds (functions + classes), not just
/// classes — a hallucinated free function's closest real match is often
/// another free function (e.g. `rescale` → `reshape`/`resize`).
pub fn verify_cpp_bare_functions(content: &str) -> Vec<String> {
    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    verify_cpp_bare_functions_with_cache(content, &cache)
}

/// Same as [`verify_cpp_bare_functions`] but accepts an explicit cache.
/// Used by unit tests to seed deterministic fixtures without polluting the
/// global on-disk cache.
pub fn verify_cpp_bare_functions_with_cache(
    content: &str,
    cache: &crate::symbols::cache::SymbolCache,
) -> Vec<String> {
    static CPP_BUILTINS: Lazy<HashSet<&str>> = Lazy::new(|| {
        ["printf", "fprintf", "sprintf", "scanf", "malloc", "free", "calloc",
         "realloc", "exit", "abort", "atoi", "atof", "atol", "strlen",
         "strcpy", "strncpy", "strcat", "strcmp", "strncmp", "memcpy",
         "memmove", "memset", "memcmp", "abs", "sqrt", "pow", "floor",
         "ceil", "round", "sin", "cos", "tan", "log", "exp", "rand",
         "srand", "time", "clock", "size", "begin", "end", "swap",
         "sort", "find", "count", "fill", "copy", "move", "transform",
         // C++ keywords (lowercase form) — never flag.
         "if", "for", "while", "switch", "return", "break", "continue",
         "sizeof", "static_cast", "dynamic_cast", "reinterpret_cast",
         "const_cast", "typeid", "operator", "new", "delete", "throw",
         "catch", "try", "namespace", "using", "template", "typename",
         "class", "struct", "enum", "union", "public", "private",
         "protected", "virtual", "override", "final", "const", "constexpr",
         "mutable", "volatile", "inline", "explicit", "friend", "this",
         "true", "false", "nullptr", "auto", "decltype", "nullptr_t",
         "static_assert", "extern", "register", "thread_local",
         // Common user-defined helper names — too generic to flag confidently.
         "main", "init", "run", "start", "stop", "destroy", "create",
         "update", "render", "draw", "load", "save", "open", "close",
         "read", "write", "process", "handle", "callback", "compute",
         "calculate", "execute", "perform", "apply", "check", "validate",
         "test", "assert", "print", "log", "trace", "error", "warn",
         "info", "debug",
         // C++ std library function/thread names — never flag as bare calls.
         "sleep_for", "sleep_until", "yield", "this_thread", "chrono",
         "milliseconds", "seconds", "microseconds", "nanoseconds",
         "hours", "minutes", "duration", "time_point", "steady_clock",
         "system_clock", "high_resolution_clock",
        ]
        .iter().copied().collect()
    });

    let mut warnings = Vec::new();

    // Cross-language contamination filter: only accept matches from libraries
    // classified as C++. Without this, `lookup_global("rescale")` returns 22
    // hits from robin (Rust workspace) and prisma (Python) and the function
    // passes every C++ call as "verified" — defeating the bare-function
    // hallucination check entirely.
    let cpp_matches = |name: &str| -> Vec<crate::symbols::types::Symbol> {
        cache.lookup_global(name).into_iter()
            .filter(|s| crate::symbols::library_to_language(&s.library) == "cpp")
            .collect()
    };
    let cpp_prefix_matches = |prefix: &str| -> Vec<(String, String, String)> {
        cache.find_symbols_with_prefix(prefix).into_iter()
            .filter(|(lib, _, _)| crate::symbols::library_to_language(lib) == "cpp")
            .collect()
    };

    // Match lowercase function calls: name(args) — NOT after :: or .
    // Namespace-qualified calls: ns::func(args). The `::` form is the
    // C++ way to call free functions inside a namespace, e.g.
    // `arma::rescale(...)`. We verify these by stripping the namespace
    // qualifier and checking the function name against the cache.
    let mut checked: HashSet<String> = HashSet::new();

    for caps in BARE_RE.captures_iter(content) {
        let name = caps.get(1).unwrap().as_str();
        if !checked.insert(name.to_string()) { continue; }
        if CPP_BUILTINS.contains(name) { continue; }

        if cpp_matches(name).is_empty() {
            // Not in cache — could be user code or hallucination.
            // Search ALL symbols (functions + classes) for close matches.
            // Try 4-char prefix first; fall back to 3-char if nothing matches.
            // This catches cases like `rescale` → `reshape` (different 4th char).
            let mut suggestion: Option<String> = None;
            for prefix_len in [4, 3] {
                if prefix_len > name.len() { continue; }
                let prefix: String = name.chars().take(prefix_len).collect();
                let candidates = cpp_prefix_matches(&prefix);
                let filtered = candidates.iter()
                    .map(|(_, c, _)| c.clone())
                    .filter(|c| {
                        if c.len() < 3 { return false; }
                        let d = levenshtein(name, c);
                        // Scale threshold by length: 3 for short names,
                        // up to ~30% of name length for longer ones.
                        let max_d = if name.len() <= 6 { 3 } else { name.len() / 3 + 1 };
                        d > 0 && d <= max_d
                    })
                    .min_by_key(|c| levenshtein(name, c));
                if let Some(s) = filtered {
                    suggestion = Some(s);
                    break;
                }
            }
            if let Some(s) = suggestion {
                warnings.push(format!(
                    "hallucinated-function: `{}` — not in any cached library. Did you mean `{}`?", name, s));
            }
        }
    }

    // Namespace-qualified function calls: ns::func(args).
    // These are common in armadillo/dlib/std code. We verify `func`
    // against the cache — if not present, it's likely hallucinated.
    for caps in NS_RE.captures_iter(content) {
        let ns = caps.get(1).unwrap().as_str();
        let name = caps.get(2).unwrap().as_str();
        let full = format!("{}::{}", ns, name);
        if !checked.insert(full.clone()) { continue; }
        // Common namespaces — never flag their internal callsites blindly.
        // The user code can shadow these.
        if matches!(ns, "std" | "cv" | "fs" | "detail" | "internal" | "util" | "utils") {
            continue;
        }
        if CPP_BUILTINS.contains(name) { continue; }
        // Only flag if the namespace looks like a known library alias.
        // Map common aliases to their libraries for context-sensitive checks.
        // If we can't resolve the namespace, skip — too risky for FP.
        let known_ns = matches!(ns,
            "arma" | "mlpack" | "dlib" | "boost" | "gsl" | "openvdb" |
            "pcl" | "osg" | "ogdf"
        );
        if !known_ns { continue; }

        if cpp_matches(name).is_empty() {
            // Search ALL symbols for close matches.
            let mut suggestion: Option<String> = None;
            for prefix_len in [4, 3] {
                if prefix_len > name.len() { continue; }
                let prefix: String = name.chars().take(prefix_len).collect();
                let candidates = cpp_prefix_matches(&prefix);
                let filtered = candidates.iter()
                    .map(|(_, c, _)| c.clone())
                    .filter(|c| {
                        if c.len() < 3 { return false; }
                        let d = levenshtein(name, c);
                        let max_d = if name.len() <= 6 { 3 } else { name.len() / 3 + 1 };
                        d > 0 && d <= max_d
                    })
                    .min_by_key(|c| levenshtein(name, c));
                if let Some(s) = filtered {
                    suggestion = Some(s);
                    break;
                }
            }
            if let Some(s) = suggestion {
                warnings.push(format!(
                    "hallucinated-function: `{}::{}` — not in any cached library. Did you mean `{}`?", ns, name, s));
            }
        }
    }
    warnings
}

// ─── C++ header verification ──────────────────────────────────────────────

/// Known C++ headers. Includes C++17 standard library + commonly bundled
/// third-party library headers (armadillo, dlib, boost, eigen, etc.).
///
/// Path-style headers (e.g. `dlib/clustering.h`) are stored without the
/// leading/trailing angle brackets. Headers from libraries we don't ship
/// a complete list of (boost, Qt) are intentionally partial — false-positive
/// risk is mitigated by only warning when a close levenshtein match exists.
static KNOWN_CPP_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s: HashSet<&'static str> = HashSet::new();
    // ─── C++ standard library (C++17 + C++20 additions) ───
    let std_headers = [
        "algorithm", "any", "array", "atomic", "barrier", "bit",
        "bitset", "charconv", "chrono", "codecvt", "compare", "complex",
        "concepts", "condition_variable", "coroutine", "deque",
        "exception", "execution", "filesystem", "format", "forward_list",
        "fstream", "functional", "future", "initializer_list", "iomanip",
        "ios", "iosfwd", "iostream", "istream", "iterator", "latch",
        "limits", "list", "locale", "map", "memory", "memory_resource",
        "mutex", "new", "numbers", "numeric", "optional", "ostream",
        "queue", "random", "ranges", "ratio", "regex", "scoped_allocator",
        "semaphore", "set", "shared_mutex", "source_location", "span",
        "sstream", "stack", "stacktrace", "stdexcept", "stop_token",
        "streambuf", "string", "string_view", "strstream", "syncstream",
        "system_error", "thread", "tuple", "type_traits", "typeindex",
        "typeinfo", "unordered_map", "unordered_set", "utility",
        "valarray", "variant", "vector", "version",
        // C compatibility headers (c-prefixed)
        "cassert", "ccomplex", "cctype", "cerrno", "cfenv", "cfloat",
        "cinttypes", "ciso646", "climits", "clocale", "cmath", "csetjmp",
        "csignal", "cstdalign", "cstdarg", "cstdbool", "cstddef",
        "cstdint", "cstdio", "cstdlib", "cstring", "ctgmath", "ctime",
        "cuchar", "cwchar", "cwctype",
        // POSIX / legacy C
        "assert.h", "ctype.h", "errno.h", "fenv.h", "float.h",
        "inttypes.h", "limits.h", "locale.h", "math.h", "setjmp.h",
        "signal.h", "stdarg.h", "stddef.h", "stdint.h", "stdio.h",
        "stdlib.h", "string.h", "tgmath.h", "time.h", "wchar.h",
        "wctype.h", "unistd.h", "fcntl.h", "pthread.h",
    ];
    for h in std_headers { s.insert(h); }
    // ─── Common third-party library TOP-LEVEL headers ───
    // Armadillo ships a single umbrella header.
    s.insert("armadillo");
    // Eigen umbrella headers.
    s.insert("Eigen/Dense");
    s.insert("Eigen/Sparse");
    s.insert("Eigen/Geometry");
    s.insert("Eigen/Cholesky");
    s.insert("Eigen/LU");
    s.insert("Eigen/QR");
    s.insert("Eigen/SVD");
    s.insert("Eigen/Eigenvalues");
    // OpenCV top-level.
    s.insert("opencv2/opencv.hpp");
    s.insert("opencv2/core.hpp");
    s.insert("opencv2/imgproc.hpp");
    s.insert("opencv2/highgui.hpp");
    s.insert("opencv2/videoio.hpp");
    s.insert("opencv2/imgcodecs.hpp");
    s.insert("opencv2/dnn.hpp");
    s.insert("opencv2/features2d.hpp");
    s.insert("opencv2/calib3d.hpp");
    s.insert("opencv2/ml.hpp");
    s.insert("opencv2/objdetect.hpp");
    s.insert("opencv2/photo.hpp");
    s.insert("opencv2/stitching.hpp");
    s.insert("opencv2/video.hpp");
    // SFML top-level.
    s.insert("SFML/Graphics.hpp");
    s.insert("SFML/System.hpp");
    s.insert("SFML/Window.hpp");
    s.insert("SFML/Audio.hpp");
    s.insert("SFML/Network.hpp");
    s.insert("SFML/OpenGL.hpp");
    s.insert("SFML/Main.hpp");
    // SDL.
    s.insert("SDL.h");
    s.insert("SDL2/SDL.h");
    s.insert("SDL_image.h");
    s.insert("SDL_ttf.h");
    s.insert("SDL_mixer.h");
    // ─── dlib headers (commonly hallucinated subpaths) ───
    // Reference: https://github.com/davisking/dlib/tree/master/dlib
    let dlib_headers = [
        "dlib/clustering.h", "dlib/svm.h", "dlib/matrix.h",
        "dlib/matrix/matrix.h", "dlib/rand.h", "dlib/rand/rand.h",
        "dlib/image_processing.h", "dlib/image_io.h", "dlib/gui_widgets.h",
        "dlib/opencv.h", "dlib/threads.h", "dlib/sockstreambuf.h",
        "dlib/server.h", "dlib/server/server_http.h", "dlib/server/server_iostream.h",
        "dlib/sqlite.h", "dlib/logger.h", "dlib/timeout.h", "dlib/timer.h",
        "dlib/queue.h", "dlib/hash_table.h", "dlib/set_utils.h",
        "dlib/graph_utils.h", "dlib/graph.h", "dlib/directed_graph.h",
        "dlib/array2d.h", "dlib/array.h", "dlib/map.h", "dlib/hash_map.h",
        "dlib/tokenize.h", "dlib/string.h", "dlib/uintn.h", "dlib/algs.h",
        "dlib/serialize.h", "dlib/disjoint_subsets.h", "dlib/ref.h",
        "dlib/smart_pointers.h", "dlib/enumerable.h", "dlib/any.h",
        "dlibpipe.h", "dlib/iosockstream.h", "dlib/dnn.h",
        "dlib/cuda_dlib.h", "dlib/tensor.h",
    ];
    for h in dlib_headers { s.insert(h); }
    // ─── boost common headers ───
    let boost_headers = [
        "boost/asio.hpp", "boost/asio/io_context.hpp",
        "boost/filesystem.hpp", "boost/system/error_code.hpp",
        "boost/thread.hpp", "boost/optional.hpp", "boost/variant.hpp",
        "boost/program_options.hpp", "boost/property_tree/ptree.hpp",
        "boost/algorithm/string.hpp", "boost/format.hpp",
        "boost/smart_ptr.hpp", "boost/shared_ptr.hpp",
        "boost/lexical_cast.hpp", "boost/tokenizer.hpp",
        "boost/regex.hpp", "boost/date_time.hpp",
        "boost/test/unit_test.hpp", "boost/math/special_functions.hpp",
        "boost/multi_array.hpp", "boost/iostreams/stream.hpp",
        "boost/log/trivial.hpp", "boost/json.hpp", "boost/url.hpp",
        "boost/circular_buffer.hpp", "boost/bimap.hpp",
        "boost/variant.hpp", "boost/hana.hpp", "boost/mp11.hpp",
        "boost/beast.hpp", "boost/cobalt.hpp", "boost/url.hpp",
    ];
    for h in boost_headers { s.insert(h); }
    // ─── Qt common headers (subset — Qt has thousands) ───
    let qt_headers = [
        "QObject", "QApplication", "QCoreApplication", "QWidget", "QMainWindow",
        "QDialog", "QPushButton", "QLabel", "QLineEdit", "QTextEdit",
        "QListView", "QTreeView", "QTableView", "QComboBox", "QCheckBox",
        "QRadioButton", "QSlider", "QProgressBar", "QSpinBox", "QDoubleSpinBox",
        "QDateEdit", "QTimeEdit", "QDateTimeEdit", "QCalendarWidget",
        "QMenuBar", "QMenu", "QToolBar", "QStatusBar", "QDockWidget",
        "QAction", "QActionGroup", "QShortcut", "QKeySequence",
        "QString", "QStringList", "QByteArray", "QChar", "QRegularExpression",
        "QList", "QVector", "QMap", "QHash", "QSet", "QQueue", "QStack",
        "QPair", "QVariant", "QJsonValue", "QJsonObject", "QJsonDocument",
        "QJsonArray", "QFile", "QFileInfo", "QDir", "QFileSystemWatcher",
        "QSaveFile", "QTextStream", "QDataStream", "QBuffer",
        "QDebug", "QLoggingCategory", "QIODevice",
        "QThread", "QMutex", "QReadWriteLock", "QSemaphore", "QWaitCondition",
        "QFuture", "QFutureWatcher", "QPromise", "QtConcurrent",
        "QNetworkAccessManager", "QNetworkRequest", "QNetworkReply",
        "QTcpServer", "QTcpSocket", "QUdpSocket", "QLocalServer", "QLocalSocket",
        "QSqlDatabase", "QSqlQuery", "QSqlError", "QSqlTableModel",
        "QPainter", "QPixmap", "QImage", "QBitmap", "QPicture",
        "QBrush", "QPen", "QColor", "QFont", "QFontMetrics", "QFontDatabase",
        "QGradient", "QPalette",
        "QEvent", "QMouseEvent", "QKeyEvent", "QWheelEvent", "QResizeEvent",
        "QCloseEvent", "QPaintEvent", "QTimerEvent", "QFocusEvent",
        "QTimer", "QElapsedTimer",
    ];
    for h in qt_headers { s.insert(h); }
    // ─── GLM (OpenGL Mathematics) common ───
    let glm_headers = [
        "glm/glm.hpp", "glm/vec2.hpp", "glm/vec3.hpp", "glm/vec4.hpp",
        "glm/mat2x2.hpp", "glm/mat3x3.hpp", "glm/mat4x4.hpp",
        "glm/geometric.hpp", "glm/trigonometric.hpp", "glm/matrix.hpp",
        "glm/exponential.hpp", "glm/common.hpp", "glm/integer.hpp",
        "glm/packing.hpp", "glm/gtc/matrix_transform.hpp",
        "glm/gtc/type_ptr.hpp", "glm/gtc/constants.hpp",
        "glm/gtc/quaternion.hpp", "glm/gtx/quaternion.hpp",
    ];
    for h in glm_headers { s.insert(h); }
    s
});

/// Verify `#include <X>` and `#include "X"` directives against a known
/// headers list. C++ has no central package index, so this is a hand-curated
/// list of standard + common third-party library headers.
///
/// Generalized heuristic — does NOT special-case any specific source. Only
/// flags headers when (a) the path doesn't match a known header AND (b) a
/// close levenshtein match (≤3) exists in the known set. The levenshtein
/// gate prevents false positives on legitimate niche headers from
/// lesser-known libraries.
pub fn verify_cpp_includes(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    // #include <header>   or   #include "header"
    // Match the angle-bracket and quoted forms. Use a non-greedy capture
    // of the path inside.
    let include_re = Regex::new(
        r#"#include\s+(?:<([^>]+)>|"([^"]+)")"#
    ).unwrap();

    let mut checked: HashSet<String> = HashSet::new();

    for caps in include_re.captures_iter(content) {
        let header = caps.get(1).or_else(|| caps.get(2))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if header.is_empty() { continue; }
        if !checked.insert(header.to_string()) { continue; }

        // Skip local-ish headers (paths starting with ./ or ../ or containing \\).
        if header.starts_with("./") || header.starts_with("../") || header.contains('\\') {
            continue;
        }

        // Skip headers that look like project-local files: end in .hpp/.hxx/.cc/.cxx
        // AND have no slash AND aren't in known list — these are likely project
        // headers like "MyHeader.hpp" which would be false positives.
        // Project headers are usually capitalized or CamelCase.
        let is_known = KNOWN_CPP_HEADERS.contains(header);

        if is_known { continue; }

        // Find closest known header by levenshtein on the basename
        // (ignore directory prefix for distance calc when comparing).
        let basename = header.rsplit('/').next().unwrap_or(header);
        // Strip common C++ header extensions for comparison.
        let basename_no_ext = basename
            .trim_end_matches(".h")
            .trim_end_matches(".hpp")
            .trim_end_matches(".hxx")
            .trim_end_matches(".h++");

        let mut best: Option<(usize, &str)> = None;
        for known in KNOWN_CPP_HEADERS.iter() {
            let known_base = known.rsplit('/').next().unwrap_or(known);
            let known_no_ext = known_base
                .trim_end_matches(".h")
                .trim_end_matches(".hpp")
                .trim_end_matches(".hxx")
                .trim_end_matches(".h++");
            let d = levenshtein(basename_no_ext, known_no_ext);
            // Allow up to 3 edits. For long basenames (≥10 chars), allow
            // up to 30% relative distance to reduce under-matching.
            let threshold = if basename_no_ext.len() >= 10 || known_no_ext.len() >= 10 {
                3 + (basename_no_ext.len().max(known_no_ext.len()) / 4)
            } else {
                3
            };
            if d > 0 && d <= threshold {
                match best {
                    None => best = Some((d, known)),
                    Some((bd, _)) if d < bd => best = Some((d, known)),
                    _ => {}
                }
            }
        }

        // Gate: only warn if there's a close match. This is critical for
        // avoiding FPs on legitimate third-party headers we don't ship.
        if let Some((d, suggestion)) = best {
            // Avoid false positives on CamelCase project headers (like
            // "MyClass.hpp") — those usually don't have a close known match
            // but if they do, the close match would be a Qt class like QObject.
            // Only suggest if the basename doesn't start with uppercase OR
            // the suggestion is also in the same case style.
            let suggestion_starts_upper = suggestion.chars().next()
                .map(|c| c.is_uppercase())
                .unwrap_or(false);
            let header_starts_upper = basename.chars().next()
                .map(|c| c.is_uppercase())
                .unwrap_or(false);
            // If header is CamelCase (likely a class-named project header)
            // and suggestion is lowercase stdlib, skip — different namespaces.
            if header_starts_upper && !suggestion_starts_upper && d > 1 {
                continue;
            }
            warnings.push(format!(
                "hallucinated-include: `{}` — not a known C++ header. Did you mean `{}` (distance {})?",
                header, suggestion, d
            ));
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cpp_receiver_map_catches_declaration() {
        let content = "arma::mat result = m.rows(0, 5);";
        let map = build_cpp_receiver_map(content);
        // arma::mat is namespace::type — regex catches "mat" as type, "result" as receiver
        assert!(!map.is_empty());
    }

    #[test]
    fn build_cpp_receiver_map_catches_auto() {
        let content = "auto x = std::vector<int>::begin();";
        let map = build_cpp_receiver_map(content);
        assert!(map.contains_key("x"));
    }

    #[test]
    fn build_cpp_receiver_map_skips_keywords() {
        let content = "If x = 5;";
        let map = build_cpp_receiver_map(content);
        assert!(!map.contains_key("x"), "should skip If keyword");
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("rows", "rows"), 0);
        assert_eq!(levenshtein("rows", "cols"), 2);  // r→c + w→l = 2 substitutions
    }

    #[test]
    fn container_map_catches_vector() {
        let content = "std::vector<arma::cube> filters;";
        let map = build_cpp_container_map(content);
        assert_eq!(map.get("filters").map(String::as_str), Some("cube"));
    }

    #[test]
    fn container_map_catches_no_prefix() {
        let content = "vector<int> nums;";
        let map = build_cpp_container_map(content);
        assert_eq!(map.get("nums").map(String::as_str), Some("int"));
    }

    #[test]
    fn container_map_strips_namespace() {
        let content = "std::vector<arma::cube> trainData;";
        let map = build_cpp_container_map(content);
        // arma::cube → cube
        assert_eq!(map.get("trainData").map(String::as_str), Some("cube"));
    }

    #[test]
    fn verify_cpp_includes_catches_armadillomat() {
        let warnings = verify_cpp_includes("#include <armadillomat>");
        assert!(warnings.iter().any(|w| w.contains("armadillomat") && w.contains("armadillo")),
            "expected armadillomat to suggest armadillo, got: {:?}", warnings);
    }

    #[test]
    fn verify_cpp_includes_catches_kmeans_clustering() {
        let warnings = verify_cpp_includes("#include <dlib/kmeans_clustering.h>");
        assert!(warnings.iter().any(|w| w.contains("kmeans_clustering") && w.contains("clustering")),
            "expected kmeans_clustering.h to suggest clustering.h, got: {:?}", warnings);
    }

    #[test]
    fn verify_cpp_includes_allows_known_headers() {
        let known = "#include <vector>\n#include <string>\n#include <armadillo>\n#include <dlib/clustering.h>";
        let warnings = verify_cpp_includes(known);
        assert!(warnings.is_empty(),
            "known headers should not warn, got: {:?}", warnings);
    }

    #[test]
    fn verify_cpp_includes_skips_project_headers() {
        // MyClass.hpp — looks like a project header, should NOT match QObject.
        let warnings = verify_cpp_includes("#include \"MyClass.hpp\"");
        // Either no warning, or warning not matching QObject
        assert!(!warnings.iter().any(|w| w.contains("QObject")),
            "project header should not match QObject, got: {:?}", warnings);
    }

    #[test]
    fn verify_cpp_bare_catches_namespace_qualified_rescale() {
        // Deterministic isolated test using an in-memory cache seeded only
        // with armadillo's known free-function symbols (reshape, resize —
        // NOT rescale, which is a hallucination).
        //
        // The original test had two latent defects:
        //   1. Relied on symbol_bundle.jsonl containing armadillo entries,
        //      but that fixture has zero armadillo symbols.
        //   2. Used lookup_global against the global on-disk cache, which
        //      returned 22 cross-language hits for "rescale" (robin Rust +
        //      prisma Python) and defeated the bare-function check entirely.
        //      Fixed by language-gating the lookup inside
        //      verify_cpp_bare_functions (cpp_matches / cpp_prefix_matches).
        use crate::symbols::cache::SymbolCache;
        use crate::symbols::types::Symbol;
        let c = match SymbolCache::open_in_memory() {
            Ok(c) => c,
            Err(_) => return,
        };
        let seed = vec![
            Symbol::new("cpp.armadillo", "stdlib", "arma.reshape"),
            Symbol::new("cpp.armadillo", "stdlib", "arma.resize"),
            Symbol::new("cpp.armadillo", "stdlib", "arma.size"),
        ];
        let inserted = c.insert_many(&seed);
        assert!(inserted.is_ok(), "insert_many failed: {:?}", inserted);
        assert_eq!(inserted.unwrap(), 3);

        // Direct test: arma::rescale() should be flagged as hallucinated
        // with reshape as the closest C++-language suggestion.
        let warnings = verify_cpp_bare_functions_with_cache(
            "arma::rescale(img.slice(0));", &c);
        assert!(warnings.iter().any(|w| w.contains("rescale")),
            "expected arma::rescale to be flagged, got: {:?}", warnings);
        assert!(warnings.iter().any(|w| w.contains("reshape")),
            "expected reshape as suggestion, got: {:?}", warnings);
    }
}
