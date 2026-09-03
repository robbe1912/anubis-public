//! Scope analysis — track variable types, verify instance method calls.
//!
//! The base `check_symbols` only catches `ClassName.method(` patterns.
//! Most real-world code (and most DELULU hallucinations) use instance
//! methods: `varName.method(`. To verify these, we need to know the
//! variable's type.
//!
//! Flow:
//!   1. `analyze_scope(content)` extracts variable-type bindings from
//!      declarations (`Type varName = ...`, `let varName: Type`, etc.).
//!   2. `check_instance_calls(content)` extracts `var.method(` patterns,
//!      looks up the variable's type, and verifies the method against
//!      the symbol cache. If the type is cached but the method is not,
//!      emits a warning (with fuzzy-match suggestion when close).
//!
//! Language coverage: Java, C#, C++, TypeScript, Python (typed), Go, Rust.
//! All patterns are general — not DELULU-specific.

use std::collections::{HashMap, HashSet};

use crate::symbols::cache::SymbolCache;
use crate::symbols::levenshtein_capped;

/// Variable scope: maps variable name → inferred/declared type name.
#[derive(Debug, Default)]
pub struct Scope {
    pub vars: HashMap<String, String>,
}

/// Extract variable-type bindings from typed-language declarations.
///
/// Recognizes (language-agnostic — patterns are distinct enough that
/// cross-language false positives are rare):
///   - Java/C#/C++: `Type varName = ...`, `final Type varName = ...`,
///     `Type varName;`
///   - TypeScript: `let/const/var varName: Type = ...`,
///     `let/const/var varName = new Type(...)`
///   - Python (typed): `varName: Type = ...`,
///     `varName = ClassName(...)`
///   - Go: `var varName Type`, `varName := Type{...}`,
///     `varName := pkg.Func()`
///   - Rust: `let varName: Type`, `let varName = Type::new()`,
///     `let mut varName: Type`
pub fn analyze_scope(content: &str) -> Scope {
    let mut scope = Scope::default();

    // Java/C#: `[final] Type varName [= ..., ;, )]
    // Type must start uppercase; varName must be lowercase (filters noise).
    let java_decl = regex::Regex::new(
        r"\b(?:final\s+)?([A-Z][\w<>]*(?:\s*<[^>]+>)?)\s+([a-z_]\w*)\s*(?:[=;,)])",
    )
    .unwrap();
    for caps in java_decl.captures_iter(content) {
        if let (Some(t), Some(v)) = (caps.get(1), caps.get(2)) {
            // Strip generics from type: List<String> -> List
            let type_name = t.as_str().split('<').next().unwrap_or(t.as_str()).trim();
            if !type_name.is_empty() {
                scope.vars.insert(v.as_str().to_string(), type_name.to_string());
            }
        }
    }

    // C++: `Type varName [= ..., ;]` — Type can be lowercase (vector, string,
    // std::vector, etc.). Restricted to known C++ stdlib types to avoid
    // matching function calls like `foo(x);` or English prose.
    let cpp_decl = regex::Regex::new(
        r"\b(?:std::)?(int|float|double|char|bool|long|short|unsigned|signed|size_t|ssize_t|auto|vector|string|map|unordered_map|set|unordered_set|list|pair|array|deque|queue|stack|tuple|shared_ptr|unique_ptr|weak_ptr|function|thread|mutex|atomic|chrono::\w+|filesystem::\w+)(?:\s*<[^>]+>)?\s+([a-z_]\w*)\s*(?:[=;])",
    )
    .unwrap();
    for caps in cpp_decl.captures_iter(content) {
        if let (Some(t), Some(v)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }

    // TypeScript/JS: `let/const/var varName: Type =` or `let/const/var varName = new Type(`
    let ts_typed = regex::Regex::new(
        r"\b(?:let|const|var)\s+([a-z_]\w*)\s*:\s*([A-Z]\w*)",
    )
    .unwrap();
    for caps in ts_typed.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }
    let ts_new = regex::Regex::new(
        r"\b(?:let|const|var)\s+([a-z_]\w*)\s*=\s*new\s+([A-Z]\w*)",
    )
    .unwrap();
    for caps in ts_new.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }

    // Python typed: `varName: Type =`
    let py_typed = regex::Regex::new(r"\b([a-z_]\w*)\s*:\s*([A-Z]\w*)\s*=").unwrap();
    for caps in py_typed.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }
    // Python inferred: `varName = ClassName(`  (constructor call → type = ClassName)
    let py_inferred =
        regex::Regex::new(r"\b([a-z_]\w*)\s*=\s*([A-Z]\w*)\s*\(").unwrap();
    for caps in py_inferred.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }

    // Go: `var varName Type` (handles `pkg.Type` — captures only the Type segment)
    let go_var = regex::Regex::new(r"\bvar\s+([a-z_]\w*)\s+(?:\w+\.)?([A-Z]\w*)").unwrap();
    for caps in go_var.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }
    // Go: `varName := pkg.Type{...}` or `varName := Type{...}`
    let go_short_struct =
        regex::Regex::new(r"\b([a-z_]\w*)\s*:=\s*(?:\w+\.)?([A-Z]\w*)\s*\{").unwrap();
    for caps in go_short_struct.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }

    // Rust: `let varName: Type` (with optional `mut`)
    let rust_typed =
        regex::Regex::new(r"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*:\s*([A-Z]\w*)").unwrap();
    for caps in rust_typed.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }
    // Rust: `let varName = Type::method(` → type = Type
    let rust_new =
        regex::Regex::new(r"\blet\s+(?:mut\s+)?([a-z_]\w*)\s*=\s*([A-Z]\w*)::").unwrap();
    for caps in rust_new.captures_iter(content) {
        if let (Some(v), Some(t)) = (caps.get(1), caps.get(2)) {
            scope.vars.insert(v.as_str().to_string(), t.as_str().to_string());
        }
    }

    scope
}

/// Filter out common false-positive variable names that aren't really
/// variables (keywords, primitives, noise).
fn is_plausible_var(name: &str) -> bool {
    if name.len() < 2 {
        return false;
    }
    matches!(
        name,
        "if" | "for" | "while" | "function" | "return" | "switch"
        | "case" | "break" | "continue" | "new" | "this" | "self"
        | "use" | "import" | "from" | "export" | "default" | "fn"
        | "def" | "class" | "struct" | "enum" | "interface" | "impl"
        | "trait" | "type" | "const" | "let" | "var" | "static"
        | "public" | "private" | "protected" | "internal" | "package"
        | "extends" | "implements" | "throws" | "throw" | "try"
        | "catch" | "finally" | "async" | "await" | "yield" | "in"
        | "of" | "as" | "where" | "when" | "is" | "not" | "and"
        | "or" | "true" | "false" | "null" | "nil" | "None"
        | "True" | "False" | "void" | "int" | "long" | "float"
        | "double" | "char" | "bool" | "boolean" | "byte" | "short"
        | "string"
    ) == false
}

/// Filter out common primitive/built-in types that we don't track.
fn is_plausible_type(name: &str) -> bool {
    if name.len() < 2 {
        return false;
    }
    matches!(
        name,
        "Void" | "void" | "Int" | "int" | "Long" | "long"
        | "Float" | "float" | "Double" | "double" | "Char" | "char"
        | "Bool" | "bool" | "boolean" | "Byte" | "byte" | "Short"
        | "short" | "String" | "string" | "str" | "Object" | "object"
        | "Any" | "any" | "Unknown" | "unknown" | "Never" | "never"
        | "None" | "Self" | "self" | "Unit" | "Boolean" | "Number"
        | "Integer" | "Array" | "List" | "Map" | "Dict" | "Set"
        | "Tuple" | "Vec" | "Option" | "Result" | "Box" | "Rc"
        | "Arc" | "Ref" | "Mutex" | "RwLock"
    ) == false
}

/// Result of instance-method checking.
#[derive(Debug, Default)]
pub struct InstanceCheckResult {
    /// Warnings, one per hallucinated/unknown method call.
    pub warnings: Vec<String>,
    /// Count of method calls examined (after dedup).
    pub checked_count: usize,
    /// Count of variable names resolved to a type in scope.
    pub resolved_count: usize,
    /// Count of variables whose type was found in some cached library.
    pub type_cached_count: usize,
    /// Count of method calls flagged as hallucinated/unknown.
    pub hallucination_count: usize,
    /// Snapshot of variable-type bindings extracted from the content
    /// (e.g., `[("mutableInt", "MutableInt"), ("df", "DataFrame")]`).
    /// Used by L3 prompt to verify instance-method calls against known types.
    pub scope_vars: Vec<(String, String)>,
}

/// Check instance method calls (`var.method(`) against the symbol cache.
///
/// Self-contained: opens its own cache, returns warnings. Stays silent
/// when the cache is empty (no library context) — same pattern as
/// `check_symbols`.
pub fn check_instance_calls(content: &str, language: &str) -> InstanceCheckResult {
    let mut out = InstanceCheckResult::default();

    let cache = match SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return out,
    };
    let all_libs = match cache.list_libraries() {
        libs if !libs.is_empty() => libs,
        _ => return out,
    };

    // Filter libraries by language to prevent cross-language cache contamination.
    // C/C++/C# don't have external library fetchers — common type names like
    // `queue`, `mutex`, `auto` match against Rust/Go/Python caches causing FPs.
    // For these languages, only search local project libraries.
    let cached_libs: Vec<(String, String, usize)> = match language {
        "cpp" | "c" | "csharp" => {
            all_libs.into_iter().filter(|(lib, _, _)| {
                lib.starts_with("local.") || lib == "std" || lib == "std::"
            }).collect()
        }
        _ => all_libs,
    };
    if cached_libs.is_empty() {
        return out;
    }

    let scope = analyze_scope(content);
    // Expose scope vars (sorted, capped) so callers (e.g., L3 prompt builder)
    // can give the validator ground-truth variable-type bindings.
    let mut scope_vars: Vec<(String, String)> = scope
        .vars
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    scope_vars.sort_by(|a, b| a.0.cmp(&b.0));
    scope_vars.truncate(40); // cap to bound prompt size
    out.scope_vars = scope_vars;

    // Instance method calls: varName.method(
    let call_re = regex::Regex::new(r"\b([a-z_]\w*)\.([a-zA-Z_]\w*)\s*\(").unwrap();

    let mut seen: HashSet<(String, String)> = HashSet::new();
    for caps in call_re.captures_iter(content) {
        let var = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let method = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

        if !seen.insert((var.clone(), method.clone())) {
            continue;
        }
        if !is_plausible_var(&var) {
            continue;
        }
        // Skip property access / getters without paren (call_re already requires `(`)

        out.checked_count += 1;

        // Resolve variable to type via scope
        let type_name = match scope.vars.get(&var) {
            Some(t) => t.clone(),
            None => continue, // unknown var — can't verify, skip
        };
        if !is_plausible_type(&type_name) {
            continue;
        }
        out.resolved_count += 1;

        // Look up type + method across cached libraries
        let mut type_found_in: Vec<String> = Vec::new();
        let mut method_found = false;
        let mut suggestions: Vec<(String, usize)> = Vec::new(); // (method_name, distance)

        for (lib_name, _lib_version, _sym_count) in &cached_libs {
            // Type itself
            if cache.lookup(lib_name, &type_name).is_some() {
                type_found_in.push(lib_name.clone());

                // Method on this type
                let path = format!("{}.{}", type_name, method);
                if cache.lookup(lib_name, &path).is_some() {
                    method_found = true;
                    break;
                }

                // Collect fuzzy candidates from this type's methods
                let prefix = format!("{}.", type_name);
                let methods = cache.lookup_prefix(lib_name, &prefix);
                for sym in methods.iter() {
                    let dist = levenshtein_capped(&method, &sym.name, 4);
                    if dist <= 3 {
                        suggestions.push((sym.name.clone(), dist));
                    }
                }
            }
        }

        if method_found {
            continue; // legitimate method call, no warning
        }

        if !type_found_in.is_empty() {
            // Type is cached but method is not — hallucination signal.
            // Only emit warning when we have a strong fuzzy suggestion
            // (Levenshtein ≤2). Without a suggestion, the call might be a
            // legitimate method we just haven't indexed — stay silent to
            // avoid false positives on real-world code that uses methods
            // our bundle doesn't cover.
            out.type_cached_count += type_found_in.len();

            if let Some((best_suggestion, best_dist)) =
                suggestions.into_iter().filter(|(_, d)| *d <= 2).min_by_key(|(_, d)| *d)
            {
                out.hallucination_count += 1;
                let lib_str = type_found_in.join(", ");
                out.warnings.push(format!(
                    "{}.{}() — method not in cached symbols for type {} (in {}). \
                     Did you mean {}.{}() (distance {})?",
                    type_name, method, type_name, lib_str, type_name, best_suggestion, best_dist
                ));
            }
            // else: no strong suggestion → silent (avoid FP on unindexed methods)
        }
        // else: type not cached, can't verify — silent
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_scope_finds_java_decl() {
        let code = "MutableInt mutableInt = new MutableInt(1); counterMap.put(str, x);";
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("mutableInt").map(|s| s.as_str()), Some("MutableInt"));
    }

    #[test]
    fn analyze_scope_finds_ts_typed() {
        let code = "let count: MutableInt = new MutableInt();";
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("count").map(|s| s.as_str()), Some("MutableInt"));
    }

    #[test]
    fn analyze_scope_finds_python_typed() {
        let code = "df: DataFrame = pd.read_csv('x.csv')";
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("df").map(|s| s.as_str()), Some("DataFrame"));
    }

    #[test]
    fn analyze_scope_finds_python_inferred() {
        let code = "model = RandomForestClassifier()";
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("model").map(|s| s.as_str()), Some("RandomForestClassifier"));
    }

    #[test]
    fn analyze_scope_finds_go_var_decl() {
        let code = "var buf bytes.Buffer";
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("buf").map(|s| s.as_str()), Some("Buffer"));
    }

    #[test]
    fn analyze_scope_finds_rust_let_typed() {
        let code = "let cache: SymbolCache = SymbolCache::open()?;";
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("cache").map(|s| s.as_str()), Some("SymbolCache"));
    }

    #[test]
    fn analyze_scope_finds_rust_let_new() {
        let code = "let app = Router::new();";
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("app").map(|s| s.as_str()), Some("Router"));
    }

    #[test]
    fn analyze_scope_skips_lowercase_primitive_types() {
        // C++ stdlib types ARE tracked now (needed for claim classification
        // filter — `vector<int> x; x.push_back(...)` should skip L3).
        let code = "int x = 5; float y = 1.0; vector<int> v;";
        let scope = analyze_scope(code);
        // int and float are primitive C++ types but tracked so we can filter
        // method calls on them (they don't have library methods to verify).
        assert_eq!(scope.vars.get("x").map(|s| s.as_str()), Some("int"));
        assert_eq!(scope.vars.get("v").map(|s| s.as_str()), Some("vector"));
    }

    #[test]
    fn analyze_scope_catches_cpp_stdlib_collections() {
        // DELULU regression test: vector<int> trainLabelsAll; trainLabelsAll.end()
        // was being flagged as hallucination because scope_analysis missed
        // lowercase C++ types. With the cpp_decl regex, trainLabelsAll should
        // be tracked as type "vector" — claim classification will then skip
        // L3 for trainLabelsAll.end().
        let code = r#"
            #include <vector>
            #include <iostream>
            int main() {
                std::vector<int> trainLabelsAll;
                std::vector<std::string> names;
                std::map<std::string, int> counts;
                trainLabelsAll.push_back(1);
                return 0;
            }
        "#;
        let scope = analyze_scope(code);
        assert_eq!(scope.vars.get("trainLabelsAll").map(|s| s.as_str()), Some("vector"));
        assert_eq!(scope.vars.get("names").map(|s| s.as_str()), Some("vector"));
        assert_eq!(scope.vars.get("counts").map(|s| s.as_str()), Some("map"));
    }

    #[test]
    fn check_instance_calls_silent_when_cache_empty() {
        // With no library context, should return empty warnings (no type
        // resolution possible without scope + cache).
        let result = check_instance_calls("mutableInt.incrementValue();", "java");
        assert!(result.warnings.is_empty());
    }
}
