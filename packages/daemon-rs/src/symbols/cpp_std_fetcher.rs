//! C++ standard library symbol fetcher.
//!
//! Fetches std type/member function names from the libc++ project on GitHub
//! (the live upstream for LLVM's C++ standard library implementation).
//! Results cached in SymbolCache for FORGE method verification.
//!
//! Source of truth: https://github.com/llvm/llvm-project/blob/main/libcxx/include/
//! This is NOT hardcoded data — it's parsed from the live libc++ source.

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::{Symbol, SymbolKind, Visibility};

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

const LIBCXX_BASE: &str =
    "https://raw.githubusercontent.com/llvm/llvm-project/main/libcxx/include";

/// Key std headers covering the types most commonly used in production code.
/// These map to the file names in libc++ (without angle brackets).
const STD_HEADERS: &[(&str, &str)] = &[
    // (header_file, cache_type_prefix)
    ("algorithm", "algorithm"),
    ("vector", "vector"),
    ("map", "map"),
    ("unordered_map", "unordered_map"),
    ("set", "set"),
    ("queue", "queue"),
    ("deque", "deque"),
    ("mutex", "mutex"),
    ("thread", "thread"),
    ("chrono", "chrono"),
    ("string", "string"),
    ("memory", "memory"),
    ("functional", "functional"),
    ("array", "array"),
    ("list", "list"),
    ("forward_list", "forward_list"),
    ("stack", "stack"),
    ("condition_variable", "condition_variable"),
    ("future", "future"),
    ("atomic", "atomic"),
    ("optional", "optional"),
    ("variant", "variant"),
    ("tuple", "tuple"),
    ("filesystem", "filesystem"),
    ("regex", "regex"),
    ("sstream", "sstream"),
    ("fstream", "fstream"),
    ("iostream", "iostream"),
];

/// Fetch C++ std symbols and cache them. Runs at most once per process.
///
/// Fetches libc++ headers from GitHub, extracts class/struct member functions
/// and free functions, stores as `cpp.std.{Type}.{Method}` in the SymbolCache.
pub async fn fetch_and_cache_cpp_std() -> Result<(usize, String), String> {
    use std::sync::OnceLock;
    static SEEDED: OnceLock<Result<(usize, String), String>> = OnceLock::new();
    if let Some(result) = SEEDED.get() {
        return result.clone();
    }
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("anubis-scanner/0.5 (cpp-std-fetcher)")
        .build()
        .map_err(|e| format!("client: {e}"))?;
    let result = do_fetch_and_cache_cpp_std(client).await;
    let _ = SEEDED.set(result.clone());
    result
}

async fn do_fetch_and_cache_cpp_std(client: reqwest::Client) -> Result<(usize, String), String> {
    let cache = SymbolCache::open().map_err(|e| format!("cache: {e}"))?;
    let now = chrono::Utc::now().timestamp_millis() as u64;

    let mut all_symbols = Vec::new();
    let mut fetched_headers = Vec::new();

    for (header_file, type_prefix) in STD_HEADERS {
        let url = format!("{LIBCXX_BASE}/{header_file}");
        let resp = client.get(&url).send().await;

        let body = match resp {
            Ok(r) if r.status().is_success() => {
                r.text().await.unwrap_or_default()
            }
            _ => continue, // Skip headers that fail to fetch
        };

        let symbols = extract_cpp_symbols(&body, type_prefix, now);
        fetched_headers.push(format!(
            "{}: {} symbols",
            header_file,
            symbols.len()
        ));
        all_symbols.extend(symbols);
    }

    let total_symbols = all_symbols.len();
    cache.insert_many(&all_symbols).map_err(|e| format!("insert: {e}"))?;

    let summary = if total_symbols == 0 {
        "no symbols extracted (network error or parse failure)".to_string()
    } else {
        format!(
            "extracted {} symbols from {} headers: {}",
            total_symbols,
            fetched_headers.len(),
            fetched_headers.join(", ")
        )
    };

    Ok((total_symbols, summary))
}

/// Extract type names, member functions, and free functions from C++ header source.
///
/// Parses the public API surface of libc++ headers:
/// - Class/struct declarations: `class vector {`, `struct mutex {`
/// - Member function declarations: `size_type size() const`, `void push_back(...)`
/// - Free functions (algorithm): `template<...> void sort(...)`
///
/// Member functions are attributed to the enclosing class. Free functions
/// (those outside any class) are stored under the header's type_prefix.
fn extract_cpp_symbols(source: &str, type_prefix: &str, now: u64) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Track current class/struct context for member function attribution.
    let mut current_class: Option<String> = None;

    // Regex patterns:
    // Class/struct declaration: "class vector {" or "struct mutex {"
    // C++ std types are lowercase (vector, map, queue), not PascalCase.
    let class_re = regex::Regex::new(
        r"^\s*(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::|;|\{|$)"
    ).unwrap();

    // Member function declaration: identifier immediately before `(`.
    // C++ method syntax: "return_type method_name(params)".
    // The identifier BEFORE `(` is the method name, not the return type.
    let method_re = regex::Regex::new(
        r"\b([a-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\("
    ).unwrap();

    // Free function (algorithm-style): "template<...> ret func_name(...)"
    // We capture func_name only if outside a class context.
    let free_func_re = regex::Regex::new(
        r"^\s*(?:inline\s+|constexpr\s+|template\s*<[^>]*>\s*)*[a-z_][A-Za-z0-9_]*(?:\s+\*?|\s*&?\s*\*?)*\s+([a-z_][A-Za-z0-9_]*)\s*\([^)]*\)"
    ).unwrap();

    for line in source.lines() {
        let trimmed = line.trim();

        // Track class context via opening/closing braces.
        // Simple heuristic: decrement depth on '}' lines.
        if trimmed.starts_with('}') {
            current_class = None;
            continue;
        }

        // Detect class/struct declaration.
        if let Some(cap) = class_re.captures(trimmed) {
            let class_name = cap.get(1).unwrap().as_str();
            // Skip macro/template machinery.
            if is_cpp_noise(class_name) {
                continue;
            }
            current_class = Some(class_name.to_string());

            // Register the type itself.
            let lib = format!("cpp.std.{class_name}");
            let path = class_name.to_string();
            let key = format!("{lib}.{path}");
            if seen.insert(key) {
                symbols.push(Symbol {
                    library: lib,
                    version: "latest".to_string(),
                    path,
                    name: class_name.to_string(),
                    kind: SymbolKind::Class,
                    signature: None,
                    params: vec![],
                    return_type: None,
                    doc_text: None,
                    source_file: Some(format!("<{}>", type_prefix)),
                    visibility: Visibility::Public,
                    is_deprecated: false,
                    deprecated_message: None,
                    extracted_at: now,
                });
            }
            continue;
        }

        // Extract member function if inside a class.
        if let Some(ref class_name) = current_class {
            if let Some(cap) = method_re.captures(trimmed) {
                let method = cap.get(1).unwrap().as_str();
                if is_cpp_noise(method) {
                    continue;
                }
                let lib = format!("cpp.std.{class_name}");
                let path = method.to_string();
                let key = format!("{lib}.{path}");
                if seen.insert(key) {
                    symbols.push(Symbol {
                        library: lib,
                        version: "latest".to_string(),
                        path,
                        name: method.to_string(),
                        kind: SymbolKind::Method,
                        signature: None,
                        params: vec![],
                        return_type: None,
                        doc_text: None,
                        source_file: Some(format!("<{}>", type_prefix)),
                        visibility: Visibility::Public,
                        is_deprecated: false,
                        deprecated_message: None,
                        extracted_at: now,
                    });
                }
            }
        } else {
            // Free function (algorithm, etc.) — outside class context.
            if let Some(cap) = free_func_re.captures(trimmed) {
                let func = cap.get(1).unwrap().as_str();
                if is_cpp_noise(func) {
                    continue;
                }
                let lib = format!("cpp.std.{type_prefix}");
                let path = func.to_string();
                let key = format!("{lib}.{path}");
                if seen.insert(key) {
                    symbols.push(Symbol {
                        library: lib,
                        version: "latest".to_string(),
                        path,
                        name: func.to_string(),
                        kind: SymbolKind::Function,
                        signature: None,
                        params: vec![],
                        return_type: None,
                        doc_text: None,
                        source_file: Some(format!("<{}>", type_prefix)),
                        visibility: Visibility::Public,
                        is_deprecated: false,
                        deprecated_message: None,
                        extracted_at: now,
                    });
                }
            }
        }
    }

    symbols
}

/// Filter out C++ keywords, preprocessor noise, and template machinery
/// that would otherwise pollute the symbol cache.
fn is_cpp_noise(name: &str) -> bool {
    matches!(
        name,
        "if" | "else" | "while" | "for" | "switch" | "case" | "return"
        | "break" | "continue" | "throw" | "catch" | "try" | "do"
        | "sizeof" | "alignof" | "alignas" | "decltype" | "nullptr"
        | "true" | "false" | "this" | "operator"
        | "const" | "static" | "inline" | "virtual" | "explicit"
        | "override" | "final" | "default" | "delete"
        | "typename" | "template" | "using" | "namespace"
        | "typedef" | "struct" | "class" | "enum" | "union"
        | "public" | "private" | "protected"
        | "friend" | "mutable" | "volatile" | "register"
        | "auto" | "void" | "char" | "short" | "int" | "long"
        | "float" | "double" | "signed" | "unsigned"
        | "bool" | "wchar_t" | "char16_t" | "char32_t"
        | "size_t" | "ptrdiff_t" | "uint8_t" | "uint16_t"
        | "uint32_t" | "uint64_t" | "int8_t" | "int16_t"
        | "int32_t" | "int64_t"
        | "_LIBCPP" | "_VSTD" | "_LIBCPP_HIDE_FROM_ABI"
        | "_LIBCPP_CONSTEXPR" | "_LIBCPP_NODISCARD"
        | "_LIBCPP_INLINE_VISIBILITY" | "_LIBCPP_DEPRECATED"
        | "__" | "defined" | "include" | "define" | "pragma"
        | "ifndef" | "ifdef" | "endif" | "once"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_class_and_methods() {
        let source = r#"
class vector {
public:
    void push_back(const value_type& __x);
    size_type size() const;
    bool empty() const;
    void clear();
    reference operator[](size_type __n);
};
"#;
        let symbols = extract_cpp_symbols(source, "vector", 0);
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"vector"), "class name: {:?}", names);
        assert!(names.contains(&"push_back"), "push_back: {:?}", names);
        assert!(names.contains(&"size"), "size: {:?}", names);
        assert!(names.contains(&"empty"), "empty: {:?}", names);
        assert!(names.contains(&"clear"), "clear: {:?}", names);
    }

    #[test]
    fn extract_free_functions() {
        let source = r#"
template <class _RandomAccessIterator>
void sort(_RandomAccessIterator __first, _RandomAccessIterator __last);

template <class _RandomAccessIterator, class _Compare>
void sort(_RandomAccessIterator __first, _RandomAccessIterator __last, _Compare __comp);

template <class _InputIterator, class _Tp>
_InputIterator find(_InputIterator __first, _InputIterator __last, const _Tp& __value);
"#;
        let symbols = extract_cpp_symbols(source, "algorithm", 0);
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        // sort and find should appear as free functions
        assert!(names.contains(&"sort"), "sort: {:?}", names);
        assert!(names.contains(&"find"), "find: {:?}", names);
    }

    #[test]
    fn skips_noise_keywords() {
        let source = "class foo { public: return bar(); };";
        let symbols = extract_cpp_symbols(source, "test", 0);
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(!names.contains(&"return"), "return is noise");
        assert!(names.contains(&"foo"), "class foo should be extracted");
    }

    #[test]
    fn filters_preprocessor_macros() {
        let source = "_LIBCPP_HIDE_FROM_ABI void push_back();";
        let symbols = extract_cpp_symbols(source, "test", 0);
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(!names.contains(&"_LIBCPP_HIDE_FROM_ABI"), "macro should be filtered");
    }
}
