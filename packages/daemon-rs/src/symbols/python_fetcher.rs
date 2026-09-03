//! Python package symbol fetcher.
//!
//! Fetches package info from PyPI JSON API and extracts top-level
//! module/class/function names. Results are cached in SymbolCache
//! for cross-reference during hallucination detection.
//!
//! Two-tier approach:
//!   1. PyPI JSON API — verify package exists, get version + metadata
//!   2. pydoc.dev HTML — extract class/function names from rendered docs
//!
//! If pydoc.dev is unavailable, falls back to storing the package as
//! verified-exists with empty symbol list (prevents hallucinated-import FPs).

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::{Symbol, SymbolKind, Visibility};

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Fetch Python package symbols and cache them.
///
/// Returns (symbol_count, version_string) on success.
pub async fn fetch_and_cache_python_package(package: &str) -> Result<(usize, String), String> {
    let lib_name = format!("pypi.{}", package);
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("anubis-scanner/0.4 (python-fetcher)")
        .build()
        .map_err(|e| format!("client: {e}"))?;

    // Step 1: Verify package exists on PyPI.
    let pypi_url = format!("https://pypi.org/pypi/{}/json", package);
    let resp = client.get(&pypi_url).send().await
        .map_err(|e| format!("pypi fetch: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("pypi returned {} for '{}'", resp.status(), package));
    }

    #[derive(serde::Deserialize, Default)]
    struct PyPIInfo {
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        summary: Option<String>,
        #[serde(default)]
        requires_python: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct PyPIResponse {
        #[serde(default)]
        info: PyPIInfo,
    }

    let pypi: PyPIResponse = resp.json().await
        .map_err(|e| format!("pypi parse: {e}"))?;

    let version = pypi.info.version.unwrap_or_else(|| "unknown".to_string());

    // Step 2: Try pydoc.dev for symbol extraction.
    // pydoc.dev renders Python package docs with class/function listings.
    let doc_url = format!("https://pydoc.dev/{}/latest/{}/", package, package.replace('-', "_"));
    let doc_resp = client.get(&doc_url).send().await;

    let symbols = match doc_resp {
        Ok(r) if r.status().is_success() => {
            let html = r.text().await.unwrap_or_default();
            parse_python_symbols(&html, &lib_name, package)
        }
        _ => {
            // Step 3: Fallback — at least register the package as verified.
            // This prevents hallucinated-import FPs for packages that exist
            // but have no parseable documentation.
            vec![Symbol {
                library: lib_name.clone(),
                version: version.clone(),
                path: package.to_string(),
                name: package.to_string(),
                kind: SymbolKind::Module,
                signature: None,
                params: vec![],
                return_type: None,
                doc_text: pypi.info.summary,
                source_file: None,
                visibility: Visibility::Public,
                is_deprecated: false,
                deprecated_message: None,
                extracted_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }]
        }
    };

    if symbols.is_empty() {
        return Err(format!("no symbols found for Python package '{}'", package));
    }

    // Step 4: Cache symbols.
    let cache = SymbolCache::open().map_err(|e| format!("cache open: {e}"))?;
    let count = symbols.len();
    cache.insert_many(&symbols).map_err(|e| format!("cache insert: {e}"))?;

    Ok((count, version))
}

/// Parse Python symbols from pydoc.dev HTML.
///
/// Extracts:
///   - Classes: `class ClassName` → SymbolKind::Class
///   - Functions: `def function_name` → SymbolKind::Function
///   - Modules: top-level module references
fn parse_python_symbols(html: &str, library: &str, _package: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let push = |symbols: &mut Vec<Symbol>, seen: &mut std::collections::HashSet<String>,
                name: &str, kind: SymbolKind, library: &str, now: u64| {
        if name.is_empty() || name.len() < 2 {
            return;
        }
        // Skip dunder methods (__init__, __str__, etc.)
        if name.starts_with("__") && name.ends_with("__") {
            return;
        }
        // Skip private names
        if name.starts_with('_') {
            return;
        }
        if seen.insert(name.to_string()) {
            symbols.push(Symbol {
                library: library.to_string(),
                version: "latest".to_string(),
                path: name.to_string(),
                name: name.to_string(),
                kind,
                signature: None,
                params: vec![],
                return_type: None,
                doc_text: None,
                source_file: None,
                visibility: Visibility::Public,
                is_deprecated: false,
                deprecated_message: None,
                extracted_at: now,
            });
        }
    };

    // pydoc.dev uses <dt> tags for class/function definitions.
    // Also try generic patterns for other doc formats.
    let class_re = regex::Regex::new(
        r#"(?:class\s+|<dt[^>]*class[^>]*>\s*)([A-Z][a-zA-Z0-9_]*)"#,
    ).unwrap();
    let func_re = regex::Regex::new(
        r#"(?:<dt[^>]*function[^>]*>\s*(?:def\s+)?|def\s+)([a-z_][a-zA-Z0-9_]*)"#,
    ).unwrap();

    // Also catch camelCase and PascalCase in code spans
    let symbol_re = regex::Regex::new(
        r#"<code[^>]*>([A-Z][a-zA-Z0-9_]*)</code>"#,
    ).unwrap();

    for caps in class_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            push(&mut symbols, &mut seen, m.as_str(), SymbolKind::Class, library, now);
        }
    }
    for caps in func_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            push(&mut symbols, &mut seen, m.as_str(), SymbolKind::Function, library, now);
        }
    }
    for caps in symbol_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            push(&mut symbols, &mut seen, m.as_str(), SymbolKind::Class, library, now);
        }
    }

    symbols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_classes_and_functions() {
        let html = r#"
        <dt class="class">class BaseModel</dt>
        <dt class="function">def model_validate</dt>
        <dt class="function">def field_validator</dt>
        <code>ConfigDict</code>
        "#;
        let symbols = parse_python_symbols(html, "pypi.pydantic", "pydantic");
        assert!(symbols.iter().any(|s| s.name == "BaseModel" && s.kind == SymbolKind::Class));
        assert!(symbols.iter().any(|s| s.name == "model_validate" && s.kind == SymbolKind::Function));
        assert!(symbols.iter().any(|s| s.name == "ConfigDict" && s.kind == SymbolKind::Class));
    }

    #[test]
    fn parse_skips_dunder_and_private() {
        let html = r#"
        <dt>def __init__</dt>
        <dt>def _private</dt>
        <dt>def public_func</dt>
        "#;
        let symbols = parse_python_symbols(html, "pypi.test", "test");
        assert!(!symbols.iter().any(|s| s.name == "__init__"));
        assert!(!symbols.iter().any(|s| s.name == "_private"));
        assert!(symbols.iter().any(|s| s.name == "public_func"));
    }
}
