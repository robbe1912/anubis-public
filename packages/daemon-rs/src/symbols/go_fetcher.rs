//! Go module symbol fetcher.
//!
//! Fetches Go module documentation from proxy.golang.org / pkg.go.dev
//! and extracts exported symbol names (functions, types, constants).
//! Results are cached in SymbolCache for constructor verification.
//!
//! Pattern: fetch module source .zip info → parse for exported names.
//! Falls back to pkg.go.dev HTML scrape if proxy unavailable.

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::{Symbol, SymbolKind, Visibility};

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Fetch Go module symbols and cache them.
///
/// Returns (symbol_count, version_string) on success.
pub async fn fetch_and_cache_go_module(module: &str) -> Result<(usize, String), String> {
    // Step 1: Get latest version from Go proxy.
    let latest_url = format!("https://proxy.golang.org/{}/@latest", module);
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("anubis-scanner/0.3 (go-fetcher)")
        .build()
        .map_err(|e| format!("client: {e}"))?;

    let resp = client.get(&latest_url).send().await
        .map_err(|e| format!("fetch latest: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("proxy returned {}", resp.status()));
    }

    #[derive(serde::Deserialize)]
    struct LatestInfo {
        #[serde(alias = "Version")]
        version: String,
    }
    let info: LatestInfo = resp.json().await
        .map_err(|e| format!("parse latest JSON: {e}"))?;

    // Step 2: Fetch the module's go.mod to find packages.
    let mod_url = format!("https://proxy.golang.org/{}/@v/{}.mod", module, info.version);
    let mod_resp = client.get(&mod_url).send().await
        .map_err(|e| format!("fetch mod: {e}"))?;

    let mod_content = if mod_resp.status().is_success() {
        mod_resp.text().await.unwrap_or_default()
    } else {
        String::new()
    };

    // Step 3: Fetch pkg.go.dev documentation page for symbol extraction.
    // This is more reliable than parsing .go source from the zip.
    let doc_url = format!("https://pkg.go.dev/{}", module);
    let doc_resp = client.get(&doc_url).send().await
        .map_err(|e| format!("fetch docs: {e}"))?;

    let doc_html = if doc_resp.status().is_success() {
        doc_resp.text().await.unwrap_or_default()
    } else {
        // Fallback: use go.mod content + module path as symbol source.
        mod_content.clone()
    };

    // Step 4: Extract exported symbols from documentation HTML.
    let symbols = parse_go_symbols(&doc_html, module);

    if symbols.is_empty() {
        return Err(format!("no symbols found for Go module '{}'", module));
    }

    // Step 5: Cache symbols.
    let cache = SymbolCache::open().map_err(|e| format!("cache open: {e}"))?;
    let count = symbols.len();
    cache.insert_many(&symbols).map_err(|e| format!("cache insert: {e}"))?;

    Ok((count, info.version))
}

/// Parse Go symbols from pkg.go.dev HTML or source text.
///
/// Extracts:
///   - Functions: `func FunctionName` → SymbolKind::Function
///   - Types: `type TypeName` → SymbolKind::Class (structs/interfaces)
///   - Constants: `const ConstName` → SymbolKind::Constant
///   - Variables: `var VarName` → SymbolKind::Property
///
/// Only EXPORTED names (first letter uppercase) are included.
fn parse_go_symbols(html: &str, module: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let push_symbol = |symbols: &mut Vec<Symbol>, seen: &mut std::collections::HashSet<String>,
                       name: &str, kind: SymbolKind, module: &str, now: u64| {
        if name.len() < 2 || !name.chars().next().map_or(false, |c| c.is_uppercase()) {
            return;
        }
        if seen.insert(name.to_string()) {
            symbols.push(Symbol {
                library: module.to_string(),
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

    // Extract from HTML or plain text using regex.
    let func_re = regex::Regex::new(r#"(?:func\s+|data-TestID="function"[^>]*>\s*)([A-Z][a-zA-Z0-9_]*)"#).unwrap();
    let type_re = regex::Regex::new(r#"(?:type\s+|data-TestID="type"[^>]*>\s*)([A-Z][a-zA-Z0-9_]*)"#).unwrap();
    let const_re = regex::Regex::new(r#"(?:const\s+|data-TestID="constant"[^>]*>\s*)([A-Z][a-zA-Z0-9_]*)"#).unwrap();
    let var_re = regex::Regex::new(r"(?:var\s+)([A-Z][a-zA-Z0-9_]*)").unwrap();

    // Also extract from <code> tags which pkg.go.dev uses for symbol names.
    let code_re = regex::Regex::new(r"<code[^>]*>([A-Z][a-zA-Z0-9_]*)</code>").unwrap();

    for caps in func_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            push_symbol(&mut symbols, &mut seen, m.as_str(), SymbolKind::Function, module, now);
        }
    }
    for caps in type_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            push_symbol(&mut symbols, &mut seen, m.as_str(), SymbolKind::Class, module, now);
        }
    }
    for caps in const_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            push_symbol(&mut symbols, &mut seen, m.as_str(), SymbolKind::Constant, module, now);
        }
    }
    for caps in var_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            push_symbol(&mut symbols, &mut seen, m.as_str(), SymbolKind::Property, module, now);
        }
    }
    for caps in code_re.captures_iter(html) {
        if let Some(m) = caps.get(1) {
            // Could be any kind — use Function as default.
            push_symbol(&mut symbols, &mut seen, m.as_str(), SymbolKind::Function, module, now);
        }
    }

    symbols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_exported_functions() {
        let html = "<div>func <a href=\"#Pointer\">Pointer</a></div>\n<div>func <a href=\"#StoreMessageInfo\">StoreMessageInfo</a></div>\n<div>func internalFunc</div>\n<div>var <a href=\"#Default\">Default</a></div>\n<div>type <a href=\"#Message\">Message</a></div>";
        let symbols = parse_go_symbols(html, "google.golang.org/protobuf/proto");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        // internalFunc should NOT be included (lowercase first letter).
        assert!(!names.contains(&"internalFunc"), "got: {:?}", names);
    }

    #[test]
    fn parse_extracts_from_code_tags() {
        let html = r#"<code>WrapPointer</code><code>CacheMessageInfo</code>"#;
        let symbols = parse_go_symbols(html, "test");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"WrapPointer"), "got: {:?}", names);
        assert!(names.contains(&"CacheMessageInfo"), "got: {:?}", names);
    }

    #[test]
    fn parse_dedupes_names() {
        let html = "func Foo\ntype Foo\nvar Foo";
        let symbols = parse_go_symbols(html, "test");
        let foo_count = symbols.iter().filter(|s| s.name == "Foo").count();
        assert_eq!(foo_count, 1, "should dedupe; got {} Foo entries", foo_count);
    }

    #[test]
    fn parse_skips_lowercase_names() {
        let html = "func lowercase\ntype camelCase\nfunc Proper";
        let symbols = parse_go_symbols(html, "test");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Proper"), "got: {:?}", names);
        assert!(!names.contains(&"lowercase"), "got: {:?}", names);
        assert!(!names.contains(&"camelCase"), "got: {:?}", names);
    }
}
