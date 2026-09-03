//! Java library symbol fetcher.
//!
//! Fetches Java class/method names from Maven Central + javadoc.io.
//! Results cached in SymbolCache for constructor verification.

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::{Symbol, SymbolKind, Visibility};

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Fetch Java library symbols and cache them.
///
/// `group_artifact` format: "groupId:artifactId" (e.g., "org.apache.commons:commons-lang3")
/// or just "groupId" to search for all artifacts in that group.
pub async fn fetch_and_cache_java_library(group_artifact: &str) -> Result<(usize, String), String> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("anubis-scanner/0.3 (java-fetcher)")
        .build()
        .map_err(|e| format!("client: {e}"))?;

    // Step 1: Search Maven Central for artifacts in this group.
    let (group, artifact) = match group_artifact.split_once(':') {
        Some((g, a)) => (g.to_string(), a.to_string()),
        None => (group_artifact.to_string(), String::new()),
    };

    // Step 2: Fetch javadoc.io page for class names.
    // javadoc.io provides HTML with predictable class listing.
    let doc_path = if artifact.is_empty() {
        format!("https://javadoc.io/static/{}/latest/_list.html", group)
    } else {
        format!("https://javadoc.io/static/{}/{}/latest/_list.html", group, artifact)
    };

    let resp = client.get(&doc_path).send().await
        .map_err(|e| format!("fetch javadoc.io: {e}"))?;

    let html = if resp.status().is_success() {
        resp.text().await.unwrap_or_default()
    } else {
        // Fallback: try Maven search API for artifact names.
        let search_url = format!(
            "https://search.maven.org/solrsearch/select?q=g:{}&rows=20&wt=json",
            group
        );
        let search_resp = client.get(&search_url).send().await
            .map_err(|e| format!("maven search: {e}"))?;
        if search_resp.status().is_success() {
            search_resp.text().await.unwrap_or_default()
        } else {
            return Err(format!("javadoc.io and Maven both failed for '{}'", group_artifact));
        }
    };

    // Step 3: Extract class/method names from documentation.
    let symbols = parse_java_symbols(&html, &group);

    if symbols.is_empty() {
        return Err(format!("no symbols found for Java library '{}'", group_artifact));
    }

    let cache = SymbolCache::open().map_err(|e| format!("cache open: {e}"))?;
    let count = symbols.len();
    cache.insert_many(&symbols).map_err(|e| format!("cache insert: {e}"))?;

    Ok((count, "latest".to_string()))
}

/// Parse Java symbols from javadoc HTML or JSON.
fn parse_java_symbols(content: &str, library: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let push = |symbols: &mut Vec<Symbol>, seen: &mut std::collections::HashSet<String>,
                name: &str, kind: SymbolKind| {
        if name.len() < 3 || !name.chars().next().map_or(false, |c| c.is_uppercase()) {
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

    // From HTML: class names in <a href="ClassName.html"> links.
    let class_re = regex::Regex::new(r#"<a[^>]*href="([A-Z][a-zA-Z0-9_]*)\.html"#).unwrap();
    for caps in class_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            push(&mut symbols, &mut seen, m.as_str(), SymbolKind::Class);
        }
    }

    // From HTML: method names in code tags or method summaries.
    let method_re = regex::Regex::new(r#"<code[^>]*>([a-z][a-zA-Z0-9_]*)\("#).unwrap();
    for caps in method_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            // Method names are lowercase — but we want them for verification too.
            if m.as_str().len() >= 4 {
                let name = m.as_str();
                if seen.insert(name.to_string()) {
                    symbols.push(Symbol {
                        library: library.to_string(),
                        version: "latest".to_string(),
                        path: name.to_string(),
                        name: name.to_string(),
                        kind: SymbolKind::Method,
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
            }
        }
    }

    // From JSON (Maven search): artifact names.
    let artifact_re = regex::Regex::new(r#""a":"([a-zA-Z0-9_-]+)""#).unwrap();
    for caps in artifact_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            // Convert artifact names to CamelCase for matching.
            let name: String = m.as_str()
                .split('-')
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                        None => String::new(),
                    }
                })
                .collect();
            if name.len() >= 3 {
                push(&mut symbols, &mut seen, &name, SymbolKind::Class);
            }
        }
    }

    symbols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_class_names_from_html() {
        let html = r#"<a href="ArrayList.html">ArrayList</a><a href="HashMap.html">HashMap</a>"#;
        let symbols = parse_java_symbols(html, "java.util");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"ArrayList"), "got: {:?}", names);
        assert!(names.contains(&"HashMap"), "got: {:?}", names);
    }

    #[test]
    fn parse_extracts_method_names_from_code_tags() {
        let html = r#"<code>hashCode()</code><code>toString()</code>"#;
        let symbols = parse_java_symbols(html, "java.lang");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"hashCode"), "got: {:?}", names);
        assert!(names.contains(&"toString"), "got: {:?}", names);
    }

    #[test]
    fn parse_dedupes() {
        let html = r#"<a href="List.html">List</a><a href="List.html">List</a>"#;
        let symbols = parse_java_symbols(html, "java.util");
        assert_eq!(symbols.iter().filter(|s| s.name == "List").count(), 1);
    }
}
