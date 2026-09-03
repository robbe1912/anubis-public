//! C# library symbol fetcher.
//!
//! Fetches C# class/method names from NuGet package metadata.
//! Results cached in SymbolCache for constructor verification.

use crate::symbols::cache::SymbolCache;
use crate::symbols::types::{Symbol, SymbolKind, Visibility};

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Key .NET BCL packages to seed at startup. These cover the types most
/// commonly used in production C# code. Fetched from NuGet via fuget.org.
const BCL_PACKAGES: &[&str] = &[
    "System.Runtime",
    "System.Collections",
    "System.Linq",
    "System.Threading",
    "System.Threading.Tasks",
    "System.IO",
    "System.Net.Http",
    "System.Text.Json",
    "Microsoft.EntityFrameworkCore",
    "Microsoft.Extensions.Logging.Abstractions",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Options",
    "Microsoft.AspNetCore.Http",
    "Newtonsoft.Json",
];

/// Seed C# BCL symbols by fetching key NuGet packages. Runs at most once
/// per process (OnceCell guard). Each package is fetched via the existing
/// `fetch_and_cache_csharp_package` path — fuget.org HTML → CamelCase extraction.
///
/// This eliminates FPs on common .NET types (DbContextOptions, DbSet,
/// CancellationToken, ILogger, IServiceCollection) that were never in the
/// cache because FORGE only fetches packages found in `using` statements,
/// and `using System;` maps to a namespace, not a NuGet package.
pub async fn seed_csharp_bcl() {
    // Delegate to metadata-based seeding (authoritative ECMA-335 from NuGet).
    // Falls back to fuget.org BCL_PACKAGES scraping if metadata fetch fails.
    super::csharp_metadata_fetcher::seed_bcl_via_metadata().await;

    // Also seed via fuget.org as fallback/supplement for BCL packages
    // not covered by Microsoft.NETCore.App.Ref (e.g., EF Core, ASP.NET).
    use std::sync::OnceLock;
    static SEEDED_FUGET: OnceLock<()> = OnceLock::new();
    if SEEDED_FUGET.get().is_some() {
        return;
    }
    let _ = SEEDED_FUGET.set(());
    for package in BCL_PACKAGES {
        let _ = fetch_and_cache_csharp_package(package).await;
    }
}

/// Fetch C# library symbols and cache them.
///
/// `package` format: NuGet package name (e.g., "Newtonsoft.Json",
/// "Microsoft.Extensions.Logging").
pub async fn fetch_and_cache_csharp_package(package: &str) -> Result<(usize, String), String> {
    // Try ECMA-335 metadata parsing first (authoritative, complete type+method coverage).
    // Falls back to fuget.org HTML scraping on failure.
    match super::csharp_metadata_fetcher::fetch_and_cache_via_metadata(package, None).await {
        Ok(result) => {
            tracing::debug!(package, count = result.0, "csharp symbols via metadata fetcher");
            return Ok(result);
        }
        Err(e) => {
            tracing::debug!(package, error = %e, "metadata fetch failed, falling back to fuget.org");
        }
    }

    // Fallback: fuget.org HTML scraping (original path)
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent("anubis-scanner/0.3 (csharp-fetcher)")
        .build()
        .map_err(|e| format!("client: {e}"))?;

    // Step 1: Fetch NuGet registration index for package metadata.
    let reg_url = format!(
        "https://api.nuget.org/v3/registration5-semver1/{}/index.json",
        package.to_lowercase()
    );
    let resp = client.get(&reg_url).send().await
        .map_err(|e| format!("fetch nuget: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("nuget returned {} for '{}'", resp.status(), package));
    }

    let body = resp.text().await.map_err(|e| format!("read body: {e}"))?;

    // Step 2: Extract symbols from NuGet JSON + fuget.org documentation.
    // NuGet JSON has catalog entries with dependency information but not
    // class names. Fuget.org provides browsable API docs.
    let fuget_url = format!("https://www.fuget.org/packages/{}", package);
    let fuget_resp = client.get(&fuget_url).send().await;
    let fuget_html = match fuget_resp {
        Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
        _ => body.clone(),
    };

    let symbols = parse_csharp_symbols(&fuget_html, package);

    if symbols.is_empty() {
        // Fallback: extract CamelCase identifiers from NuGet JSON metadata.
        let fallback_symbols = parse_csharp_from_metadata(&body, package);
        if fallback_symbols.is_empty() {
            return Err(format!("no symbols found for C# package '{}'", package));
        }
        let cache = SymbolCache::open().map_err(|e| format!("cache: {e}"))?;
        let count = fallback_symbols.len();
        cache.insert_many(&fallback_symbols).map_err(|e| format!("insert: {e}"))?;
        return Ok((count, "latest".to_string()));
    }

    let cache = SymbolCache::open().map_err(|e| format!("cache: {e}"))?;
    let count = symbols.len();
    cache.insert_many(&symbols).map_err(|e| format!("insert: {e}"))?;

    Ok((count, "latest".to_string()))
}

/// Parse C# symbols from fuget.org HTML or NuGet JSON.
fn parse_csharp_symbols(html: &str, library: &str) -> Vec<Symbol> {
    extract_camelcase_symbols(html, library)
}

/// Fallback: extract CamelCase identifiers from NuGet metadata JSON.
fn parse_csharp_from_metadata(json: &str, library: &str) -> Vec<Symbol> {
    extract_camelcase_symbols(json, library)
}

/// Universal CamelCase extraction — works on HTML, JSON, or plain text.
/// Extracts all identifiers matching [A-Z][a-zA-Z0-9]{2,} that are likely
/// class/method names (not HTML tags or JSON keys).
fn extract_camelcase_symbols(content: &str, library: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Skip common noise words.
    let skip = [
        "True", "False", "Null", "None", "Version", "Package", "Type",
        "String", "Integer", "Boolean", "Object", "Array", "Error",
        "Task", "Async", "Await", "Latest", "Catalog", "Content",
        "Html", "Json", "Xml", "Http", "Uri", "Url",
    ];

    let re = regex::Regex::new(r"\b([A-Z][a-zA-Z0-9]{2,})\b").unwrap();
    for caps in re.captures_iter(content) {
        let name = caps.get(1).unwrap().as_str();
        if skip.contains(&name) || !seen.insert(name.to_string()) {
            continue;
        }
        symbols.push(Symbol {
            library: library.to_string(),
            version: "latest".to_string(),
            path: name.to_string(),
            name: name.to_string(),
            kind: SymbolKind::Class,
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

    symbols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_finds_camelcase_names() {
        let html = "<div>StringBuilder</div><div>Dictionary</div><div>Console</div>";
        let symbols = extract_camelcase_symbols(html, "System");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"StringBuilder"), "got: {:?}", names);
        assert!(names.contains(&"Dictionary"), "got: {:?}", names);
        assert!(names.contains(&"Console"), "got: {:?}", names);
    }

    #[test]
    fn extract_skips_noise_words() {
        let html = "Version Package Type String True False";
        let symbols = extract_camelcase_symbols(html, "test");
        assert!(symbols.is_empty(), "should skip noise; got: {:?}", symbols.iter().map(|s| &s.name).collect::<Vec<_>>());
    }

    #[test]
    fn extract_dedupes() {
        let html = "Console Console Console";
        let symbols = extract_camelcase_symbols(html, "test");
        assert_eq!(symbols.iter().filter(|s| s.name == "Console").count(), 1);
    }

    #[test]
    fn extract_from_json_metadata() {
        let json = r#"{"catalogEntry":{"id":"Newtonsoft.Json","version":"13.0.1"}}"#;
        let symbols = extract_camelcase_symbols(json, "Newtonsoft.Json");
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"Newtonsoft"), "got: {:?}", names);
    }
}
