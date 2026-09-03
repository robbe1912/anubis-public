//! Package index lookup — verifies imports against language registries.
//!
//! Research finding (librarian bg_03f932f4, 2026-07-25): DELULU paper
//! identifies `imports` as the HARDEST hallucination category (21-24pt
//! accuracy gap vs easiest). Package index lookup directly addresses this
//! by checking whether an imported package actually exists in its language's
//! registry.
//!
//! Supported registries:
//!   - Python: PyPI (pypi.org/pypi/<name>/json)
//!   - TypeScript/JavaScript: npm (registry.npmjs.org/<name>)
//!   - Rust: crates.io (crates.io/api/v1/crates/<name>)
//!   - Java: Maven Central (search.maven.org/solrsearch/select)
//!   - C#: NuGet (api.nuget.org/v3/registration5/<name>/index.json)
//!   - Go: proxy.golang.org (no central registry — uses module path)
//!
//! C/C++ skipped (no central registry — #include paths vary by project).
//!
//! All HTTP calls use HEAD where possible (lighter than GET) and respect
//! a global concurrency cap (5 parallel) to avoid rate-limit issues.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use tokio::sync::Semaphore;

/// Concurrency cap for registry HTTP calls. Prevents accidental DoS of
/// PyPI/npm/etc. when a single response has 20+ imports.
const MAX_CONCURRENT_LOOKUPS: usize = 5;
static LOOKUP_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)));

/// HTTP client timeout for registry calls. Most registries respond in
/// <500ms; 3s is generous for transatlantic latency.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Outcome of a package-index verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportStatus {
    /// Package exists in its language's registry (verified real).
    Verified,
    /// Registry returned 404 — package does not exist (hallucinated).
    NotFound,
    /// Registry returned non-404 error, or transport failed, or we hit
    /// the concurrency limit and timed out. Caller should treat as
    /// "could not verify" — do NOT flag as hallucination.
    NetworkError,
    /// We don't have a registry check for this import type (e.g., C++
    /// headers, scoped relative imports, stdlib already cached).
    Skipped,
}

/// Detect which registry an import string should be checked against.
///
/// Returns `Skipped` for imports we can't verify (C++ headers, relative
/// paths, stdlib modules already in our symbol cache).
pub fn classify_import(imp: &str) -> ImportStatus {
    let imp = imp.trim();
    if imp.is_empty() {
        return ImportStatus::Skipped;
    }

    // Skip relative imports — always user-local, not in any registry.
    if imp.starts_with("./") || imp.starts_with("../") || imp.starts_with('/') {
        return ImportStatus::Skipped;
    }

    // Skip C++ headers — no central registry.
    if imp.ends_with(".h") || imp.ends_with(".hpp") || imp.ends_with(".hh") {
        return ImportStatus::Skipped;
    }
    // Bare C++ standard names (no extension, lowercase, common stdlib).
    static CPP_STDLIB: Lazy<HashSet<&'static str>> = Lazy::new(|| {
        [
            "vector", "string", "iostream", "cmath", "cstdlib", "cstdint",
            "cstring", "cstdio", "fstream", "sstream", "iomanip", "memory",
            "algorithm", "functional", "numeric", "utility", "iterator",
            "map", "set", "unordered_map", "unordered_set", "vector",
            "array", "deque", "queue", "stack", "list", "forward_list",
            "thread", "mutex", "atomic", "chrono", "condition_variable",
            "future", "regex", "random", "ratio", "type_traits", "tuple",
            "any", "optional", "variant", "bit", "charconv", "codecvt",
            "complex", "exception", "initializer_list", "limits", "locale",
            "new", "scoped_allocator", "system_error", "typeindex",
            "typeinfo", "valarray",
        ]
        .iter()
        .copied()
        .collect()
    });
    if CPP_STDLIB.contains(imp) {
        return ImportStatus::Skipped;
    }

    // Java framework packages — JDK classes (java.*, javax.*, com.sun.*, sun.*)
    // are NOT Maven artifacts. NuGet-style registry lookup always 404s on them.
    // Skip to avoid false-positive hallucinated-import warnings.
    if imp.starts_with("java.")
        || imp.starts_with("javax.")
        || imp.starts_with("com.sun.")
        || imp.starts_with("sun.")
        || imp == "java" || imp == "javax"
    {
        return ImportStatus::Skipped;
    }

    // .NET BCL namespaces (System.*, Microsoft.*, net.*) are framework
    // namespaces — NOT NuGet packages. NuGet lookup always 404s on them.
    // Skip to avoid false-positive hallucinated-import warnings.
    if imp.starts_with("system.")
        || imp.starts_with("microsoft.")
        || imp.starts_with("net.")
        || imp == "system" || imp == "microsoft"
    {
        return ImportStatus::Skipped;
    }

    // We classify by format only — caller passes one import at a time.
    // The actual registry check happens in `verify_import_with_language`.
    ImportStatus::Skipped
}

/// Per-language registry check — WITH PROCESS-WIDE CACHE.
///
/// Results are cached in a process-wide HashMap keyed by (language, package_name).
/// Once verified, subsequent calls return cached status instantly — no HTTP.
/// This is critical for benchmarks (3 scans per sample × multiple imports)
/// AND production (same package imported across multiple responses).
///
/// Cache lives in process memory. For disk persistence, the SymbolCache
/// at ~/.anubis/symbols/cache.sqlite stores full API definitions separately.
pub async fn verify_import_with_language(
    language: &str,
    package_name: &str,
) -> ImportStatus {
    let package_name = package_name.trim();
    if package_name.is_empty() {
        return ImportStatus::Skipped;
    }

    // PyPI import→package alias map. Python imports use the package's
    // import name, which often differs from its PyPI distribution name.
    // Without this mapping, legitimate imports like `import rest_framework`
    // 404 on PyPI (real package is `djangorestframework`).
    let package_name = if language == "python" {
        match package_name {
            "rest_framework" => "djangorestframework",
            "cv2" => "opencv-python",
            "PIL" => "Pillow",
            "yaml" => "PyYAML",
            "dateutil" => "python-dateutil",
            "sklearn" => "scikit-learn",
            "bs4" => "beautifulsoup4",
            "dotenv" => "python-dotenv",
            "jwt" => "PyJWT",
            "magic" => "python-magic",
            _ => package_name,
        }
    } else {
        package_name
    };

    // Skip relative paths regardless of language.
    if package_name.starts_with("./")
        || package_name.starts_with("../")
        || package_name.starts_with('/')
    {
        return ImportStatus::Skipped;
    }

    // Java framework packages — JDK classes (java.*, javax.*, com.sun.*, sun.*)
    // are NOT Maven artifacts. Maven lookup always 404s on them, producing
    // false-positive hallucinated-import warnings on legitimate code.
    if package_name.starts_with("java.")
        || package_name.starts_with("javax.")
        || package_name.starts_with("com.sun.")
        || package_name.starts_with("sun.")
        || package_name == "java" || package_name == "javax"
    {
        return ImportStatus::Skipped;
    }

    // .NET BCL namespaces (System.*, Microsoft.*, net.*) are framework
    // namespaces — NOT NuGet packages. NuGet lookup always 404s on them.
    if package_name.starts_with("system.")
        || package_name.starts_with("microsoft.")
        || package_name.starts_with("net.")
        || package_name == "system" || package_name == "microsoft"
    {
        return ImportStatus::Skipped;
    }

    // C++ headers — no central registry.
    if package_name.ends_with(".h")
        || package_name.ends_with(".hpp")
        || package_name.ends_with(".hh")
    {
        return ImportStatus::Skipped;
    }

    // ── Process-wide HTTP result cache ────────────────────────────────
    // Avoids re-fetching the same package status across scans. Dramatic
    // speedup for benchmarks (baseline-diff does 3x scans) and production
    // (same package appears in multiple responses).
    use once_cell::sync::Lazy;
    use tokio::sync::RwLock;
    static HTTP_CACHE: Lazy<RwLock<std::collections::HashMap<(String, String), ImportStatus>>> =
        Lazy::new(|| RwLock::new(std::collections::HashMap::new()));

    let cache_key = (language.to_string(), package_name.to_string());
    {
        let cache = HTTP_CACHE.read().await;
        if let Some(status) = cache.get(&cache_key) {
            return *status;
        }
    }

    let url = match build_registry_url(language, package_name) {
        Some(u) => u,
        None => return ImportStatus::Skipped,
    };

    let _permit = match LOOKUP_SEMAPHORE.acquire().await {
        Ok(p) => p,
        Err(_) => return ImportStatus::NetworkError,
    };

    let client = match reqwest::Client::builder()
        .timeout(LOOKUP_TIMEOUT)
        .user_agent("anubis-scanner/0.3 (package-index-lookup)")
        .build()
    {
        Ok(c) => c,
        Err(_) => return ImportStatus::NetworkError,
    };

    // Use GET (not HEAD) because some registries (notably npm) don't support
    // HEAD on individual package URLs and return 405/404 erroneously.
    let resp = client.get(&url).send().await;
    let mut status = match resp {
        Ok(r) => {
            let code = r.status().as_u16();
            if code == 200 {
                ImportStatus::Verified
            } else if code == 404 {
                ImportStatus::NotFound
            } else {
                ImportStatus::NetworkError
            }
        }
        Err(_) => ImportStatus::NetworkError,
    };

    // Go module progressive shortening: Go module paths can include
    // subpackage segments (golang.org/x/mod/semver). The proxy only
    // resolves module-level paths (golang.org/x/mod). If the full path
    // 404s, try progressively shorter paths by removing the last segment.
    // This eliminates false positives on legitimate Go subpackages.
    if status == ImportStatus::NotFound && language == "go" {
        let parts: Vec<&str> = package_name.split('/').collect();
        if parts.len() > 3 {
            // Try shorter paths (remove last segment each time).
            for len in (3..parts.len()).rev() {
                let shorter = parts[..len].join("/");
                let shorter_url = format!(
                    "https://proxy.golang.org/{}/@latest",
                    shorter.to_lowercase()
                );
                if let Ok(r) = client.get(&shorter_url).send().await {
                    if r.status().as_u16() == 200 {
                        status = ImportStatus::Verified;
                        break;
                    }
                }
            }
        }
    }

    // C# NuGet progressive shortening: NuGet packages ship many namespaces.
    // e.g., `BenchmarkDotNet.Diagnostics` is a namespace inside the
    // `BenchmarkDotNet` package — NuGet registry only knows the package
    // name, so `benchmarkdotnet.diagnostics` returns 404 even though the
    // namespace is real. If full dotted path 404s, try progressively
    // shorter paths by removing the last segment. This eliminates false
    // positives on legitimate C# subnamespaces.
    if status == ImportStatus::NotFound && language == "csharp" {
        let parts: Vec<&str> = package_name.split('.').collect();
        if parts.len() > 1 {
            // Try shorter dotted paths (keep removing last segment).
            // Stop as soon as one resolves — parent package likely owns
            // the sub-namespace.
            for len in (1..parts.len()).rev() {
                let shorter = parts[..len].join(".");
                let shorter_url = format!(
                    "https://api.nuget.org/v3/registration5-semver1/{}/index.json",
                    shorter.to_lowercase()
                );
                if let Ok(r) = client.get(&shorter_url).send().await {
                    if r.status().as_u16() == 200 {
                        status = ImportStatus::Verified;
                        break;
                    }
                }
            }
        }
    }

    // Java Maven progressive shortening: a Java import path
    // (org.springframework.boot.SpringApplication) ends in a CLASS name, not a
    // groupId. solrsearch `g:org...SpringApplication` 404s even though the
    // artifact exists — the real groupId is a dotted prefix
    // (org.springframework.boot). If the full path 404s, try progressively
    // shorter prefixes by removing the last segment. Mirrors the Go/C#
    // shortening arms — eliminates FPs on legitimate JVM artifacts.
    if status == ImportStatus::NotFound && language == "java" {
        let parts: Vec<&str> = package_name.split('.').collect();
        if parts.len() > 2 {
            for len in (2..parts.len()).rev() {
                let shorter = parts[..len].join(".");
                let shorter_url = format!(
                    "https://search.maven.org/solrsearch/select?q=g:{}&rows=1&wt=json",
                    shorter
                );
                if let Ok(r) = client.get(&shorter_url).send().await {
                    if r.status().as_u16() == 200 {
                        status = ImportStatus::Verified;
                        break;
                    }
                }
            }
        }
    }

    // Cache result (even errors — don't retry network failures immediately).
    // Only cache definitive results (Verified/NotFound). NetworkError may be
    // transient, so skip caching those.
    if status != ImportStatus::NetworkError {
        let mut cache = HTTP_CACHE.write().await;
        cache.insert(cache_key, status);
    }

    status
}

/// Build the registry lookup URL for a (language, package_name) pair.
///
/// Returns `None` for languages we don't support (e.g., C++).
pub fn build_registry_url(language: &str, package_name: &str) -> Option<String> {
    match language {
        "python" => {
            // PyPI: take top-level package (split on '.').
            // e.g., "sklearn.preprocessing" → "scikit-learn" via alias map,
            // otherwise just check "sklearn" top-level.
            let top = package_name.split('.').next()?;
            // Common aliases — PyPI name differs from import name.
            let aliased = match top {
                "sklearn" => "scikit-learn",
                "PIL" => "Pillow",
                "cv2" => "opencv-python",
                "yaml" => "PyYAML",
                "dateutil" => "python-dateutil",
                "bs4" => "beautifulsoup4",
                "dotenv" => "python-dotenv",
                "jose" => "python-jose",
                "jwt" => "PyJWT",
                "rest_framework" => "djangorestframework",
                _ => top,
            };
            Some(format!("https://pypi.org/pypi/{}/json", aliased))
        }
        "typescript" | "javascript" => {
            // npm: scoped packages need URL-encoded slash.
            // e.g., "@react-router/dev" → "/@react-router%2Fdev"
            let encoded = package_name.replace('/', "%2F");
            Some(format!("https://registry.npmjs.org/{}", encoded))
        }
        "rust" => {
            // crates.io: take crate name (split on '::').
            let top = package_name.split("::").next()?;
            Some(format!("https://crates.io/api/v1/crates/{}", top))
        }
        "java" => {
            // Maven Central: groupId[:artifactId]. Use solrsearch.
            // For "org.apache.commons" we search by g (groupId).
            // For "org.apache.commons:lang3" we add a (artifactId).
            if let Some((group, artifact)) = package_name.split_once(':') {
                Some(format!(
                    "https://search.maven.org/solrsearch/select?q=g:{}%20AND%20a:{}&rows=1&wt=json",
                    group, artifact
                ))
            } else {
                Some(format!(
                    "https://search.maven.org/solrsearch/select?q=g:{}&rows=1&wt=json",
                    package_name
                ))
            }
        }
        "csharp" => {
            // NuGet: take top-level namespace as package name.
            // e.g., "Microsoft.Extensions.Logging" → check "Microsoft.Extensions.Logging"
            Some(format!(
                "https://api.nuget.org/v3/registration5-semver1/{}/index.json",
                package_name.to_lowercase()
            ))
        }
        "go" => {
            // Go module proxy. Lower-cased full path.
            Some(format!(
                "https://proxy.golang.org/{}/@latest",
                package_name.to_lowercase()
            ))
        }
        _ => None,
    }
}

/// Verify a batch of imports concurrently. Returns the result for each
/// (language, import_name) pair in the input order.
///
/// Designed for the scanner flow: caller passes `(language, [imports])`
/// pairs extracted from `extract_lookup_terms`, and we return status for
/// each. Imports classified as `Skipped` upfront don't consume HTTP quota.
pub async fn verify_imports(
    language: &str,
    imports: &[String],
) -> Vec<(String, ImportStatus)> {
    let mut out = Vec::with_capacity(imports.len());
    for imp in imports {
        let status = if classify_import(imp) == ImportStatus::Skipped {
            ImportStatus::Skipped
        } else {
            verify_import_with_language(language, imp).await
        };
        out.push((imp.clone(), status));
    }
    out
}

/// Suggest the correct import path for a hallucinated one by fuzzy-matching
/// against cached library names.
///
/// When a registry lookup returns `NotFound`, the LLM may have been 1-2 path
/// segments off the real package (e.g., `golang.org/x/semver` → `golang.org/x/mod/semver`,
/// `serder` → `serde`). This function queries the symbol cache for all known
/// library names and returns the closest match within a Levenshtein threshold.
///
/// Threshold scales with path length: `max(3, len/5)` capped at 10.
/// Libraries with <5 cached symbols are skipped (can't trust sparse entries).
/// Names shorter than 4 chars are skipped (too noisy for fuzzy match).
///
/// Returns `None` if cache is cold or no match within threshold.
pub fn suggest_correct_import(hallucinated: &str) -> Option<String> {
    if hallucinated.len() < 4 {
        return None;
    }

    let cache = crate::symbols::cache::SymbolCache::open().ok()?;
    let libraries = cache.list_libraries();

    let threshold = (hallucinated.len() / 5).max(3).min(10);
    let mut best: Option<(String, usize)> = None;

    for (lib, _ver, count) in &libraries {
        if *count < 5 {
            continue;
        }
        let dist = crate::scanner::levenshtein::capped(hallucinated, lib, threshold + 1);
        if dist <= threshold {
            match &best {
                Some((_, best_dist)) if dist >= *best_dist => {}
                _ => best = Some((lib.clone(), dist)),
            }
        }
    }

    best.map(|(lib, _)| lib)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_skips_relative_imports() {
        assert_eq!(classify_import("./local"), ImportStatus::Skipped);
        assert_eq!(classify_import("../parent"), ImportStatus::Skipped);
        assert_eq!(classify_import("/abs/path"), ImportStatus::Skipped);
    }

    #[test]
    fn classify_skips_cpp_headers() {
        assert_eq!(classify_import("armadillo"), ImportStatus::Skipped);
        assert_eq!(classify_import("dlib/clustering.h"), ImportStatus::Skipped);
        assert_eq!(classify_import("vector"), ImportStatus::Skipped);
        assert_eq!(classify_import("iostream"), ImportStatus::Skipped);
    }

    #[test]
    fn classify_skips_empty_and_whitespace() {
        assert_eq!(classify_import(""), ImportStatus::Skipped);
        assert_eq!(classify_import("   "), ImportStatus::Skipped);
    }

    #[test]
    fn build_url_python_handles_aliased_packages() {
        let url = build_registry_url("python", "sklearn.preprocessing").unwrap();
        assert!(url.contains("scikit-learn"), "got: {}", url);
        assert!(url.starts_with("https://pypi.org/pypi/"));

        let url = build_registry_url("python", "PIL.Image").unwrap();
        assert!(url.contains("Pillow"), "got: {}", url);
    }

    #[test]
    fn build_url_python_takes_top_level_only() {
        let url = build_registry_url("python", "langchain_core.documents").unwrap();
        assert_eq!(url, "https://pypi.org/pypi/langchain_core/json");
    }

    #[test]
    fn build_url_npm_scopes_correctly() {
        let url = build_registry_url("typescript", "@react-router/dev").unwrap();
        assert_eq!(url, "https://registry.npmjs.org/@react-router%2Fdev");

        let url = build_registry_url("javascript", "react").unwrap();
        assert_eq!(url, "https://registry.npmjs.org/react");
    }

    #[test]
    fn build_url_rust_takes_crate_name() {
        let url = build_registry_url("rust", "tokio::sync").unwrap();
        assert_eq!(url, "https://crates.io/api/v1/crates/tokio");

        let url = build_registry_url("rust", "anyhow").unwrap();
        assert_eq!(url, "https://crates.io/api/v1/crates/anyhow");
    }

    #[test]
    fn build_url_java_handles_group_only_and_group_artifact() {
        let url = build_registry_url("java", "org.apache.commons").unwrap();
        assert!(url.contains("g:org.apache.commons"));

        let url = build_registry_url("java", "org.apache.commons:lang3").unwrap();
        assert!(url.contains("g:org.apache.commons"));
        assert!(url.contains("a:lang3"));
    }

    #[test]
    fn build_url_csharp_lowercases_namespace() {
        let url = build_registry_url("csharp", "Microsoft.Extensions.Logging").unwrap();
        assert_eq!(
            url,
            "https://api.nuget.org/v3/registration5-semver1/microsoft.extensions.logging/index.json"
        );
    }

    #[test]
    fn build_url_go_uses_proxy_with_lowercased_path() {
        let url = build_registry_url("go", "github.com/prometheus/client_golang").unwrap();
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/prometheus/client_golang/@latest"
        );
    }

    #[test]
    fn build_url_returns_none_for_unsupported_language() {
        assert!(build_registry_url("cpp", "armadillo").is_none());
        assert!(build_registry_url("ruby", "rails").is_none());
        assert!(build_registry_url("php", "laravel").is_none());
    }
}
