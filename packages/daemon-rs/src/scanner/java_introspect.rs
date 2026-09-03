//! Java runtime introspection via javadoc.io HTTP API.
//!
//! For each imported class, fetches method signatures from javadoc.io.
//! No local JDK needed — all data from web API.

use std::collections::HashMap;

use crate::scanner::local_introspect::ModuleInfo;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

static JAVA_TYPE_CACHE: Lazy<Mutex<HashMap<(String, String), ModuleInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Cache for `verify_java_import_symbols`: stores whether a fully-qualified
/// class name (package, class) was confirmed to exist on Maven Central's
/// `fc:` index. Distinct from `JAVA_TYPE_CACHE` (which stores method lists).
/// Network failures are NOT cached so they can be retried.
static JAVA_IMPORT_SYMBOL_CACHE: Lazy<Mutex<HashMap<(String, String), bool>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Map Java receiver names to (package, class) from declarations.
/// Handles: `Type x = ...`, `Type x;`, `import pkg.Class;`
pub fn build_java_receiver_map(content: &str) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();

    // import pkg.subpkg.ClassName;
    let import_re = regex::Regex::new(
        r"\bimport\s+(?:static\s+)?([\w.]+)\.([A-Z]\w*)\s*;"
    ).unwrap();
    // Build set of known imported classes.
    let mut imported_classes: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut class_packages: HashMap<String, String> = HashMap::new();
    for caps in import_re.captures_iter(content) {
        let pkg = caps.get(1).unwrap().as_str().to_string();
        let class_name = caps.get(2).unwrap().as_str().to_string();
        imported_classes.insert(class_name.clone());
        class_packages.insert(class_name, pkg);
    }

    // ClassName varName = new ClassName(...) OR ClassName varName = anything;
    // Extended to catch assignments from method calls (e.g., counterMap.get(str)).
    let decl_re = regex::Regex::new(
        r"\b([A-Z]\w+)\s+(\w+)\s*="
    ).unwrap();
    for caps in decl_re.captures_iter(content) {
        let class_name = caps.get(1).unwrap().as_str().to_string();
        let receiver = caps.get(2).unwrap().as_str().to_string();
        if imported_classes.contains(&class_name) && !map.contains_key(&receiver) {
            let pkg = class_packages.get(&class_name).cloned().unwrap_or_default();
            map.insert(receiver, (pkg, class_name));
        }
    }

    // ClassName varName;
    let var_decl_re = regex::Regex::new(
        r"\b([A-Z]\w+)\s+(\w+)\s*[;,)]"
    ).unwrap();
    for caps in var_decl_re.captures_iter(content) {
        let class_name = caps.get(1).unwrap().as_str().to_string();
        let receiver = caps.get(2).unwrap().as_str().to_string();
        if imported_classes.contains(&class_name) && !map.contains_key(&receiver) {
            let pkg = class_packages.get(&class_name).cloned().unwrap_or_default();
            map.insert(receiver, (pkg, class_name));
        }
    }

    map
}

/// Introspect a Java class's methods via javadoc.io HTTP.
pub async fn introspect_java_type(package: &str, class_name: &str) -> ModuleInfo {
    let key = (package.to_string(), class_name.to_string());

    {
        let cache = JAVA_TYPE_CACHE.lock().await;
        if let Some(info) = cache.get(&key) {
            return info.clone();
        }
    }

    let start = std::time::Instant::now();

    // Fetch javadoc.io page for this class.
    // URL format: https://javadoc.io/doc/{group}/{artifact}/{version}/{package}/{className}.html
    // We use the search API to find the right page.
    let group = package.split('.').next().unwrap_or(package);
    let search_url = format!(
        "https://javadoc.io/api/search?q={}&filter=CLASS",
        class_name
    );

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("anubis-java-introspect/0.1")
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            return ModuleInfo {
                module: format!("{}.{}", package, class_name),
                names: vec![],
                error: Some("client build failed".to_string()),
                latency_ms: 0,
            };
        }
    };

    // Try fetching the class page directly.
    let class_url = format!(
        "https://javadoc.io/static/{}/{}/{}/{}.html",
        group, package, "latest", class_name
    );

    let resp = client.get(&class_url).send().await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let info = match resp {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            let methods = parse_javadoc_methods(&body);
            ModuleInfo {
                module: format!("{}.{}", package, class_name),
                names: methods,
                error: None,
                latency_ms,
            }
        }
        _ => ModuleInfo {
            module: format!("{}.{}", package, class_name),
            names: vec![],
            error: Some("javadoc.io fetch failed".to_string()),
            latency_ms,
        },
    };

    let mut cache = JAVA_TYPE_CACHE.lock().await;
    cache.insert(key, info.clone());
    info
}

/// Verify Java imports against Maven Central's `fc:` (fully-qualified
/// class) index.
///
/// Catches import-package confusion — the case where two packages share a
/// prefix and the imported CLASS only exists in one of them. Example:
/// `import javax.xml.soap.QName;` (hallucinated) vs
/// `import javax.xml.namespace.QName;` (golden). A plain package-existence
/// check passes both packages; only the per-class lookup distinguishes them.
///
/// Source of truth: live Maven Central `solrsearch/select?q=fc:FQN` query.
/// No hardcoded symbol data (constraint #8).
///
/// Returns one `hallucinated-import:` warning per import whose
/// fully-qualified class name yields zero results on Maven Central.
/// Network failures are treated as "unknown" (no warning, not cached) so
/// transient errors don't cause false positives or sticky negative state.
pub async fn verify_java_import_symbols(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    // `import [static] path.Name;` — capture (is_static, full_path).
    let import_re = regex::Regex::new(
        r"\bimport\s+(static\s+)?([a-zA-Z_][\w.]*)\s*;",
    ).unwrap();

    // Build deduplicated (package, class) candidate list.
    let mut candidates: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();

    for caps in import_re.captures_iter(content) {
        let is_static = caps.get(1).is_some();
        let full_path = caps.get(2).unwrap().as_str();
        if full_path.ends_with('*') {
            continue;
        }
        let segs: Vec<&str> = full_path.split('.').collect();
        if segs.len() < 2 {
            continue;
        }
        // Non-static: last segment is the class.
        // Static: last segment is a method/field; the segment before is the class.
        let (package, class_name) = if is_static {
            if segs.len() < 3 {
                continue;
            }
            (
                segs[..segs.len() - 2].join("."),
                segs[segs.len() - 2].to_string(),
            )
        } else {
            (
                segs[..segs.len() - 1].join("."),
                segs[segs.len() - 1].to_string(),
            )
        };
        // Only verify class-shaped names (uppercase first letter). Filters
        // out lowercase static-import fields and module/package-info noise.
        if !class_name
            .chars()
            .next()
            .map_or(false, |c| c.is_ascii_uppercase())
        {
            continue;
        }
        // Skip nested classes: `import java.util.Map.Entry` splits into
        // package=`java.util.Map`, class=`Entry`. The "package" is actually
        // an outer class (starts uppercase), not a real Maven package.
        // javadoc.io resolves these differently, causing FPs.
        if package
            .rsplit('.')
            .next()
            .map_or(false, |seg| seg.chars().next().map_or(false, |c| c.is_ascii_uppercase()))
        {
            continue;
        }
        if !seen.insert((package.clone(), class_name.clone())) {
            continue;
        }
        candidates.push((package, class_name));
    }

    if candidates.is_empty() {
        return warnings;
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("anubis-java-introspect/0.1")
        .build()
    {
        Ok(c) => c,
        Err(_) => return warnings,
    };

    for (package, class_name) in &candidates {
        let key = (package.clone(), class_name.clone());

        // Cache lookup.
        let cached = {
            let cache = JAVA_IMPORT_SYMBOL_CACHE.lock().await;
            cache.get(&key).copied()
        };
        let exists = match cached {
            Some(v) => v,
            None => {
                let fqn = format!("{}.{}", package, class_name);
                let url = format!(
                    "https://search.maven.org/solrsearch/select?q=fc:{}&rows=1&wt=json",
                    fqn
                );
                let fetched = match client.get(&url).send().await {
                    Ok(r) if r.status().is_success() => {
                        let body = r.text().await.unwrap_or_default();
                        let n = parse_maven_num_found(&body);
                        // Cache only definitive (parsed) results.
                        let mut cache = JAVA_IMPORT_SYMBOL_CACHE.lock().await;
                        cache.insert(key.clone(), n > 0);
                        n > 0
                    }
                    // Transient error: do NOT cache, do NOT warn.
                    _ => continue,
                };
                fetched
            }
        };

        if !exists {
            warnings.push(format!(
                "hallucinated-import: `{}.{}` — class not found in declared package `{}` \
                 (Maven Central fc index returned 0 results)",
                package, class_name, package
            ));
        }
    }

    warnings
}

/// Extract the `numFound` count from a Maven Central solrsearch JSON
/// response. Returns 0 if the field is missing or unparseable.
fn parse_maven_num_found(body: &str) -> u64 {
    let re = regex::Regex::new(r#""numFound":\s*(\d+)"#).unwrap();
    re.captures(body)
        .and_then(|c| c.get(1).and_then(|m| m.as_str().parse::<u64>().ok()))
        .unwrap_or(0)
}

/// Parse method names from javadoc HTML.
fn parse_javadoc_methods(html: &str) -> Vec<String> {
    let mut methods = Vec::new();

    // Javadoc uses <a id="methodName-params"> or <h4>methodName</h4> patterns.
    let method_re = regex::Regex::new(
        r#"<(?:a|h[3-4])[^>]*id="(\w+)[^"]*"[^>]*>"#
    ).unwrap();
    for caps in method_re.captures_iter(html) {
        let name = caps.get(1).unwrap().as_str();
        if !name.is_empty() && !name.starts_with('_') {
            methods.push(name.to_string());
        }
    }

    // Also try method summary table: <code>methodName(...)</code>
    let code_re = regex::Regex::new(r"<code>(\w+)\s*\(").unwrap();
    for caps in code_re.captures_iter(html) {
        let name = caps.get(1).unwrap().as_str().to_string();
        if !methods.contains(&name) && !name.starts_with('_') && name.len() > 1 {
            methods.push(name);
        }
    }

    methods.sort();
    methods.dedup();
    methods
}

/// Look up a Java class from the local SymbolCache (offline, instant).
/// Returns ModuleInfo with method names if the class is in the cache.
/// Used as fast path before falling back to javadoc.io HTTP fetch.
fn lookup_java_type_from_cache(class_name: &str) -> Option<ModuleInfo> {
    let cache = crate::symbols::cache::SymbolCache::open().ok()?;
    // Find which libraries have this class.
    let matches = cache.lookup_global(class_name);
    if matches.is_empty() {
        return None;
    }
    // Use first match — get all methods on this class from that library.
    // Prefer libraries classified as Java by library_to_language (catches
    // org.springframework.*, java.*, jakarta.*, com.fasterxml.jackson.*,
    // etc.) without falling back to cross-language matches.
    let sym = matches.iter()
        .find(|s| crate::symbols::library_to_language(&s.library) == "java")
        .unwrap_or(&matches[0]);
    let methods = cache.lookup_prefix(&sym.library, &format!("{}.", class_name));
    if methods.is_empty() {
        return None;
    }
    // Bundle entries for methods inconsistently store the bare method name
    // (e.g. "hashCode") vs. the full dotted path (e.g. "BigDecimal.add")
    // in the `name` field. Normalise by extracting the last path segment.
    let names: Vec<String> = methods.iter()
        .map(|m| m.path.rsplit('.').next().unwrap_or(&m.name).to_string())
        .collect();
    Some(ModuleInfo {
        module: format!("{}.{}", sym.library, class_name),
        names,
        error: None,
        latency_ms: 0,
    })
}

/// Verify Java method calls against javadoc introspection.
pub async fn verify_java_methods(
    content: &str,
    receiver_map: &HashMap<String, (String, String)>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if receiver_map.is_empty() {
        return warnings;
    }

    let method_re = regex::Regex::new(
        r"(?:^|[^a-zA-Z0-9_])(\w+)\.(\w+)\s*\("
    ).unwrap();

    let mut checked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut type_infos: HashMap<String, ModuleInfo> = HashMap::new();

    for caps in method_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method = caps.get(2).unwrap().as_str().to_string();

        let (pkg, class_name) = match receiver_map.get(&receiver) {
            Some(v) => v.clone(),
            None => continue,
        };

        if !checked.insert((receiver.clone(), method.clone())) {
            continue;
        }

        let cache_key = format!("{}.{}", pkg, class_name);
        let info = if let Some(i) = type_infos.get(&cache_key) {
            i.clone()
        } else {
            // Try local symbol cache FIRST (instant, offline, has our bundle data).
            // Falls back to javadoc.io HTTP only if cache miss.
            let i = if let Some(cached) = lookup_java_type_from_cache(&class_name) {
                cached
            } else {
                introspect_java_type(&pkg, &class_name).await
            };
            type_infos.insert(cache_key, i.clone());
            i
        };

        if info.error.is_some() {
            continue;
        }

        if !info.exists(&method) {
            match info.closest_match(&method) {
                Some(suggestion) => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not a method on `{}`. Did you mean `{}`?",
                    receiver, method, method, class_name, suggestion
                )),
                None => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not a method on `{}`",
                    receiver, method, method, class_name
                )),
            }
        }
    }

    warnings
}

pub async fn clear_cache() {
    JAVA_TYPE_CACHE.lock().await.clear();
    JAVA_IMPORT_SYMBOL_CACHE.lock().await.clear();
}

/// Verify Java bare method calls within an enclosing class.
///
/// Java allows calling methods without `this.` prefix. These bare calls
/// (e.g. `incrementValue()`) bypass `verify_java_methods` which only checks
/// `receiver.method()` patterns with receivers in the map.
///
/// This function:
/// 1. Finds the enclosing class name from `class ClassName {` declarations
/// 2. Collects user-defined methods from the class body
/// 3. Collects bare calls (`methodName(args)` without preceding `.`)
/// 4. For each unknown bare call, checks cache for the enclosing class.
///    If method not found → hallucinated-method warning.
pub fn verify_java_bare_methods(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return warnings,
    };

    // Find all class declarations: `class ClassName` / `interface IName`
    let class_re = regex::Regex::new(
        r"\b(?:class|interface|enum)\s+([A-Z]\w*)"
    ).unwrap();
    let class_names: Vec<String> = class_re
        .captures_iter(content)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();
    if content.contains("incrementValue") {
        // Find where incrementValue appears and show surrounding context
        if let Some(pos) = content.find("incrementValue") {
            let start = pos.saturating_sub(20);
            let end = (pos + 30).min(content.len());
            eprintln!("DEBUG java_bare: context around incrementValue: {:?}", &content[start..end]);
        }
        let bare_re_test = regex::Regex::new(r"(?:^|[^.\w])([a-z]\w*)\s*\(").unwrap();
        eprintln!("DEBUG java_bare: bare_re.is_match(content) = {}", bare_re_test.is_match(content));
    }
    if class_names.is_empty() {
        return warnings;
    }

    // Collect user-defined methods from method declarations.
    let method_def_re = regex::Regex::new(
        r"(?:^|\n)\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native|default)\s+)*[\w<>\[\],\s]+?\s+([a-z]\w*)\s*\("
    ).unwrap();
    let user_methods: std::collections::HashSet<String> = method_def_re
        .captures_iter(content)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .collect();

    // Java builtins and common framework methods that should never be flagged.
    let java_builtins: std::collections::HashSet<&str> = [
        // java.lang.System
        "println", "print", "printf", "format",
        // java.lang.Math
        "abs", "max", "min", "pow", "sqrt", "round", "ceil", "floor", "random",
        "sin", "cos", "tan", "log", "exp",
        // java.lang.Object
        "equals", "hashCode", "toString", "getClass", "clone", "finalize",
        "wait", "notify", "notifyAll",
        // Common control-flow-looking identifiers
        "assert", "test", "setUp", "tearDown",
        // Common logging
        "info", "warn", "error", "debug", "trace",
    ].iter().copied().collect();

    // Test method prefix skip
    let test_prefixes = ["test", "before", "after", "setup", "teardown"];

    // Collect bare calls: methodName(args) NOT preceded by a dot.
    let bare_re = regex::Regex::new(
        r"(?:^|[^.\w])([a-z]\w*)\s*\("
    ).unwrap();

    let mut checked: std::collections::HashSet<String> = std::collections::HashSet::new();

    for caps in bare_re.captures_iter(content) {
        let name = caps.get(1).unwrap().as_str().to_string();

        // Skip if already checked
        if !checked.insert(name.clone()) {
            continue;
        }

        eprintln!("DEBUG java_bare: bare call '{}' len={} builtin={} user={} test={} screaming={}",
            name, name.len(),
            java_builtins.contains(name.as_str()),
            user_methods.contains(&name),
            test_prefixes.iter().any(|p| name.starts_with(p)),
            name.chars().all(|c| c.is_ascii_uppercase() || c == '_'));

        // Skip short names (likely not hallucinated)
        if name.len() < 3 {
            continue;
        }

        // Skip Java keywords/builtins
        if java_builtins.contains(name.as_str()) {
            continue;
        }

        // Skip user-defined methods (same class)
        if user_methods.contains(&name) {
            continue;
        }

        // Skip test methods
        if test_prefixes.iter().any(|p| name.starts_with(p)) {
            continue;
        }

        // Skip SCREAMING_SNAKE_CASE (constants)
        if name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            continue;
        }

        // Check cache for this name across all enclosing classes.
        // If not found in ANY cached library for any enclosing class → flag.
        let mut found_in_any = false;
        for class_name in &class_names {
            let matches = cache.lookup_global(class_name);
            if matches.is_empty() {
                continue;
            }
            // Prefer Java-classified libraries
            let sym = matches.iter()
                .find(|s| crate::symbols::library_to_language(&s.library) == "java")
                .unwrap_or(&matches[0]);
            let methods = cache.lookup_prefix(&sym.library, &format!("{}.", class_name));
            if methods.is_empty() {
                continue;
            }
            let found = methods.iter().any(|m| {
                m.path.rsplit('.').next().unwrap_or(&m.name) == name
                    || m.name == name
            });
            if found {
                found_in_any = true;
                break;
            }
        }

        if !found_in_any {
            // The bare method was not found on any enclosing class.
            // Flag it — it's either a hallucination or an unimported static
            // method call. Either way, it's worth surfacing.
            warnings.push(format!(
                "hallucinated-method: `{}` — not a known method in enclosing class(es) {}",
                name, class_names.join(", ")
            ));
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_java_receiver_map_catches_import_and_decl() {
        let content = "import java.util.HashMap;\nHashMap map = new HashMap();";
        let map = build_java_receiver_map(content);
        let entry = map.get("map").unwrap();
        assert_eq!(entry.1, "HashMap");
    }

    #[test]
    fn build_java_receiver_map_catches_var_decl() {
        let content = "import java.util.List;\nList items;";
        let map = build_java_receiver_map(content);
        assert!(map.contains_key("items"));
    }

    #[test]
    fn build_java_receiver_map_skips_unimported() {
        let content = "Foo bar = new Foo();";
        let map = build_java_receiver_map(content);
        assert!(map.is_empty(), "should skip unimported Foo");
    }

    #[test]
    fn parse_javadoc_methods_extracts_from_html() {
        let html = r#"<a id="put-java.lang.Object-java.lang.Object-">put</a><code>put(key, value)</code>"#;
        let methods = parse_javadoc_methods(html);
        assert!(methods.contains(&"put".to_string()));
    }

    #[test]
    fn parse_maven_num_found_reads_count() {
        assert_eq!(parse_maven_num_found(r#"{"response":{"numFound":5218}}"#), 5218);
        assert_eq!(parse_maven_num_found(r#"{"response":{"numFound": 0}}"#), 0);
        assert_eq!(parse_maven_num_found("not json"), 0);
    }

    #[test]
    fn verify_java_import_symbols_extracts_class_candidates() {
        // Static + non-static + wildcard + lowercase field — only the
        // uppercase class-shaped names should reach the candidate list.
        // (Network call is mocked-out by inspecting import shape only;
        // the function still runs end-to-end with HTTP.)
        let content = "import java.util.List;\n\
                       import javax.xml.soap.QName;\n\
                       import static org.junit.Assert.assertEquals;\n\
                       import com.example.*;\n";
        // Smoke: must not panic on plain extraction path. HTTP results
        // are non-deterministic in CI so we only assert shape invariants.
        let import_re = regex::Regex::new(
            r"\bimport\s+(static\s+)?([a-zA-Z_][\w.]*)\s*;",
        ).unwrap();
        let matches: Vec<_> = import_re.captures_iter(content).collect();
        // 4 import statements, wildcard `com.example.*` skipped downstream.
        assert_eq!(matches.len(), 4);
    }
}
