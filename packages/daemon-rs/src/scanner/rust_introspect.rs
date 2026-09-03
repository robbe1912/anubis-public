//! Rust runtime introspection via docs.rs JSON API.
//!
//! For each imported crate, fetches type + method info from docs.rs.
//! No local Rust installation needed — all data from HTTP API.
//!
//! Pattern: for `use syn::DeriveInput` → fetch docs.rs/syn → get methods
//! on DeriveInput → verify `derive_input.method()` calls.

use std::collections::HashMap;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

/// Process-wide cache for Rust type introspection results.
/// Key: (crate_name, type_name) → ModuleInfo with methods.
static RUST_TYPE_CACHE: Lazy<Mutex<HashMap<(String, String), RustTypeInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Introspection result for one Rust type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustTypeInfo {
    pub crate_name: String,
    pub type_name: String,
    pub methods: Vec<String>,
    pub error: Option<String>,
}

/// Look up a Rust type from local SymbolCache (offline, instant).
fn lookup_rust_type_from_cache(type_name: &str) -> Option<RustTypeInfo> {
    let cache = crate::symbols::cache::SymbolCache::open().ok()?;
    let matches = cache.lookup_global(type_name);
    // Iterate candidate libraries in priority order:
    //   1. libraries classified as Rust by library_to_language
    //      (covers rust.* stdlib + crates like axum/tokio/serde)
    //   2. fallback: any library with rust.* prefix (defence in depth)
    //   3. fallback: first match (cross-language, last resort)
    //
    // Within each tier, return the FIRST library that has methods for
    // this type. Using `.find()` without checking methods would pick
    // rust.serde_json.Entry (alphabetically before rust.std.Entry)
    // even when serde_json has no Entry methods — silently dropping
    // the verification (cf. verify_rust_methods return_type_map
    // builder which already uses this iterate-and-try pattern).
    let tier0 = matches.iter()
        .filter(|m| m.library == "rust.std" || m.library == "rust.core" || m.library == "rust.alloc");
    let tier1 = matches.iter()
        .filter(|m| crate::symbols::library_to_language(&m.library) == "rust");
    let tier2 = matches.iter()
        .filter(|m| m.library.starts_with("rust."));
    let tier3 = matches.iter();
    for sym in tier0.chain(tier1).chain(tier2).chain(tier3) {
        let methods = cache.lookup_prefix(&sym.library, &format!("{}.", type_name));
        let names: Vec<String> = methods.iter().map(|m| {
            // Extract bare name from path (last segment after '.').
            m.path.rsplit('.').next().unwrap_or(&m.name).to_string()
        }).collect();
        if !names.is_empty() {
            return Some(RustTypeInfo {
                crate_name: sym.library.clone(),
                type_name: type_name.to_string(),
                methods: names,
                error: None,
            });
        }
    }
    None
}

/// Extract bare crate names from `use <crate>;` declarations in content.
/// Used by the bare-type-receiver fallback to gate HTTP escalation on
/// `use` proof (avoids runaway docs.rs fetches for unrelated identifiers).
fn find_use_crates(content: &str) -> Vec<String> {
    use regex::Regex;
    use std::sync::OnceLock;
    static USE_CRATE_RE: OnceLock<Regex> = OnceLock::new();
    let re = USE_CRATE_RE.get_or_init(|| {
        // `use <crate>;` only — excludes `use <crate>::<Type>;` and `use std::...;`.
        Regex::new(r"(?m)^\s*use\s+([a-z_][a-z0-9_]*)\s*;").unwrap()
    });
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in re.captures_iter(content) {
        let name = caps.get(1).unwrap().as_str().to_string();
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

/// Resolve a bare uppercase receiver (e.g., `UnixStream`) to (crate, type)
/// using cache first, then HTTP fallback gated on `use <crate>;` proof.
/// Returns None for non-TypeLike receivers (lowercase vars, SCREAMING_SNAKE
/// constants, project-local types) → caller skips verification cleanly.
async fn resolve_bare_type_with_use_proof(
    receiver: &str,
    local_types: &std::collections::HashSet<String>,
    use_crates: &[String],
) -> Option<(String, String)> {
    let first = receiver.chars().next()?;
    if !first.is_uppercase() {
        return None;
    }
    let is_screaming = receiver.len() >= 2
        && receiver.chars().all(|c| c.is_uppercase() || c == '_')
        && receiver.chars().filter(|c| c.is_uppercase()).count() >= 2;
    if is_screaming {
        return None;
    }
    if local_types.contains(receiver) {
        return None;
    }
    // Try cache first (instant, offline). However, cache hits with very
    // few methods (<3) are usually false positives — local project scans
    // that happened to produce a `<Type>.<one_method>` symbol entry
    // (e.g. `UnixStream.connect` from a sibling test file). A real
    // published Rust type has dozens of inherent + trait-impl methods,
    // so a 1-2 method list is a tell-tale of bogus projection. In that
    // case, fall through to HTTP via `use` proof — the disk-cached
    // rustdoc JSON for major crates (tokio, serde, axum) is fast.
    if let Some(info) = lookup_rust_type_from_cache(receiver) {
        if info.methods.len() >= 3 {
            return Some((info.crate_name, receiver.to_string()));
        }
    }
    // HTTP fallback: try each `use <crate>;` until one resolves with non-empty
    // methods. JSON path is the full impl method list (incl. trait impls) but
    // can fail for large crates (rustdoc JSON timeout / 5-10MB download) or
    // std/core types with no published JSON. HTML path is faster (~100KB
    // page) and covers those gaps — try both before declaring unresolved.
    for crate_name in use_crates {
        let json_info = introspect_rust_type(crate_name, receiver).await;
        if json_info.error.is_none() && !json_info.methods.is_empty() {
            return Some((crate_name.clone(), receiver.to_string()));
        }
        let html_info = introspect_rust_type_live(crate_name, receiver).await;
        if html_info.error.is_none() && !html_info.methods.is_empty() {
            return Some((crate_name.clone(), receiver.to_string()));
        }
    }
    None
}

/// Map receiver names to (crate, type) for Rust code.
/// Parses `let x: Type = ...` and `use crate::Type` patterns.
pub fn build_rust_receiver_map(content: &str) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();

    // Pattern: let x: CrateName::TypeName = ...
    let typed_let = regex::Regex::new(
        r"let\s+(?:mut\s+)?(\w+)\s*:\s*(?:\w+::)*([A-Z]\w+)"
    ).unwrap();
    for caps in typed_let.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let type_name = caps.get(2).unwrap().as_str().to_string();
        map.insert(receiver, (String::new(), type_name));
    }

    // Pattern: let x = CrateName::TypeName::new(...)
    let constructor = regex::Regex::new(
        r"let\s+(?:mut\s+)?(\w+)\s*=\s*(\w+)::([A-Z]\w+)::(?:new|default|from)"
    ).unwrap();
    for caps in constructor.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let crate_name = caps.get(2).unwrap().as_str().to_string();
        let type_name = caps.get(3).unwrap().as_str().to_string();
        map.insert(receiver, (crate_name, type_name));
    }

    // Pattern: let x = TypeName::new(...) (no crate prefix, e.g. String::new())
    let constructor_no_crate = regex::Regex::new(
        r"let\s+(?:mut\s+)?(\w+)\s*=\s*([A-Z]\w+)::(?:new|default|from)"
    ).unwrap();
    for caps in constructor_no_crate.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let type_name = caps.get(2).unwrap().as_str().to_string();
        // Don't overwrite if already matched by crate-qualified pattern.
        map.entry(receiver).or_insert((String::new(), type_name));
    }

    // Pattern: let x = TypeName::<Generics>::new(...) (turbofish constructor)
    // Handles HashMap::<K, V>::new(), Vec::<T>::with_capacity(), etc.
    // The greedy .* backtracks to find the last > before >::method.
    let constructor_turbofish = regex::Regex::new(
        r"let\s+(?:mut\s+)?(\w+)\s*=\s*([A-Z]\w+)::<.*>::(?:new|default|from|with_capacity)\b"
    ).unwrap();
    for caps in constructor_turbofish.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let type_name = caps.get(2).unwrap().as_str().to_string();
        map.entry(receiver).or_insert((String::new(), type_name));
    }

    map
}

/// Extract project-local type names from Rust source code.
///
/// Finds `struct Name`, `enum Name`, `trait Name`, `union Name`,
/// `type Name`, and `impl Name` definitions. Returns a set of type names
/// that are DEFINED in the code being scanned, so the method verifier
/// can skip them (project-local types have their methods defined locally,
/// not in the symbol cache).
fn extract_local_rust_types(content: &str) -> std::collections::HashSet<String> {
    use std::collections::HashSet;
    let mut types = HashSet::new();

    // Match type definitions: struct/enum/trait/union/type Name
    let def_re = regex::Regex::new(
        r"\b(?:pub\s+)?(?:pub\(crate\)\s+)?(?:struct|enum|trait|union|type)\s+([A-Z]\w*)"
    ).unwrap();

    // Match impl blocks: impl Name {  or  impl Trait for Name {
    let impl_re = regex::Regex::new(
        r"\bimpl\s+(?:[A-Z]\w*)\s+for\s+([A-Z]\w*)|\bimpl\s+([A-Z]\w*)\s*[<{]"
    ).unwrap();

    for caps in def_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            types.insert(m.as_str().to_string());
        }
    }

    for caps in impl_re.captures_iter(content) {
        // Group 1 = "impl Trait for Type", Group 2 = "impl Type"
        if let Some(m) = caps.get(1).or_else(|| caps.get(2)) {
            types.insert(m.as_str().to_string());
        }
    }

    types
}

/// Extract Rust type names from the project index.
///
/// The project index is a text blob with lines like `main.rs: TodoList`.
/// We only take entries from `.rs` files and only PascalCase names (Rust
/// type convention for struct/enum/trait/union/type). This supplements
/// [`extract_local_rust_types`] which only sees the CURRENT response content,
/// not types defined in other project files.
pub(crate) fn extract_project_rust_types(project_index: &str) -> std::collections::HashSet<String> {
    use std::collections::HashSet;
    let mut types = HashSet::new();
    for line in project_index.lines() {
        // Lines are "filename: Name"
        let Some((fname, name)) = line.split_once(": ") else {
            continue;
        };
        if !fname.ends_with(".rs") {
            continue;
        }
        let name = name.trim();
        // Include ALL identifiers (types, functions, variables, constants)
        // from .rs files. The method verifier only skips PascalCase types,
        // and the scope checker needs all defined names. Having extra
        // function/variable names in the type set is harmless — they won't
        // appear as method receivers in the receiver_map.
        if !name.is_empty()
            && name
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
        {
            types.insert(name.to_string());
        }
    }
    types
}

/// Verify Rust method calls against docs.rs API.
///
/// For each `receiver.method(` pattern where receiver is in the receiver_map,
/// fetch the type's methods from docs.rs and check if method exists.
pub async fn verify_rust_methods(
    content: &str,
    receiver_map: &HashMap<String, (String, String)>,
    project_types: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    // NOTE: receiver_map may be empty — bare-type-receiver fallback
    // (Tier 2.1) handles `use <crate>; Type.method()` patterns via
    // `use`-proof + cache + HTTP escalation.

    // Extract project-local type names from the code being scanned.
    let local_types = {
        let mut t = extract_local_rust_types(content);
        t.extend(project_types.iter().cloned());
        t
    };

    // Tier 2.1: extract `use <crate>;` declarations once for the
    // bare-type-receiver fallback's HTTP escalation gate.
    let use_crates = find_use_crates(content);

    let method_re = regex::Regex::new(
        r"(?:^|[^a-zA-Z0-9_:])(\w+)\.(\w+)\s*\("
    ).unwrap();

    let mut checked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for caps in method_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method = caps.get(2).unwrap().as_str().to_string();

        let (crate_name, type_name) = match receiver_map.get(&receiver) {
            Some(v) => v.clone(),
            None => {
                // Tier 2.1: bare-type-receiver fallback for patterns like
                // `use tokio; UnixStream.try_read_buf()`. Resolves via
                // cache first, then HTTP fallback gated on `use` proof.
                match resolve_bare_type_with_use_proof(
                    &receiver,
                    &local_types,
                    &use_crates,
                ).await {
                    Some(resolved) => resolved,
                    None => continue,
                }
            }
        };

        // Skip project-local types — methods are defined in the same codebase.
        if local_types.contains(&type_name) {
            continue;
        }

        // Skip common Rust trait methods (clone, iter, as_ref, etc.).
        // These exist on most types via trait impls but aren't listed as
        // inherent methods in docs.rs — causes false positives like
        // `todo.clone()` on a #[derive(Clone)] struct.
        static RUST_INSTANCE_TRAIT_METHODS: std::sync::OnceLock<std::collections::HashSet<&'static str>> = std::sync::OnceLock::new();
        let trait_methods = RUST_INSTANCE_TRAIT_METHODS.get_or_init(|| {
            [
                "clone", "as_ref", "as_mut", "into", "try_into",
                "iter", "iter_mut", "into_iter", "to_string", "to_owned",
                "fmt", "len", "is_empty", "contains", "eq", "ne",
                "hash", "default", "borrow", "borrow_mut",
            ].iter().copied().collect()
        });
        if trait_methods.contains(method.as_str()) {
            continue;
        }

        if !checked.insert((receiver.clone(), method.clone())) {
            continue;
        }

        // Trust cached entry only when it has enough methods to be a real
        // published type (≥3). <3 methods almost always means a false-positive
        // projection from a local project scan (e.g. `UnixStream.connect`
        // lifted from a sibling test file). Otherwise fall through to HTTP.
        // JSON path first (full impl method list incl. trait impls). HTML
        // fallback when JSON fails or returns empty — JSON path needs the
        // whole rustdoc JSON (often 5-10MB for tokio) which can time out or
        // yield no methods; HTML is one ~100KB page and works for std/core/
        // alloc where JSON isn't published.
        let info = match lookup_rust_type_from_cache(&type_name) {
            Some(cached) if cached.methods.len() >= 3 => cached,
            _ => {
                let json_info = introspect_rust_type(&crate_name, &type_name).await;
                if json_info.error.is_some() || json_info.methods.is_empty() {
                    // For typed_let patterns (crate_name="") we still need a
                    // crate to query docs.rs — guess std crate for prelude
                    // + std::* types the caller couldn't qualify.
                    let html_crate = if crate_name.is_empty() {
                        guess_std_crate_for_type(&type_name).unwrap_or(&crate_name)
                    } else {
                        crate_name.as_str()
                    };
                    if !html_crate.is_empty() {
                        introspect_rust_type_live(html_crate, &type_name).await
                    } else {
                        json_info
                    }
                } else {
                    json_info
                }
            }
        };

        if info.error.is_some() {
            continue;
        }

        if !info.methods.contains(&method) {
            // Find closest match.
            let closest = info.methods.iter()
                .map(|m| (levenshtein(&method, m), m))
                .filter(|(d, _)| *d <= 4)
                .min_by_key(|(d, _)| *d);

            match closest {
                Some((_, suggestion)) => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not a method on `{}`. Did you mean `{}`?",
                    receiver, method, method, type_name, suggestion
                )),
                None => {
                    // Council #3 finding: silent skip creates recall hole for
                    // novel invented methods. But emitting on ALL misses creates
                    // noise from incomplete HTTP-fetched method lists.
                    // Compromise: only emit advisory when method list is
                    // reasonably complete (≥10 methods = likely exhaustive).
                    // Below that, list is probably partial — stay silent.
                    if info.methods.len() >= 10 {
                        warnings.push(format!(
                            "hallucinated-method-uncertain: `{}.{}` — `{}` not in known methods for `{}` (may be incomplete list)",
                            receiver, method, method, type_name
                        ));
                    }
                }
            }
        }
    }

    // Chained method verification: receiver.method1().method2()
    // Track return types from known methods to verify chained calls.
    // Use [^;]*? instead of [^)]* to handle nested parentheses like
    // entry(Cow::Borrowed(name)) — the inner call has its own ).
    let chain_re = regex::Regex::new(
        r"(?:^|[^a-zA-Z0-9_:])(\w+)\.(\w+)\s*\(([^;]*?)\)\s*\.(\w+)\s*\("
    ).unwrap();

    // Build a return-type map: (receiver, method) → return_type
    // by looking up each known receiver's methods in cache.
    let mut return_type_map: std::collections::HashMap<(String, String), String> = std::collections::HashMap::new();
    let cache = crate::symbols::cache::SymbolCache::open().ok();
    if let Some(ref cache) = cache {
        for (receiver, (_, type_name)) in receiver_map {
            let prefix = format!("{}.", type_name);
            // Try ALL matching libraries (lookup_global returns entries
            // from multiple libraries sorted alphabetically). The type
            // might exist in both a third-party crate (no methods bundled)
            // and in stdlib (methods bundled). Try each until we find
            // methods.
            let type_syms = cache.lookup_global(type_name);
            // Iterate libraries in priority order — stdlib first, then
            // other rust-classified libraries, then rust.* prefix, then
            // anything. Without this preference, lookup_global's ORDER BY
            // library+version returns robin (Java-ported HashMap with 106
            // Java-style methods) before rust.std (real Rust HashMap with
            // entry/len/etc.). The chained-method check then fails because
            // robin's methods don't have return_type='Entry' on `entry`.
            let tier0_syms: Vec<_> = type_syms.iter()
                .filter(|s| s.library == "rust.std" || s.library == "rust.core" || s.library == "rust.alloc")
                .collect();
            let tier1_syms: Vec<_> = type_syms.iter()
                .filter(|s| crate::symbols::library_to_language(&s.library) == "rust")
                .collect();
            let tier2_syms: Vec<_> = type_syms.iter()
                .filter(|s| s.library.starts_with("rust."))
                .collect();
            let tier3_syms: Vec<_> = type_syms.iter().collect();
            let mut selected_lib: Option<&str> = None;
            for type_sym in tier0_syms.iter().chain(tier1_syms.iter()).chain(tier2_syms.iter()).chain(tier3_syms.iter()) {
                let methods = cache.lookup_prefix(&type_sym.library, &prefix);
                if methods.is_empty() {
                    continue;
                }
                selected_lib = Some(&type_sym.library);
                for m in methods {
                    if let Some(rt) = &m.return_type {
                        if !rt.is_empty() {
                            let bare = rt
                                .trim_start_matches('&')
                                .trim_start_matches("mut ")
                                .trim();
                            let bare_name = bare
                                .split(|c: char| c == '<' || c == '(' || c == ' ' || c == ',')
                                .next()
                                .unwrap_or("")
                                .trim();
                            if !bare_name.is_empty() && bare_name.len() >= 2 {
                                return_type_map.insert(
                                    (receiver.clone(), m.name.clone()),
                                    bare_name.to_string(),
                                );
                            }
                        }
                    }
                }
                break; // Found methods in this library — stop searching.
            }
            let _ = selected_lib; // suppress unused warning
        }
    }

    let mut chain_checked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for caps in chain_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method1 = caps.get(2).unwrap().as_str().to_string();
        let method2 = caps.get(4).unwrap().as_str().to_string();

        if !chain_checked.insert((receiver.clone(), method2.clone())) {
            continue;
        }

        // Resolve the return type of method1 on receiver.
        let return_type = match return_type_map.get(&(receiver.clone(), method1.clone())) {
            Some(rt) => rt.clone(),
            None => continue,
        };

        // Look up method2 on the return type. Cache first (offline,
        // instant), then live docs.rs HTML fallback for std/prelude
        // types whose crate we can guess (Option, HashMap, etc.). The
        // full JSON-based introspect_rust_type requires a known crate
        // name, which we don't have here — chain return types resolve
        // to bare names like "Option" with no crate context.
        let info = if let Some(cached) = lookup_rust_type_from_cache(&return_type) {
            cached
        } else if let Some(std_crate) = guess_std_crate_for_type(&return_type) {
            introspect_rust_type_live(std_crate, &return_type).await
        } else {
            continue; // Can't verify — return type not in cache, no crate hint.
        };

        if info.error.is_some() {
            continue;
        }

        if !info.methods.contains(&method2) {
            let closest = info.methods.iter()
                .map(|m| (levenshtein(&method2, m), m))
                .filter(|(d, _)| *d <= 3)
                .min_by_key(|(d, _)| *d);

            match closest {
                Some((_, suggestion)) => warnings.push(format!(
                    "hallucinated-method: `{}.{}().{}` — `{}` not a method on `{}`. Did you mean `{}`?",
                    receiver, method1, method2, method2, return_type, suggestion
                )),
                None => warnings.push(format!(
                    "hallucinated-method: `{}.{}().{}` — `{}` not a method on `{}`",
                    receiver, method1, method2, method2, return_type
                )),
            }
        }
    }

    warnings
}

/// Fetch a Rust type's method list by scraping docs.rs HTML.
///
/// Faster and more reliable than [`introspect_rust_type`] for one-off
/// lookups: fetches a single HTML page (~100KB) instead of the whole
/// crate's rustdoc JSON (often 5-10MB for tokio/serde/etc.). Also works
/// for std/core/alloc types where rustdoc JSON is not published.
///
/// URL pattern: `https://docs.rs/{crate}/{Type}` — docs.rs redirects to
/// the canonical module path, e.g.
///   `/tokio/UnixStream` → `/tokio/latest/tokio/net/struct.UnixStream.html`
///   `/std/Option`       → `/std/latest/std/option/struct.Option.html`
///
/// Returns method list parsed from `<h4 id="method.<name>">` headers.
/// Errors are cached too — avoids refetching types docs.rs doesn't know.
pub async fn introspect_rust_type_live(crate_name: &str, type_name: &str) -> RustTypeInfo {
    // Normalise "rust.tokio" → "tokio" so cache keys line up with the
    // JSON-based fetcher (callers may pass either form).
    let crate_normalized = crate_name.strip_prefix("rust.").unwrap_or(crate_name);
    let key = (crate_normalized.to_string(), type_name.to_string());

    // Shared cache with introspect_rust_type — whichever path populates
    // an entry first wins, the other reuses it.
    {
        let cache = RUST_TYPE_CACHE.lock().await;
        if let Some(info) = cache.get(&key) {
            return info.clone();
        }
    }

    if crate_normalized.is_empty() {
        return RustTypeInfo {
            crate_name: crate_name.to_string(),
            type_name: type_name.to_string(),
            methods: vec![],
            error: Some("crate name required for docs.rs fetch".to_string()),
        };
    }

    // Build HTTP client with same 10s timeout pattern as java_introspect.
    // reqwest follows redirects by default — required for /{crate}/{Type}
    // shortcut to land on the right module path.
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("anubis-rust-introspect/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return RustTypeInfo {
                crate_name: crate_normalized.to_string(),
                type_name: type_name.to_string(),
                methods: vec![],
                error: Some(format!("client build: {}", e)),
            };
        }
    };

    let url = format!("https://docs.rs/{}/{}", crate_normalized, type_name);

    let info = match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.text().await {
                Ok(body) if body.is_empty() => RustTypeInfo {
                    crate_name: crate_normalized.to_string(),
                    type_name: type_name.to_string(),
                    methods: vec![],
                    error: Some(format!("empty body from {}", url)),
                },
                Ok(body) => {
                    let methods = parse_rustdoc_html_methods(&body);
                    if methods.is_empty() {
                        RustTypeInfo {
                            crate_name: crate_normalized.to_string(),
                            type_name: type_name.to_string(),
                            methods: vec![],
                            error: Some(format!("no methods parsed from {}", url)),
                        }
                    } else {
                        RustTypeInfo {
                            crate_name: crate_normalized.to_string(),
                            type_name: type_name.to_string(),
                            methods,
                            error: None,
                        }
                    }
                }
                Err(e) => RustTypeInfo {
                    crate_name: crate_normalized.to_string(),
                    type_name: type_name.to_string(),
                    methods: vec![],
                    error: Some(format!("read body {}: {}", url, e)),
                },
            }
        }
        Ok(resp) => RustTypeInfo {
            crate_name: crate_normalized.to_string(),
            type_name: type_name.to_string(),
            methods: vec![],
            error: Some(format!("HTTP {} for {}", resp.status(), url)),
        },
        Err(e) => RustTypeInfo {
            crate_name: crate_normalized.to_string(),
            type_name: type_name.to_string(),
            methods: vec![],
            error: Some(format!("fetch {}: {}", url, e)),
        },
    };

    // Cache result (even errors — avoids retrying dead types per scan).
    let mut cache = RUST_TYPE_CACHE.lock().await;
    cache.insert(key, info.clone());
    info
}

/// Parse method names from rustdoc-generated HTML on docs.rs.
///
/// rustdoc emits each inherent + trait-impl method as:
///   `<h4 id="method.<name>" class="method"><code>pub fn <name>(...)</code></h4>`
///
/// Trait-impl methods may have a suffix:
///   `<h4 id="method.borrow.borrowingself">` (rare, but we strip it).
///
/// We capture only the segment immediately after `method.` (stopping at
/// the next dot) — that's the bare method name the verifier compares
/// against. Skips underscore-prefixed (compiler-generated) and dedupes
/// across inherent + trait impls.
fn parse_rustdoc_html_methods(html: &str) -> Vec<String> {
    use std::sync::OnceLock;
    use regex::Regex;

    static METHOD_RE: OnceLock<Regex> = OnceLock::new();
    let re = METHOD_RE.get_or_init(|| {
        // Match <h4 ... id="method.<name>" ...> — name stops at the next
        // dot, quote, or whitespace. Anchored on `id="method.` to avoid
        // matching arbitrary `id="..."` headers (e.g. trait headers).
        Regex::new(r#"<h4[^>]*\bid="method\.([^.".]+)"#).unwrap()
    });

    let mut methods = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for caps in re.captures_iter(html) {
        let name = caps.get(1).unwrap().as_str();
        if name.is_empty() || name.starts_with('_') {
            continue;
        }
        if seen.insert(name.to_string()) {
            methods.push(name.to_string());
        }
    }

    methods
}

/// Guess which stdlib crate hosts a well-known Rust prelude/std type.
///
/// Used by the chain + static-method fallbacks when the receiver type
/// is known but its crate isn't (e.g. `Type::method()` with no `use`
/// declaration in scope). docs.rs redirects `/std/{Type}` to the right
/// module path, so "std" works for all prelude + std::collection types.
///
/// Returns None for project-local or third-party types — we won't blindly
/// probe docs.rs for arbitrary identifiers (FP risk on miss).
fn guess_std_crate_for_type(type_name: &str) -> Option<&'static str> {
    use std::sync::OnceLock;
    use std::collections::HashSet;

    static STD_TYPES: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let std_types = STD_TYPES.get_or_init(|| {
        [
            // prelude + smart pointers
            "String", "Vec", "Box", "Arc", "Rc",
            "Option", "Result", "Cell", "RefCell", "Mutex",
            "HashMap", "HashSet", "BTreeMap", "BTreeSet", "VecDeque",
            "Cow", "Pin", "PhantomData",
            // std::fs
            "File", "OpenOptions", "DirBuilder", "Metadata", "Permissions",
            // std::path
            "Path", "PathBuf",
            // std::process
            "Command", "ExitCode", "ExitStatus", "Child", "Stdio",
            // std::time
            "Instant", "Duration", "SystemTime",
            // std::ffi
            "OsStr", "OsString", "CString", "CStr",
            // std::io
            "BufReader", "BufWriter", "Cursor", "Sink", "Empty",
            // std::net
            "TcpStream", "TcpListener", "UdpSocket",
            // std::sync
            "RwLock", "OnceLock", "Once", "Barrier", "Condvar",
            // std::thread
            "Thread", "JoinHandle", "Builder",
            // std::env
            "VarError",
            // std::error
            "Error",
        ].iter().copied().collect()
    });
    if std_types.contains(type_name) {
        Some("std")
    } else {
        None
    }
}

/// Introspect a Rust type's methods via docs.rs rustdoc JSON.
///
/// Uses the canonical docs.rs rustdoc JSON endpoint documented at
/// <https://docs.rs/about/rustdoc-json>:
///   `https://docs.rs/crate/<name>/<version>/json.gz`
///
/// Reuses [`crate::symbols::rust_fetcher::fetch_rustdoc_json`] (handles
/// gzip, version redirect, 7-day disk cache) and
/// [`crate::symbols::rust_parser::parse_rustdoc_json`] (handles the
/// rustdoc `index` schema, walks struct impl blocks including trait impls).
///
/// The legacy `https://docs.rs/api/crates/<name>` URL returned the website
/// HTML ("Bad request" for v1 path) — not a JSON API — so every fetch
/// silently failed and methods list was always empty.
pub async fn introspect_rust_type(crate_name: &str, type_name: &str) -> RustTypeInfo {
    // Normalize crate name: callers may pass either "tokio" (from
    // build_rust_receiver_map regex) or "rust.tokio" (from cache library
    // field). Strip the "rust." prefix so both forms hit the same cache
    // entry and the same docs.rs URL.
    let crate_normalized = crate_name.strip_prefix("rust.").unwrap_or(crate_name);
    let key = (crate_normalized.to_string(), type_name.to_string());

    // Check in-process cache.
    {
        let cache = RUST_TYPE_CACHE.lock().await;
        if let Some(info) = cache.get(&key) {
            return info.clone();
        }
    }

    // Cannot fetch without a crate name — receiver_map's typed_let pattern
    // leaves crate empty for unqualified `let x: Type = ...`. Caller is
    // expected to fall back to lookup_rust_type_from_cache first.
    if crate_normalized.is_empty() {
        return RustTypeInfo {
            crate_name: crate_name.to_string(),
            type_name: type_name.to_string(),
            methods: vec![],
            error: Some("crate name required for docs.rs fetch".to_string()),
        };
    }

    // Fetch rustdoc JSON (idempotent — skips if disk cache fresh < 7 days).
    let fetch_result =
        match crate::symbols::rust_fetcher::fetch_rustdoc_json(crate_normalized, None).await {
            Ok(r) => r,
            Err(e) => {
                return RustTypeInfo {
                    crate_name: crate_normalized.to_string(),
                    type_name: type_name.to_string(),
                    methods: vec![],
                    error: Some(format!("docs.rs fetch: {}", e)),
                };
            }
        };

    // Read + parse JSON from disk. tokio::fs avoids blocking the worker
    // thread on slow disk (network mounts, cold cache) — fetcher above is
    // already tokio::process, this keeps the function non-blocking end-to-end.
    let json = match tokio::fs::read_to_string(&fetch_result.raw_path).await {
        Ok(s) => s,
        Err(e) => {
            return RustTypeInfo {
                crate_name: crate_normalized.to_string(),
                type_name: type_name.to_string(),
                methods: vec![],
                error: Some(format!("read rustdoc.json: {}", e)),
            };
        }
    };

    let symbols = match crate::symbols::rust_parser::parse_rustdoc_json(
        &json,
        crate_normalized,
        &fetch_result.version,
    ) {
        Ok(s) => s,
        Err(e) => {
            return RustTypeInfo {
                crate_name: crate_normalized.to_string(),
                type_name: type_name.to_string(),
                methods: vec![],
                error: Some(format!("parse rustdoc: {}", e)),
            };
        }
    };

    // Extract inherent + trait-impl methods of the requested type.
    let methods = extract_inherent_methods(&symbols, crate_normalized, type_name);

    let info = RustTypeInfo {
        crate_name: crate_normalized.to_string(),
        type_name: type_name.to_string(),
        methods,
        error: None,
    };

    let mut cache = RUST_TYPE_CACHE.lock().await;
    cache.insert(key, info.clone());
    info
}

/// Extract inherent + trait-impl methods of `type_name` from a parsed
/// rustdoc symbol list.
///
/// `rust_parser::parse_rustdoc_json` walks every `impl` block of each
/// struct (including trait impls like `impl AsyncRead for UnixStream`)
/// and emits methods with dot-separated path `crate.TypeName.method`.
/// We match by prefix `crate.TypeName.` and take the last path segment
/// as the bare method name.
fn extract_inherent_methods(
    symbols: &[crate::symbols::types::Symbol],
    crate_name: &str,
    type_name: &str,
) -> Vec<String> {
    use crate::symbols::types::SymbolKind;

    let prefix = format!("{}.{}.", crate_name, type_name);
    let mut methods = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for sym in symbols {
        if sym.kind != SymbolKind::Method {
            continue;
        }
        if !sym.path.starts_with(&prefix) {
            continue;
        }
        // Bare method name is the last dot-separated segment of the path.
        let bare = sym.path.rsplit('.').next().unwrap_or(&sym.name);
        // Skip empty + underscore-prefixed (internal compiler-generated
        // methods like `_method` or `__macro_helper`).
        if bare.is_empty() || bare.starts_with('_') {
            continue;
        }
        // Deduplicate: trait impls can re-emit the same name (rare, but
        // possible with blanket impls).
        if seen.insert(bare.to_string()) {
            methods.push(bare.to_string());
        }
    }

    methods
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

/// Clear the type cache (for tests).
pub async fn clear_cache() {
    RUST_TYPE_CACHE.lock().await.clear();
}

/// Verify Rust static/associated method calls: TypeName::method_name(...)
///
/// General-purpose: catches hallucinated associated functions like
/// `Abortable::wrap()` when `wrap` doesn't exist on the type.
/// Real-world Rust uses associated functions extensively (String::new,
/// Vec::with_capacity, Arc::clone).
pub async fn verify_rust_static_methods(
    content: &str,
    project_types: &std::collections::HashSet<String>,
) -> Vec<String> {
    use std::collections::HashSet;

    let mut warnings = Vec::new();
    let mut checked: HashSet<String> = HashSet::new();

    // Extract project-local type names — skip static method verification
    // for types defined in the current codebase or other project files.
    let local_types = {
        let mut t = extract_local_rust_types(content);
        t.extend(project_types.iter().cloned());
        t
    };

    // Match TypeName::method_name( patterns.
    // Skip std:: (too common, would cause noise).
    let static_re = regex::Regex::new(
        r"\b([A-Z]\w+)::([a-z_]\w*)\s*\("
    ).unwrap();

    for caps in static_re.captures_iter(content) {
        let type_name = caps.get(1).unwrap().as_str();
        let method_name = caps.get(2).unwrap().as_str();
        let key = format!("{}::{}", type_name, method_name);
        if !checked.insert(key) { continue; }

        // Skip project-local types.
        if local_types.contains(type_name) {
            continue;
        }

        // Common std/prelude types. Previously skipped unconditionally
        // because the docs.rs cache lacks method data for them, causing
        // FPs on legitimate `File::create`, `Cli::parse`, etc. Now we
        // skip only when the cache has no method data for the type —
        // when we DO have data, verification is safe and catches real
        // hallucinations on these common types.
        static COMMON_STD_TYPES: std::sync::OnceLock<std::collections::HashSet<&'static str>> = std::sync::OnceLock::new();
        let std_types = COMMON_STD_TYPES.get_or_init(|| {
            [
                // std::prelude collections / smart pointers
                "String", "Vec", "Box", "Arc", "Rc",
                "Option", "Result", "Cell", "RefCell", "Mutex",
                "HashMap", "HashSet", "BTreeMap", "BTreeSet", "VecDeque",
                "Cow", "Pin", "PhantomData",
                // std::fs
                "File", "OpenOptions", "DirBuilder", "Metadata", "Permissions",
                // std::path
                "Path", "PathBuf",
                // std::process
                "Command", "ExitCode", "ExitStatus", "Child", "Stdio",
                // std::time
                "Instant", "Duration", "SystemTime",
                // std::ffi
                "OsStr", "OsString", "CString", "CStr",
                // std::io
                "BufReader", "BufWriter", "Cursor", "Sink", "Empty",
                // std::net
                "TcpStream", "TcpListener", "UdpSocket",
                // std::sync
                "RwLock", "OnceLock", "Once", "Barrier", "Condvar",
                // std::thread
                "Thread", "JoinHandle", "Builder",
                // std::env
                "VarError",
                // chrono
                "Utc", "Local", "DateTime", "NaiveDateTime", "NaiveDate",
                "NaiveTime", "Date", "TimeZone", "FixedOffset",
                // clap (derive macros generate these)
                "Cli", "Subcommand", "Arg", "ArgAction", "ArgMatches",
                "Command",  // also std::process but clap::Command too
                // serde
                "Deserializer", "Serializer",
                // std::error
                "Error",
                // tempfile
                "TempDir", "NamedTempFile",
                // dirs
                "ProjectDirs", "UserDirs", "ConfigDirs",
            ].iter().copied().collect()
        });

        // For common std types: peek cache before deciding to skip.
        // If cache has >= MIN_METHODS_FOR_VERIFICATION methods for the
        // type, we proceed with verification. Otherwise we try a live
        // docs.rs HTML fetch as fallback (catches std types whose
        // methods aren't bundled in the symbol cache — Option,
        // HashMap, etc. when the cache misses a specific crate).
        // Non-std types always proceed (they're project or 3rd-party).
        const MIN_METHODS_FOR_VERIFICATION: usize = 5;
        if std_types.contains(type_name) {
            let cache_has_data = match crate::symbols::cache::SymbolCache::open() {
                Ok(c) => {
                    let type_syms = c.lookup_global(type_name);
                    let rust_sym_peek = type_syms.iter()
                        .find(|s| crate::symbols::library_to_language(&s.library) == "rust")
                        .or_else(|| type_syms.iter().find(|s| s.library.starts_with("rust.")))
                        .or_else(|| type_syms.first());
                    rust_sym_peek.map(|s| {
                        let prefix = format!("{}.", type_name);
                        // Count ONLY method-kind entries, not types/constants.
                        // Without this filter, types with 5+ non-method entries
                        // pass the guard but fail every method check (root cause
                        // of 11 Rust FPs on clap/sqlx in E2E benchmark).
                        c.lookup_prefix(s.library.as_str(), &prefix)
                            .iter()
                            .filter(|sym| matches!(sym.kind, crate::symbols::types::SymbolKind::Method | crate::symbols::types::SymbolKind::Function | crate::symbols::types::SymbolKind::Constructor))
                            .count() >= MIN_METHODS_FOR_VERIFICATION
                    }).unwrap_or(false)
                }
                Err(_) => false,
            };
            if !cache_has_data {
                // Live fallback: fetch std type from docs.rs HTML.
                // Method names only (no return types); enough for
                // associated-function existence check.
                let info = introspect_rust_type_live("std", type_name).await;
                if info.error.is_some() || info.methods.is_empty() {
                    continue; // live also failed → skip
                }
                // Verify against live method list and short-circuit
                // before the cache-based block below (which would
                // emit a spurious FP since cache lacks methods).
                if !info.methods.iter().any(|m| m == method_name) {
                    let suggestion = info.methods.iter()
                        .map(|m| (levenshtein(method_name, m), m.as_str()))
                        .filter(|(d, _)| *d <= 4 && *d > 0)
                        .min_by_key(|(d, _)| *d)
                        .map(|(_, m)| m.to_string());
                    match suggestion {
                        Some(s) => warnings.push(format!(
                            "hallucinated-method: `{}::{}` — not found. Did you mean `{}::{}`?",
                            type_name, method_name, type_name, s)),
                        None => warnings.push(format!(
                            "hallucinated-method: `{}::{}` — not a known associated function",
                            type_name, method_name)),
                    }
                }
                continue; // verified via live → skip cache block
            }
            // Cache has data → fall through to verification below.
        }

        // Skip Rust standard trait methods that the symbol cache doesn't
        // represent as inherent methods. Without this, valid calls like
        // `Path::from(...)` (via the `From` trait) fire a false positive
        // because the cache only lists inherent methods.
        //
        // Reference: std::convert, std::clone, std::default, std::borrow, etc.
        // These are common across the entire std library + ecosystem; the
        // cache can't possibly enumerate every trait impl, so we skip
        // verification entirely.
        static RUST_TRAIT_METHODS: std::sync::OnceLock<std::collections::HashSet<&'static str>> = std::sync::OnceLock::new();
        let trait_methods = RUST_TRAIT_METHODS.get_or_init(|| {
            [
                // std::convert
                "from", "into", "try_from", "try_into", "as_ref", "as_mut",
                // std::clone
                "clone",
                // std::default
                "default",
                // Universal Rust constructor convention — Type::new() is
                // standard across the ecosystem. Flagging it as hallucinated
                // when the type exists in cache is almost always a FP.
                "new",
                // std::borrow
                "borrow", "borrow_mut",
                // std::fmt
                "fmt",
                // std::cmp
                "eq", "ne", "partial_cmp", "cmp", "hash",
                // std::iter
                "into_iter", "iter", "iter_mut",
                // std::ops
                "deref", "deref_mut", "drop", "index", "index_mut",
                "add", "sub", "mul", "div", "rem", "neg", "not",
                "bitand", "bitor", "bitxor", "shl", "shr",
                // std::str / std::string
                "from_str", "to_string",
                // Common Debug/Display
                "to_owned",
                // std::any
                "type_id",
                // std::error
                "source", "description", "cause",
                // serde traits (very common across ecosystem)
                "serialize", "deserialize",
            ].iter().copied().collect()
        });
        if trait_methods.contains(method_name) {
            continue;
        }

        // Check SymbolCache for this type + method.
        let cache = match crate::symbols::cache::SymbolCache::open() {
            Ok(c) => c,
            Err(_) => return warnings,
        };

        // Look up type in cache.
        let type_symbols = cache.lookup_global(type_name);
        if type_symbols.is_empty() {
            // Cache miss: try live docs.rs HTML before skipping. Std
            // types were already handled in the COMMON_STD_TYPES block
            // above; this catches third-party types referenced via
            // `use <crate>;` declarations (e.g. tokio::JoinHandle).
            // Try std guess first (cheap, also catches prelude types
            // the COMMON_STD_TYPES list missed), then each use-crate.
            let mut crates_to_try: Vec<String> = Vec::new();
            if let Some(std_crate) = guess_std_crate_for_type(type_name) {
                crates_to_try.push(std_crate.to_string());
            }
            crates_to_try.extend(find_use_crates(content));
            for crate_name in &crates_to_try {
                let info = introspect_rust_type_live(crate_name, type_name).await;
                if info.error.is_some() || info.methods.is_empty() {
                    continue;
                }
                if !info.methods.iter().any(|m| m == method_name) {
                    let suggestion = info.methods.iter()
                        .map(|m| (levenshtein(method_name, m), m.as_str()))
                        .filter(|(d, _)| *d <= 4 && *d > 0)
                        .min_by_key(|(d, _)| *d)
                        .map(|(_, m)| m.to_string());
                    match suggestion {
                        Some(s) => warnings.push(format!(
                            "hallucinated-method: `{}::{}` — not found. Did you mean `{}::{}`?",
                            type_name, method_name, type_name, s)),
                        None => warnings.push(format!(
                            "hallucinated-method: `{}::{}` — not a known associated function",
                            type_name, method_name)),
                    }
                }
                break; // first matching crate wins
            }
            continue;
        }
        // Prefer libraries classified as Rust (cf. lookup_rust_type_from_cache).
        // Without this filter, type_symbols[0] could be a Java/Python
        // match (sorted alphabetically) and lookup_prefix would miss
        // the real Rust methods.
        let rust_sym = type_symbols.iter()
            .find(|s| crate::symbols::library_to_language(&s.library) == "rust")
            .or_else(|| type_symbols.iter().find(|s| s.library.starts_with("rust.")))
            .unwrap_or(&type_symbols[0]);

        // Check if method exists as associated function on this type.
        // Use lookup_prefix within the type's library to find all methods
        // on this type, then check if method_name is among them.
        // Don't use lookup_global for method verification — it strips
        // dotted paths to their suffix and searches ALL libraries, so
        // lookup_global("Abortable.wrap") would match any "wrap" entry
        // in any library (false positive).
        let prefix = format!("{}.", type_name);
        let methods = cache.lookup_prefix(rust_sym.library.as_str(), &prefix);
        let found_as_member = methods.iter().any(|s| {
            // Extract bare name from path (last segment after '.').
            s.path.rsplit('.').next().unwrap_or(&s.name) == method_name
                || s.name == method_name
        });

        if !found_as_member {
            // Method not found — emit UNCERTAIN when type has methods but
            // this specific one is missing. Cache may be incomplete (e.g.,
            // crate has partial data). Per FN≫FP, uncertain warnings are
            // suppressed by forge_rust.rs filter.
            let suggestion = methods.iter()
                .map(|s| s.path.rsplit('.').next().unwrap_or(s.name.as_str()))
                .filter(|n| { let d = levenshtein(method_name, n); d <= 4 && d > 0 })
                .min_by_key(|n| levenshtein(method_name, n));

            match suggestion {
                Some(s) => warnings.push(format!(
                    "hallucinated-method-uncertain: `{}::{}` — not found. Did you mean `{}::{}`?",
                    type_name, method_name, type_name, s)),
                None => warnings.push(format!(
                    "hallucinated-method-uncertain: `{}::{}` — not a known associated function (cache may be incomplete)",
                    type_name, method_name)),
            }
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rust_receiver_map_catches_typed_let() {
        let content = "let parser: syn::DeriveInput = ...";
        let map = build_rust_receiver_map(content);
        assert_eq!(map.get("parser").map(|(_, t)| t.as_str()), Some("DeriveInput"));
    }

    #[test]
    fn build_rust_receiver_map_catches_constructor() {
        let content = "let client = reqwest::Client::new()";
        let map = build_rust_receiver_map(content);
        let entry = map.get("client").unwrap();
        assert_eq!(entry.0, "reqwest");
        assert_eq!(entry.1, "Client");
    }

    #[test]
    fn build_rust_receiver_map_skips_untyped() {
        let content = "let x = 42;";
        let map = build_rust_receiver_map(content);
        assert!(map.is_empty());
    }

    #[test]
    fn build_rust_receiver_map_handles_mut() {
        let content = "let mut buf = String::new()";
        let map = build_rust_receiver_map(content);
        assert!(map.contains_key("buf"));
    }

    #[test]
    fn build_rust_receiver_map_catches_turbofish_constructor() {
        let content = "let mut map = HashMap::<Cow<'static, str>, TypeFlags>::new();";
        let map = build_rust_receiver_map(content);
        assert_eq!(
            map.get("map").map(|(_, t)| t.as_str()),
            Some("HashMap"),
            "turbofish constructor should be caught: {:?}",
            map
        );
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("cat", "cat"), 0);
        assert_eq!(levenshtein("cat", "bat"), 1);
        assert_eq!(levenshtein("cat", "dog"), 3);
    }

    #[tokio::test]
    async fn verify_rust_static_catches_abortable_wrap() {
        let bundle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/symbol_bundle.jsonl");
        let cache = crate::symbols::cache::SymbolCache::open().unwrap();
        if cache.seed_from_jsonl(&bundle).is_err() { return; }

        let content = "let a = Abortable::wrap(inner, reg);";
        let warnings = verify_rust_static_methods(content, &Default::default()).await;
        assert!(
            warnings.iter().any(|w| w.contains("Abortable::wrap")),
            "expected Abortable::wrap warning, got: {:?}",
            warnings
        );
    }

    #[tokio::test]
    async fn verify_rust_static_passes_abortable_new() {
        let bundle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/symbol_bundle.jsonl");
        let cache = crate::symbols::cache::SymbolCache::open().unwrap();
        if cache.seed_from_jsonl(&bundle).is_err() { return; }

        let content = "let a = Abortable::new(inner, reg);";
        let warnings = verify_rust_static_methods(content, &Default::default()).await;
        assert!(
            !warnings.iter().any(|w| w.contains("Abortable::new")),
            "Abortable::new should NOT be flagged, got: {:?}",
            warnings
        );
    }

    #[tokio::test]
    async fn verify_rust_chained_catches_or_insert_default() {
        let bundle = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/symbol_bundle.jsonl");
        let cache = crate::symbols::cache::SymbolCache::open().unwrap();
        if cache.seed_from_jsonl(&bundle).is_err() { return; }

        let content = r#"
let mut map = HashMap::<Cow<'static, str>, TypeFlags>::new();
map.entry(Cow::Borrowed(name))
    .or_insert_default()
    .set_is_never_ref(true);
"#;
        let receiver_map = build_rust_receiver_map(content);
        assert!(receiver_map.contains_key("map"), "map should be in receiver_map: {:?}", receiver_map);
        let warnings = verify_rust_methods(content, &receiver_map, &Default::default()).await;
        assert!(
            warnings.iter().any(|w| w.contains("or_insert_default")),
            "expected or_insert_default warning, got: {:?}",
            warnings
        );
    }

    /// End-to-end test: fetch live tokio rustdoc JSON from docs.rs, parse,
    /// and extract methods of `UnixStream`. Verifies the rewrite of
    /// `introspect_rust_type` against a real, well-known type.
    ///
    /// `try_read_buf` is provided by `impl AsyncRead for UnixStream` — the
    /// parser must walk trait impls, not just inherent impls.
    #[tokio::test]
    #[ignore = "requires network access to docs.rs"]
    async fn introspect_rust_type_fetches_tokio_unixstream() {
        // Clear cache so we exercise the full fetch+parse path even if a
        // previous test seeded an entry.
        clear_cache().await;

        let info = introspect_rust_type("tokio", "UnixStream").await;
        assert!(info.error.is_none(), "HTTP/parse failed: {:?}", info.error);
        assert!(
            info.methods.contains(&"try_read_buf".to_string()),
            "try_read_buf missing — trait-impl walk broken. methods: {:?}",
            info.methods
        );
        // Hallucinated method must NOT appear — confirms we're not just
        // dumping every identifier from the JSON.
        assert!(
            !info.methods.contains(&"totally_made_up_method_xyz".to_string()),
            "fake method leaked into results. methods: {:?}",
            info.methods
        );
        // Sanity: UnixStream should expose many real methods.
        assert!(
            info.methods.len() >= 10,
            "expected ≥10 methods on UnixStream, got {}: {:?}",
            info.methods.len(),
            info.methods
        );
    }

    /// `extract_inherent_methods` filters by `crate.Type.method` path
    /// prefix. Unit test with synthetic symbols — no network.
    #[test]
    fn extract_inherent_methods_filters_by_path_prefix() {
        use crate::symbols::types::{Symbol, SymbolKind};

        let crate_name = "tokio";
        let type_name = "UnixStream";
        let mk = |path: &str, kind: SymbolKind, name: &str| Symbol {
            library: "tokio".into(),
            version: "1.0.0".into(),
            path: path.into(),
            name: name.into(),
            kind,
            signature: None,
            params: vec![],
            return_type: None,
            doc_text: None,
            source_file: None,
            visibility: crate::symbols::types::Visibility::Public,
            is_deprecated: false,
            deprecated_message: None,
            extracted_at: 0,
        };

        let symbols = vec![
            mk("tokio.UnixStream.try_read_buf", SymbolKind::Method, "try_read_buf"),
            mk("tokio.UnixStream.connect", SymbolKind::Method, "connect"),
            // Trait-impl method that should match.
            mk("tokio.UnixStream.poll_read", SymbolKind::Method, "poll_read"),
            // Different type — must be excluded.
            mk("tokio.TcpStream.connect", SymbolKind::Method, "connect"),
            // Underscore-prefixed — must be excluded.
            mk("tokio.UnixStream._internal", SymbolKind::Method, "_internal"),
            // Function (free fn), not a method — must be excluded.
            mk("tokio.spawn", SymbolKind::Function, "spawn"),
            // Struct definition — must be excluded (not a Method).
            mk("tokio.UnixStream", SymbolKind::Class, "UnixStream"),
        ];

        let methods = extract_inherent_methods(&symbols, crate_name, type_name);
        assert!(methods.contains(&"try_read_buf".to_string()));
        assert!(methods.contains(&"connect".to_string()));
        assert!(methods.contains(&"poll_read".to_string()));
        assert!(!methods.contains(&"_internal".to_string()));
        assert!(
            methods.iter().filter(|m| m.as_str() == "spawn").count() == 0,
            "free functions must not leak in: {:?}",
            methods
        );
        // Path filter excluded TcpStream.connect — must not double-count.
        assert_eq!(
            methods.iter().filter(|m| m.as_str() == "connect").count(),
            1,
            "connect should appear exactly once: {:?}",
            methods
        );
    }

    #[test]
    fn debug_turbofish_chain_for_delulu_miss() {
        let content = "let mut map = HashMap::<Cow<'static, str>, TypeFlags>::new();\nmap.entry(Cow::Borrowed(name)).or_insert_default();";
        let receiver_map = build_rust_receiver_map(content);
        eprintln!("DEBUG receiver_map: {:?}", receiver_map);
        assert!(receiver_map.contains_key("map"), "turbofish 'map' should be in receiver_map, got: {:?}", receiver_map);
    }

    #[tokio::test]
    async fn debug_chain_verification_emits_warning() {
        let content = "let mut map = HashMap::<Cow<'static, str>, TypeFlags>::new();\nmap.entry(Cow::Borrowed(name)).or_insert_default();";
        let receiver_map = build_rust_receiver_map(content);
        eprintln!("DEBUG receiver_map: {:?}", receiver_map);
        let all_types = std::collections::HashSet::new();
        let warnings = verify_rust_methods(content, &receiver_map, &all_types).await;
        eprintln!("DEBUG chain warnings: {:?}", warnings);
        // Should contain a warning about or_insert_default not being a method on Entry
        assert!(!warnings.is_empty(), "Expected chain warning for or_insert_default, got: {:?}", warnings);
    }

    /// `parse_rustdoc_html_methods` extracts method names from
    /// `<h4 id="method.<name>">` headers. Offline test with synthetic
    /// HTML mirroring the real rustdoc output format.
    #[test]
    fn parse_rustdoc_html_extracts_method_names() {
        let html = r#"
        <h4 id="method.new" class="method"><code>pub fn new() -&gt; Self</code></h4>
        <h4 id="method.len" class="method"><code>pub fn len(&amp;self) -&gt; usize</code></h4>
        <h4 id="method.is_empty" class="method">
            <code>pub fn is_empty(&amp;self) -&gt; bool</code>
        </h4>
        <!-- trait-impl method (rare suffix) -->
        <h4 id="method.borrow.borrowself">...</h4>
        <!-- inherent method on different type, must be excluded -->
        <h2 id="impl-T">...</h2>
        <!-- underscore-prefixed, must be excluded -->
        <h4 id="method._internal">...</h4>
        "#;
        let methods = parse_rustdoc_html_methods(html);
        assert!(methods.contains(&"new".to_string()), "new missing: {:?}", methods);
        assert!(methods.contains(&"len".to_string()), "len missing: {:?}", methods);
        assert!(methods.contains(&"is_empty".to_string()), "is_empty missing: {:?}", methods);
        assert!(methods.contains(&"borrow".to_string()), "borrow (from trait-impl) missing: {:?}", methods);
        // Underscore-prefixed must be filtered.
        assert!(!methods.iter().any(|m| m.starts_with('_')), "underscore-prefixed leaked: {:?}", methods);
        // No duplicates.
        let dedup_count = methods.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(dedup_count, methods.len(), "duplicates: {:?}", methods);
    }

    /// Empty HTML returns empty method list — no panic, no spurious names.
    #[test]
    fn parse_rustdoc_html_empty_returns_empty() {
        assert!(parse_rustdoc_html_methods("").is_empty());
        assert!(parse_rustdoc_html_methods("<html><body>no methods here</body></html>").is_empty());
    }

    /// Live fetch from docs.rs should return Option's real methods
    /// (expect, unwrap, is_some, etc.) and reject hallucinated names
    /// like `expect_with_msg`. Catches the exact miss class that
    /// motivated this fetcher.
    #[tokio::test]
    #[ignore = "requires network access to docs.rs"]
    async fn introspect_rust_type_live_fetches_std_option() {
        clear_cache().await;
        let info = introspect_rust_type_live("std", "Option").await;
        assert!(info.error.is_none(), "fetch failed: {:?}", info.error);
        // Real Option methods.
        for expected in &["expect", "unwrap", "is_some", "is_none", "map", "and_then"] {
            assert!(
                info.methods.iter().any(|m| m == *expected),
                "expected `{}` in Option methods, got: {:?}",
                expected,
                info.methods
            );
        }
        // Hallucinated method must NOT appear.
        assert!(
            !info.methods.iter().any(|m| m == "expect_with_msg"),
            "hallucinated method leaked into Option: {:?}",
            info.methods
        );
        // Sanity: Option has many inherent methods.
        assert!(info.methods.len() >= 10, "expected ≥10 methods on Option, got {}: {:?}", info.methods.len(), info.methods);
    }

    /// guess_std_crate_for_type returns "std" for known prelude types
    /// and None for project-local / unknown identifiers.
    #[test]
    fn guess_std_crate_returns_std_for_prelude_types() {
        assert_eq!(guess_std_crate_for_type("Option"), Some("std"));
        assert_eq!(guess_std_crate_for_type("HashMap"), Some("std"));
        assert_eq!(guess_std_crate_for_type("Vec"), Some("std"));
        assert_eq!(guess_std_crate_for_type("TcpListener"), Some("std"));
        // Unknown / project-local types.
        assert_eq!(guess_std_crate_for_type("MyStruct"), None);
        assert_eq!(guess_std_crate_for_type("DeriveInput"), None);
        assert_eq!(guess_std_crate_for_type("lowercase_var"), None);
    }

    /// Regression: verify_rust_methods must catch a typo on tokio's
    /// UnixStream when only `use tokio;` is present (no explicit
    /// `let stream: UnixStream`). Previously failed because cache lookup
    /// returned a 1-method `robin` library entry (false-positive
    /// projection from local scan) and the JSON fallback never fired.
    #[tokio::test]
    async fn verify_rust_methods_catches_tokio_unixstream_typo_via_use_proof() {
        let content = "// Using tokio\nuse tokio;\n\nUnixStream.ry_read_buf()\n";
        let receiver_map = build_rust_receiver_map(content);
        let local_types = extract_local_rust_types(content);
        let warnings = verify_rust_methods(content, &receiver_map, &local_types).await;
        assert!(
            warnings.iter().any(|w| w.contains("ry_read_buf") && w.contains("try_read_buf")),
            "expected ry_read_buf typo warning with try_read_buf suggestion, got: {:?}",
            warnings
        );
    }
}
