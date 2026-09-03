//! TypeScript/JavaScript runtime introspection.
//!
//! Equivalent of Python's `local_introspect.rs` but for TypeScript. Uses
//! Node.js `require()` / dynamic `import()` to enumerate a package's
//! exports at runtime — same principle as Python's `dir(module)`.
//!
//! Catches DELULU method hallucinations like:
//!   - `st.text_field(` vs `st.text_input` on streamlit
//!   - `router.locate(` vs `router.find` on @react-router
//!   - `useEffectState(` vs `useState` on react
//!
//! Requires Node.js installed. Falls back gracefully if not available.

use std::collections::{HashMap, HashSet};
use std::process::Stdio;
use std::time::Duration;

use once_cell::sync::Lazy;
use serde::Deserialize;
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::scanner::local_introspect::ModuleInfo;

/// Per-process TS introspection cache. Same pattern as Python's
/// INTROSPECT_CACHE — avoids re-running `node -e require()` for every
/// response.
static TS_INTROSPECT_CACHE: Lazy<Mutex<HashMap<String, ModuleInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Per-process cache for Node.js GLOBAL prototype introspection.
/// Distinct from TS_INTROSPECT_CACHE so package errors don't pollute
/// prototype lookups (different keys: `global::Response` vs `react`).
static TS_GLOBAL_CACHE: Lazy<Mutex<HashMap<String, ModuleInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// DOM/Node global classes whose prototype methods we can verify at
/// runtime via `Object.getOwnPropertyNames(GlobalClass.prototype)`.
/// Used by `build_ts_factory_receiver_map` to decide which `new X(...)`
/// constructions are introspectable.
///
/// Conservative — only well-standardized globals. Adding app-level
/// classes here would cause false positives (we'd verify against the
/// installed Node version, not the user's expected API).
static GLOBAL_CLASSES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        // Fetch API (undici / browser).
        "Response",
        "Request",
        "Headers",
        "FormData",
        // Abort API.
        "AbortController",
        "AbortSignal",
        // URL / encoding.
        "URL",
        "URLSearchParams",
        "TextEncoder",
        "TextDecoder",
        // Streams.
        "ReadableStream",
        "WritableStream",
        "TransformStream",
        // Binary.
        "Blob",
        // Standard built-ins (stable across Node versions).
        "Date",
        "RegExp",
        "Map",
        "Set",
        "Promise",
        "WeakMap",
        "WeakSet",
        "Array",
    ]
    .iter()
    .copied()
    .collect()
});

/// Introspect a TypeScript/JavaScript package via Node.js.
///
/// Tries `require()` first (CommonJS), falls back to dynamic `import()`
/// (ESM). Returns ModuleInfo with exported names or error.
///
/// `package_name` should be the npm package name (e.g., "react",
/// "@react-router/dev", "lodash").
pub async fn introspect_ts_module(package_name: &str, project_root: &str) -> ModuleInfo {
    // Check cache first — but ONLY for successful introspections.
    // Error results (package not found) are NOT cached because the package
    // might be found from a different project_root with node_modules.
    {
        let cache = TS_INTROSPECT_CACHE.lock().await;
        if let Some(info) = cache.get(package_name) {
            if info.error.is_none() {
                return info.clone();
            }
        }
    }

    let start = std::time::Instant::now();

    // Sanitize package name to prevent injection (only allow npm-safe chars).
    let sanitized = package_name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '@' || *c == '/' || *c == '-' || *c == '_' || *c == '.')
        .collect::<String>();
    if sanitized != package_name || package_name.is_empty() {
        let info = ModuleInfo {
            module: package_name.to_string(),
            names: vec![],
            error: Some("invalid package name".to_string()),
            latency_ms: start.elapsed().as_millis() as u64,
        };
        let mut cache = TS_INTROSPECT_CACHE.lock().await;
        cache.insert(package_name.to_string(), info.clone());
        return info;
    }

    // Node.js script: try require() then import(), output JSON.
    // Using IIFE wrapper to handle both sync and async paths.
    let script = format!(
        r#"(async () => {{
  try {{
    const m = require('{pkg}');
    const keys = m && typeof m === 'object'
      ? Object.keys(m).filter(k => !k.startsWith('_'))
      : [];
    process.stdout.write(JSON.stringify({{names: keys, error: null}}));
  }} catch(e1) {{
    try {{
      const m = await import('{pkg}');
      const keys = m && typeof m === 'object'
        ? Object.keys(m).filter(k => !k.startsWith('_'))
        : [];
      process.stdout.write(JSON.stringify({{names: keys, error: null}}));
    }} catch(e2) {{
      process.stdout.write(JSON.stringify({{names: [], error: e2.message}}));
    }}
  }}
}})();
"#,
        pkg = package_name.replace('\'', "\\'")
    );

    let result = crate::scanner::command_hidden_tokio("node")
        .arg("-e")
        .arg(&script)
        .current_dir(project_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await;

    let latency_ms = start.elapsed().as_millis() as u64;

    let info = match result {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                ModuleInfo {
                    module: package_name.to_string(),
                    names: vec![],
                    error: Some(format!(
                        "node exit {:?}: {}",
                        output.status,
                        stderr.lines().next().unwrap_or("")
                    )),
                    latency_ms,
                }
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                #[derive(Deserialize)]
                struct Out {
                    names: Vec<String>,
                    error: Option<String>,
                }
                match serde_json::from_str::<Out>(stdout.trim()) {
                    Ok(parsed) => ModuleInfo {
                        module: package_name.to_string(),
                        names: parsed.names,
                        error: parsed.error,
                        latency_ms,
                    },
                    Err(e) => ModuleInfo {
                        module: package_name.to_string(),
                        names: vec![],
                        error: Some(format!(
                            "parse JSON: {e} (raw: {})",
                            crate::scanner::safe_slice_to(&stdout, 200)
                        )),
                        latency_ms,
                    },
                }
            }
        }
        Err(e) => ModuleInfo {
            module: package_name.to_string(),
            names: vec![],
            error: Some(format!("spawn node: {e}")),
            latency_ms,
        },
    };

    // Only cache successful introspections. Error results are NOT cached
    // because the package might be found from a different project_root.
    if info.error.is_none() {
        let mut cache = TS_INTROSPECT_CACHE.lock().await;
        cache.insert(package_name.to_string(), info.clone());
    }
    info
}

/// Verify TypeScript method calls against introspected module exports.
///
/// Takes method calls (receiver, method_name) + import alias map
/// (e.g., {"st": "streamlit"}). For each method call where the receiver
/// is a known import alias:
///   1. Introspect the aliased package
///   2. Check if method_name is in the package's exports
///   3. Flag if not found (with closest match suggestion)
///
/// Returns warnings ready for forge_pipeline.
pub async fn verify_ts_methods(
    content: &str,
    alias_map: &HashMap<String, String>,
    project_root: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if alias_map.is_empty() {
        return warnings;
    }

    // Extract method calls: receiver.method( pattern.
    // Use regex to find all `alias.methodName(` occurrences.
    let method_re =
        regex::Regex::new(r"(?:^|[^a-zA-Z0-9_])([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(")
            .unwrap();

    let mut checked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    let mut module_infos: HashMap<String, ModuleInfo> = HashMap::new();

    for caps in method_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method = caps.get(2).unwrap().as_str().to_string();

        // Only check if receiver is a known import alias.
        let package_name = match alias_map.get(&receiver) {
            Some(pkg) => pkg.clone(),
            None => continue,
        };

        // Dedupe (same receiver+method seen before).
        if !checked.insert((receiver.clone(), method.clone())) {
            continue;
        }

        // Get or introspect the module.
        let info = if let Some(i) = module_infos.get(&package_name) {
            i.clone()
        } else {
            let i = introspect_ts_module(&package_name, project_root).await;
            module_infos.insert(package_name.clone(), i.clone());
            i
        };

        // Skip if module had an error (package not installed).
        if info.error.is_some() {
            continue;
        }

        // Check if method exists in module exports.
        if !info.exists(&method) {
            match info.closest_match(&method) {
                Some(suggestion) => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not in module `{}`. Did you mean `{}`?",
                    receiver, method, method, package_name, suggestion
                )),
                None => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not in module `{}`",
                    receiver, method, method, package_name
                )),
            }
        }
    }

    warnings
}

/// Build import alias map from TypeScript import statements.
///
/// Extracts `import X from 'pkg'`, `import { X } from 'pkg'`,
/// `import * as X from 'pkg'` patterns.
pub fn build_ts_alias_map(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // import X from 'pkg'  (default import with binding)
    let default_re = regex::Regex::new(
        r#"import\s+(\w+)\s+from\s+['"]([^'"]+)['"]"#,
    )
    .unwrap();
    for caps in default_re.captures_iter(content) {
        let alias = caps.get(1).unwrap().as_str().to_string();
        let pkg = caps.get(2).unwrap().as_str().to_string();
        if !pkg.starts_with('.') {
            map.insert(alias, pkg);
        }
    }

    // import * as X from 'pkg'  (namespace import)
    let namespace_re = regex::Regex::new(
        r#"import\s+\*\s+as\s+(\w+)\s+from\s+['"]([^'"]+)['"]"#,
    )
    .unwrap();
    for caps in namespace_re.captures_iter(content) {
        let alias = caps.get(1).unwrap().as_str().to_string();
        let pkg = caps.get(2).unwrap().as_str().to_string();
        if !pkg.starts_with('.') {
            map.insert(alias, pkg);
        }
    }

    // const X = require('pkg')
    let require_re = regex::Regex::new(
        r#"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)"#,
    )
    .unwrap();
    for caps in require_re.captures_iter(content) {
        let alias = caps.get(1).unwrap().as_str().to_string();
        let pkg = caps.get(2).unwrap().as_str().to_string();
        if !pkg.starts_with('.') {
            map.insert(alias, pkg);
        }
    }

    map
}

/// Build destructured import map from TypeScript import statements.
///
/// Extracts `import { name1, name2 } from 'pkg'` patterns and maps each
/// individual name to its source package. This catches DELULU method
/// hallucinations like:
///   import { useState } from 'react'  → useState comes from 'react'
///   useEffectState()                  → not in react exports → hallucinated
///
/// Skips `import type { ... }` (compile-time only, no runtime verification).
pub fn build_ts_destructured_map(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // import { name1, name2 } from 'pkg'  — Rust regex crate doesn't support
    // negative lookahead (?!type), so we match ALL destructured imports then
    // filter out `import type { ... }` via string check on the full match.
    let destructure_re = regex::Regex::new(
        r#"(import\s+(?:type\s+)?\{([^}]+)\}\s+from\s+['"]([^'"]+)['"])"#,
    )
    .unwrap();
    for caps in destructure_re.captures_iter(content) {
        let full_match = caps.get(1).unwrap().as_str();
        // Skip `import type { ... }` — compile-time only, not verifiable.
        if full_match.contains("type ") || full_match.contains("type{") {
            continue;
        }
        let names_str = caps.get(2).unwrap().as_str();
        let pkg = caps.get(3).unwrap().as_str().to_string();
        if pkg.starts_with('.') {
            continue; // Skip relative imports.
        }
        // Parse comma-separated names, handle `name as alias` syntax.
        for name_part in names_str.split(',') {
            let trimmed = name_part.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Strip leading `type` keyword (TS type-only import modifier
            // inside a mixed import: `import { type X, Y }`). The binding
            // is still a usable type reference even though it's erased at
            // runtime — we keep it in the map for verification.
            let trimmed = trimmed.strip_prefix("type ").unwrap_or(trimmed).trim();
            // Handle `name as alias` — use the alias.
            let actual_name = if let Some(as_pos) = trimmed.find(" as ") {
                trimmed[as_pos + 4..].trim()
            } else {
                trimmed
            };
            if !actual_name.is_empty() {
                map.insert(actual_name.to_string(), pkg.clone());
            }
        }
    }

    map
}

/// Verify destructured import calls against introspected module exports.
///
/// For each bare function call `name(` where `name` is a destructured
/// import from package X:
///   1. Introspect package X
///   2. Check if `name` is in X's exports
///   3. Flag if not found
///
/// Conservative: only verifies lowercase names (functions/hooks). CamelCase
/// names (Types, Interfaces, Components) are skipped to avoid flagging
/// TypeScript type-only exports that don't appear in runtime require().
pub async fn verify_ts_destructured_calls(
    content: &str,
    destructured_map: &HashMap<String, String>,
    project_root: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if destructured_map.is_empty() {
        return warnings;
    }

    // Match bare function calls: name( (not after . which is method call).
    let call_re =
        regex::Regex::new(r"(?:^|[^.\w])([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(").unwrap();

    let mut checked: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut module_infos: HashMap<String, ModuleInfo> = HashMap::new();

    for caps in call_re.captures_iter(content) {
        let name = caps.get(1).unwrap().as_str().to_string();

        // Only check names that are destructured imports.
        let package_name = match destructured_map.get(&name) {
            Some(pkg) => pkg.clone(),
            None => continue,
        };

        // Skip CamelCase (types/interfaces) and underscore-prefixed names
        // (internal). `introspect_ts_module` filters underscore exports
        // (`!k.startsWith('_')`) so verifying them always fails — causes
        // FPs on Zod internals like `_undefined`, `_lte`.
        if name
            .chars()
            .next()
            .map_or(true, |c| c.is_uppercase())
            || name.starts_with('_')
        {
            continue;
        }

        // Skip names in COMMON_TS_EXPORTS — type-only exports, framework
        // globals, and generated symbols that don't appear in runtime
        // require() output but are valid imports. Mirrors FORGE Step 2b
        // behavior so both verification paths stay aligned. Testing globals
        // (`describe`, `it`, `test`, ...) live in TESTING_GLOBALS — the
        // canonical source shared with the tree-sitter undefined-variable pass.
        // Use `is_common_ts_export` to also honor user-provided
        // `extra_ts_exports` config (council A7).
        if crate::scanner::forge_pipeline::is_common_ts_export(name.as_str())
            || crate::scanner::ts_ast_extractor::TESTING_GLOBALS.contains(name.as_str())
        {
            continue;
        }

        if !checked.insert(name.clone()) {
            continue;
        }

        // Get or introspect the module.
        let info = if let Some(i) = module_infos.get(&package_name) {
            i.clone()
        } else {
            let i = introspect_ts_module(&package_name, project_root).await;
            module_infos.insert(package_name.clone(), i.clone());
            i
        };

        if info.error.is_some() {
            continue;
        }

        if !info.exists(&name) {
            match info.closest_match(&name) {
                Some(suggestion) => warnings.push(format!(
                    "hallucinated-import-name: `{}` — imported from `{}` but not in module exports. Did you mean `{}`?",
                    name, package_name, suggestion
                )),
                None => warnings.push(format!(
                    "hallucinated-import-name: `{}` — imported from `{}` but not in module exports",
                    name, package_name
                )),
            }
        }
    }

    warnings
}

/// Extract full TS/JS import paths including subpaths.
///
/// Unlike extract_lookup_terms (which truncates at `/`), this captures the
/// FULL import path: `@react-router/config/routes` not just `@react-router`.
/// Needed for subpath verification against npm exports map.
pub fn extract_ts_import_paths(content: &str) -> Vec<String> {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?:from\s+|import\s+|require\s*\(\s*)['"]([^'"]+)['"]"#).unwrap()
    });
    let mut paths = Vec::new();
    for caps in IMPORT_RE.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            // Skip relative imports.
            if path.starts_with('.') || path.starts_with('/') {
                continue;
            }
            paths.push(path.to_string());
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

/// Extract npm package name (2 segments for scoped, 1 for unscoped)
/// from a full import path. Handles subpaths correctly.
///
/// `@react-router/config/routes` → `@react-router/config`
/// `react/jsx-runtime` → `react`
/// `lodash` → `lodash`
pub fn npm_package_from_path(path: &str) -> String {
    if path.starts_with('@') {
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() >= 2 {
            return format!("{}/{}", parts[0], parts[1]);
        }
    }
    path.split('/').next().unwrap_or(path).to_string()
}

/// Detect bare function calls that are prefix-extensions of destructured imports.
///
/// Catches hallucinations like:
///   import { useState, useEffect } from 'react'
///   ... useEffectState()  // starts with useEffect → likely hallucinated
///
/// Only fires when the call name STARTS WITH a real destructured name and
/// the extra suffix is ≤6 chars (catches State/Callback/Ref additions).
pub fn verify_ts_prefix_extension_calls(
    content: &str,
    destructured_names: &[String],
) -> Vec<String> {
    if destructured_names.is_empty() {
        return Vec::new();
    }
    let name_set: std::collections::HashSet<&str> =
        destructured_names.iter().map(|s| s.as_str()).collect();

    // Match bare function calls: identifier followed by (
    let call_re =
        regex::Regex::new(r"(?:^|[^.\w$])([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(").unwrap();

    let mut warnings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in call_re.captures_iter(content) {
        let name = caps.get(1).unwrap().as_str();
        if seen.contains(name) {
            continue;
        }
        seen.insert(name);
        // Skip if this name IS a destructured import (correctly imported).
        if name_set.contains(name) {
            continue;
        }
        // Check prefix extension: does name start with any destructured name?
        for real_name in &name_set {
            if name.len() > real_name.len() && name.starts_with(real_name) {
                let extra = name.len() - real_name.len();
                if extra <= 6 {
                    warnings.push(format!(
                        "hallucinated-call: `{}` — not imported. Looks like extension of `{}`.",
                        name, real_name
                    ));
                    break; // One match is enough.
                }
            }
        }
    }
    warnings
}

/// Build a receiver → global-class map from `const X = <factory>(...)`
/// statements where `<factory>` is a known DOM/Node constructor or
/// the `fetch` function.
///
/// Catches hallucinations on receivers whose type comes from a GLOBAL
/// rather than an npm import. Existing `verify_ts_methods` only covers
/// import aliases (`import X from 'pkg'`); this complements it for
/// cases like:
///
/// ```ts
/// const response = await fetch(url, { signal });
/// const newData = await response.parseBody();  // ← Response has no parseBody
/// ```
///
/// Patterns matched:
///   - `const X = await fetch(...)`       → `Response`
///   - `const X = new <GlobalClass>(...)` → `<GlobalClass>` (if in allowlist)
///
/// Skips `let X = fetch(...)` (no await) — returns a Promise, not
/// Response, and chasing `.then()` chains is out of scope.
pub fn build_ts_factory_receiver_map(content: &str) -> HashMap<String, String> {
    use regex::Regex;
    use std::sync::OnceLock;

    static FETCH_RE: OnceLock<Regex> = OnceLock::new();
    static NEW_RE: OnceLock<Regex> = OnceLock::new();

    let mut map = HashMap::new();

    // const X = await fetch(...)  → Response
    let fetch_re = FETCH_RE.get_or_init(|| {
        Regex::new(r#"(?:const|let|var)\s+(\w+)\s*=\s*await\s+fetch\s*\("#).unwrap()
    });
    for caps in fetch_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            map.insert(m.as_str().to_string(), "Response".to_string());
        }
    }

    // const X = new GlobalClass(...)  → GlobalClass
    let new_re = NEW_RE.get_or_init(|| {
        Regex::new(r#"(?:const|let|var)\s+(\w+)\s*=\s*new\s+([A-Z][a-zA-Z0-9_$]*)\s*\("#).unwrap()
    });
    for caps in new_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str();
        let class_name = caps.get(2).unwrap().as_str();
        if GLOBAL_CLASSES.contains(class_name) {
            map.insert(receiver.to_string(), class_name.to_string());
        }
    }

    map
}

/// Introspect a Node.js GLOBAL class's prototype methods via subprocess.
///
/// Runs `Object.getOwnPropertyNames(<class>.prototype)` to enumerate
/// the runtime method list. Equivalent of `introspect_ts_module` for
/// globals rather than npm packages — same `ModuleInfo` shape so the
/// existing `exists` / `closest_match` helpers work unchanged.
///
/// Cached per-process via `TS_GLOBAL_CACHE` (separate key namespace
/// from package cache: keys are the bare class name).
///
/// Errors (still cached — don't retry):
///   - `class_name` isn't a Node.js global (`ReferenceError`)
///   - Class has no prototype (e.g., Math — not in allowlist anyway)
///   - Node.js spawn fails
pub async fn introspect_ts_global_prototype(class_name: &str) -> ModuleInfo {
    // Defensive: class names must be `[A-Za-z_][A-Za-z0-9_]*`. We splice
    // this into a Node script, so any other character is rejected.
    if class_name.is_empty()
        || !class_name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
        || !class_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return ModuleInfo {
            module: format!("global::{class_name}"),
            names: vec![],
            error: Some("invalid class name".to_string()),
            latency_ms: 0,
        };
    }

    {
        let cache = TS_GLOBAL_CACHE.lock().await;
        if let Some(info) = cache.get(class_name) {
            return info.clone();
        }
    }

    let start = std::time::Instant::now();

    // Use bracket-access to keep the script constant (no string
    // interpolation after sanitization). Avoids shell-escape edge cases.
    let script = format!(
        r#"(function () {{
  try {{
    var cls = globalThis['{class_name}'];
    if (typeof cls === 'undefined' || !cls.prototype) {{
      throw new Error('{class_name} is not a Node.js global');
    }}
    var names = Object.getOwnPropertyNames(cls.prototype)
      .filter(function (k) {{ return k !== 'constructor' && !k.startsWith('_'); }});
    process.stdout.write(JSON.stringify({{ names: names, error: null }}));
  }} catch (e) {{
    process.stdout.write(JSON.stringify({{ names: [], error: e.message }}));
  }}
}})();
"#,
        class_name = class_name,
    );

    let result = crate::scanner::command_hidden_tokio("node")
        .arg("-e")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await;

    let latency_ms = start.elapsed().as_millis() as u64;

    let info = match result {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                ModuleInfo {
                    module: format!("global::{class_name}"),
                    names: vec![],
                    error: Some(format!(
                        "node exit {:?}: {}",
                        output.status,
                        stderr.lines().next().unwrap_or("")
                    )),
                    latency_ms,
                }
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                #[derive(Deserialize)]
                struct Out {
                    names: Vec<String>,
                    error: Option<String>,
                }
                match serde_json::from_str::<Out>(stdout.trim()) {
                    Ok(parsed) => ModuleInfo {
                        module: format!("global::{class_name}"),
                        names: parsed.names,
                        error: parsed.error,
                        latency_ms,
                    },
                    Err(e) => ModuleInfo {
                        module: format!("global::{class_name}"),
                        names: vec![],
                        error: Some(format!(
                            "parse JSON: {e} (raw: {})",
                            crate::scanner::safe_slice_to(&stdout, 200)
                        )),
                        latency_ms,
                    },
                }
            }
        }
        Err(e) => ModuleInfo {
            module: format!("global::{class_name}"),
            names: vec![],
            error: Some(format!("spawn node: {e}")),
            latency_ms,
        },
    };

    let mut cache = TS_GLOBAL_CACHE.lock().await;
    cache.insert(class_name.to_string(), info.clone());
    info
}

/// Verify method calls on factory-derived receivers against the
/// receiver's runtime prototype.
///
/// For each `receiver.method(` in `content` where `receiver` is in
/// `factory_map` (built by `build_ts_factory_receiver_map`):
///   1. Introspect the corresponding global class prototype
///   2. Check if `method` exists on the prototype
///   3. Flag with closest-match suggestion if not
///
/// Catches DELULU method hallucinations on global APIs:
///   - `response.parseBody()` vs `response.json()` (Response)
///   - `controller.terminate()` vs `controller.abort()` (AbortController)
///   - `params.getAllKeys()` vs `params.getAll()` (URLSearchParams)
///
/// Conservative FPR design: only fires when the global class
/// introspects cleanly AND the receiver is explicitly bound to it via
/// a detected factory call. Untyped receivers fall through silently.
pub async fn verify_ts_factory_methods(
    content: &str,
    factory_map: &HashMap<String, String>,
) -> Vec<String> {
    use regex::Regex;
    use std::sync::OnceLock;

    let mut warnings = Vec::new();
    if factory_map.is_empty() {
        return warnings;
    }

    static METHOD_RE: OnceLock<Regex> = OnceLock::new();
    let method_re = METHOD_RE.get_or_init(|| {
        Regex::new(
            r"(?:^|[^a-zA-Z0-9_$])([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(",
        )
        .unwrap()
    });

    let mut checked: HashSet<(String, String)> = HashSet::new();
    let mut class_infos: HashMap<String, ModuleInfo> = HashMap::new();

    for caps in method_re.captures_iter(content) {
        let receiver = caps.get(1).unwrap().as_str().to_string();
        let method = caps.get(2).unwrap().as_str().to_string();

        let class_name = match factory_map.get(&receiver) {
            Some(c) => c.clone(),
            None => continue,
        };

        if !checked.insert((receiver.clone(), method.clone())) {
            continue;
        }

        let info = if let Some(i) = class_infos.get(&class_name) {
            i.clone()
        } else {
            let i = introspect_ts_global_prototype(&class_name).await;
            class_infos.insert(class_name.clone(), i.clone());
            i
        };

        if info.error.is_some() {
            continue;
        }

        if !info.exists(&method) {
            match info.closest_match(&method) {
                Some(suggestion) => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not on `{}` prototype. Did you mean `{}`?",
                    receiver, method, method, class_name, suggestion
                )),
                None => warnings.push(format!(
                    "hallucinated-method: `{}.{}` — `{}` not on `{}` prototype",
                    receiver, method, method, class_name
                )),
            }
        }
    }

    warnings
}

/// Clear the TS introspection cache. Useful for tests.
pub async fn clear_cache() {
    {
        let mut cache = TS_INTROSPECT_CACHE.lock().await;
        cache.clear();
    }
    let mut global_cache = TS_GLOBAL_CACHE.lock().await;
    global_cache.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_alias_map_catches_default_import() {
        let content = "import React from 'react';";
        let map = build_ts_alias_map(content);
        assert_eq!(map.get("React"), Some(&"react".to_string()));
    }

    #[test]
    fn build_alias_map_catches_namespace_import() {
        let content = "import * as lodash from 'lodash';";
        let map = build_ts_alias_map(content);
        assert_eq!(map.get("lodash"), Some(&"lodash".to_string()));
    }

    #[test]
    fn build_alias_map_catches_require() {
        let content = "const path = require('path');";
        let map = build_ts_alias_map(content);
        assert_eq!(map.get("path"), Some(&"path".to_string()));
    }

    #[test]
    fn build_alias_map_skips_relative_imports() {
        let content = "import { foo } from './local';";
        let map = build_ts_alias_map(content);
        assert!(map.is_empty(), "relative imports should be skipped: {:?}", map);
    }

    #[test]
    fn build_alias_map_handles_multiple_imports() {
        let content = r#"
            import React from 'react';
            import * as _ from 'lodash';
            const express = require('express');
        "#;
        let map = build_ts_alias_map(content);
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("React"), Some(&"react".to_string()));
        assert_eq!(map.get("_"), Some(&"lodash".to_string()));
        assert_eq!(map.get("express"), Some(&"express".to_string()));
    }

    #[tokio::test]
    async fn introspect_node_builtin_path_works() {
        clear_cache().await;
        // Node.js built-in 'path' module is always available.
        let info = introspect_ts_module("path", ".").await;
        assert!(info.error.is_none(), "path should introspect cleanly: {:?}", info.error);
        assert!(
            info.exists("join"),
            "path.join should exist; got names: {:?}",
            info.names.iter().take(10).collect::<Vec<_>>()
        );
        assert!(
            info.exists("resolve"),
            "path.resolve should exist"
        );
    }

    #[tokio::test]
    async fn introspect_nonexistent_package_returns_error() {
        clear_cache().await;
        let info = introspect_ts_module("completely-fake-pkg-xyz-12345", ".").await;
        assert!(info.error.is_some(), "expected error for fake package");
        assert!(info.names.is_empty());
    }

    #[tokio::test]
    async fn introspect_caches_results() {
        clear_cache().await;
        let first = introspect_ts_module("path", ".").await;
        let second = introspect_ts_module("path", ".").await;
        assert_eq!(first.names, second.names);
    }

    #[tokio::test]
    async fn verify_ts_methods_flags_hallucinated_method() {
        clear_cache().await;
        let content = r"path.completelyFakeMethod()";
        let mut aliases = HashMap::new();
        aliases.insert("path".to_string(), "path".to_string());
        let warnings = verify_ts_methods(content, &aliases, ".").await;
        assert!(
            warnings.iter().any(|w| w.contains("hallucinated-method") && w.contains("completelyFakeMethod")),
            "expected hallucinated-method warning; got: {:?}",
            warnings
        );
    }

    #[tokio::test]
    async fn verify_ts_methods_passes_real_method() {
        clear_cache().await;
        let content = r"path.join('a', 'b')";
        let mut aliases = HashMap::new();
        aliases.insert("path".to_string(), "path".to_string());
        let warnings = verify_ts_methods(content, &aliases, ".").await;
        assert!(
            warnings.is_empty(),
            "path.join should NOT be flagged; got: {:?}",
            warnings
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // Factory-receiver + global prototype introspection tests.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn factory_map_catches_await_fetch() {
        let content = "const response = await fetch(url, { signal });";
        let map = build_ts_factory_receiver_map(content);
        assert_eq!(map.get("response"), Some(&"Response".to_string()));
    }

    #[test]
    fn factory_map_catches_new_global_class() {
        let content = "const controller = new AbortController();";
        let map = build_ts_factory_receiver_map(content);
        assert_eq!(map.get("controller"), Some(&"AbortController".to_string()));
    }

    #[test]
    fn factory_map_skips_non_global_new_class() {
        // MongoClient is not in the allowlist — would require npm types
        // to verify, so we skip it entirely.
        let content = "const client = new MongoClient(uri);";
        let map = build_ts_factory_receiver_map(content);
        assert!(map.is_empty(), "non-global classes should be skipped: {:?}", map);
    }

    #[test]
    fn factory_map_skips_fetch_without_await() {
        // `fetch()` without await returns Promise<Response>, not Response.
        // Skipping avoids needing to resolve the Promise unwrapping.
        let content = "const promise = fetch(url);";
        let map = build_ts_factory_receiver_map(content);
        assert!(map.is_empty(), "fetch without await should be skipped: {:?}", map);
    }

    #[test]
    fn factory_map_handles_let_and_var() {
        let content = r"
            let r1 = await fetch('/a');
            var r2 = new URL(loc);
        ";
        let map = build_ts_factory_receiver_map(content);
        assert_eq!(map.get("r1"), Some(&"Response".to_string()));
        assert_eq!(map.get("r2"), Some(&"URL".to_string()));
    }

    #[tokio::test]
    async fn introspect_global_response_works() {
        clear_cache().await;
        // Response is a Node.js global since v18 (undici). Should have
        // json/text/clone on the prototype.
        let info = introspect_ts_global_prototype("Response").await;
        assert!(info.error.is_none(), "Response should introspect: {:?}", info.error);
        assert!(info.exists("json"), "Response.json missing: {:?}", info.names);
        assert!(info.exists("text"));
        assert!(info.exists("clone"));
    }

    #[tokio::test]
    async fn introspect_global_rejects_non_global() {
        clear_cache().await;
        // FakeClass is not on globalThis → error.
        let info = introspect_ts_global_prototype("FakeClassXYZ").await;
        assert!(info.error.is_some(), "expected error for non-global");
        assert!(info.names.is_empty());
    }

    #[tokio::test]
    async fn introspect_global_rejects_invalid_class_name() {
        clear_cache().await;
        // Semicolon would break out of the script if not sanitized.
        let info = introspect_ts_global_prototype("Response; console.log('pwned')").await;
        assert!(info.error.is_some(), "expected error for invalid name");
    }

    #[tokio::test]
    async fn introspect_global_caches_results() {
        clear_cache().await;
        let first = introspect_ts_global_prototype("Response").await;
        let second = introspect_ts_global_prototype("Response").await;
        assert_eq!(first.names, second.names);
    }

    #[tokio::test]
    async fn verify_factory_methods_flags_parsebody_on_response() {
        // Direct reproduction of the DELULU sample
        // typescript-method-ee593f0c04c3: response.parseBody() vs
        // response.json().
        clear_cache().await;
        let content =
            "const response = await fetch(url);\nconst data = await response.parseBody();";
        let factory_map = build_ts_factory_receiver_map(content);
        assert!(!factory_map.is_empty());
        let warnings = verify_ts_factory_methods(content, &factory_map).await;
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("hallucinated-method")
                    && w.contains("response.parseBody")
                    && w.contains("Response")),
            "expected parseBody hallucination warning; got: {:?}",
            warnings
        );
    }

    #[tokio::test]
    async fn verify_factory_methods_passes_real_response_methods() {
        // FPR safety: golden `response.json()` must NOT be flagged.
        clear_cache().await;
        let content = concat!(
            "const response = await fetch(url);\n",
            "const a = await response.json();\n",
            "const b = await response.text();\n",
            "const c = response.ok;\n",
            "const d = response.clone();\n",
        );
        let factory_map = build_ts_factory_receiver_map(content);
        let warnings = verify_ts_factory_methods(content, &factory_map).await;
        assert!(
            warnings.is_empty(),
            "real Response methods should not be flagged; got: {:?}",
            warnings
        );
    }

    #[tokio::test]
    async fn verify_factory_methods_skips_untyped_receivers() {
        // FPR safety: receivers not bound to a known factory fall through.
        clear_cache().await;
        let content = "const data = someApi();\nconst x = data.completelyFakeMethod();";
        let factory_map = build_ts_factory_receiver_map(content);
        assert!(factory_map.is_empty(), "no factory in content");
        let warnings = verify_ts_factory_methods(content, &factory_map).await;
        assert!(warnings.is_empty());
    }

    #[tokio::test]
    async fn verify_factory_methods_aborts_controller_correctly() {
        // AbortController.abort() exists — no warning.
        clear_cache().await;
        let content =
            "const controller = new AbortController();\ncontroller.abort();";
        let factory_map = build_ts_factory_receiver_map(content);
        let warnings = verify_ts_factory_methods(content, &factory_map).await;
        assert!(
            warnings.is_empty(),
            "AbortController.abort should not be flagged; got: {:?}",
            warnings
        );
    }

    #[tokio::test]
    async fn verify_factory_methods_flags_fake_abort_method() {
        // AbortController has only `signal` and `abort`. `terminate`
        // is too distant (Levenshtein > 3) to suggest a match, so we
        // only assert the warning fires without requiring a suggestion.
        clear_cache().await;
        let content =
            "const controller = new AbortController();\ncontroller.terminate();";
        let factory_map = build_ts_factory_receiver_map(content);
        let warnings = verify_ts_factory_methods(content, &factory_map).await;
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("hallucinated-method")
                    && w.contains("controller.terminate")
                    && w.contains("AbortController")),
            "expected terminate hallucination warning; got: {:?}",
            warnings
        );
    }
}
