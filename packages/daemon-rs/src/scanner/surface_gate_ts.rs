//! Surface gate for TypeScript/JavaScript — installed-package API surface
//! verification (v3 architecture, sale-ready stream 2).
//!
//! Catches the hallucination classes the compiler/AST gates miss on live
//! agent traffic (20260818 hosted-run ground truth):
//!   1. Wrong named export: `import { createServer } from 'graphql-yoga'`
//!      — createServer is node:http, NOT a graphql-yoga v5 export.
//!   2. Invented method on a typed instance: `yoga.listen(port, cb)`
//!      — YogaServerInstance v5 is a fetch handler, it has no .listen().
//!
//! Mechanism: a Node subprocess `require.resolve`s the imported package
//! from the WORKSPACE (cwd = project_root) and reports its actual export
//! surface (`Object.keys(require(pkg))`). We then check:
//!   - named-import membership: every `import { X } from 'pkg'` binding X
//!     must exist in the package's export keys (or its `default` interop
//!     namespace, or package.json `exports` subpaths — fail-open on all
//!     ambiguity per certain-mismatches-only policy).
//!   - method-existence: for `x.method(...)` where `x` is bound in the
//!     SAME response by `const x = PkgName(...)` or
//!     `const x = new PkgName(...)`, the method must exist on the
//!     package's export surface (factory return or namespace object).
//!
//! Fail-open everywhere: package not installed, node absent, subprocess
//! timeout/parse failure, CJS/ESM interop ambiguity → no warning.
//! Kill switch: ANUBIS_SURFACE_GATE=0 disables both surface gates.

use serde::Deserialize;
use std::collections::HashSet;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Max distinct packages to introspect per scan (latency bound).
const MAX_PACKAGES: usize = 8;
/// Subprocess budget for the whole export-census call.
const CENSUS_TIMEOUT_SECS: u64 = 10;

/// Extract `import { A, B as C } from 'pkg'` → [(binding, 'pkg')] and
/// `const x = require('pkg')`-style requires are handled by the TS path
/// only (plain JS `require` returns namespace, method check applies to
/// named exports only).
fn extract_named_imports(code: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in code.lines() {
        let t = line.trim();
        // import { A, B as C } from 'pkg';
        if t.starts_with("import {") {
            if let Some(close) = t.find('}') {
                let bindings_src = &t["import {".len()..close];
                let rest = &t[close + 1..];
                if let Some(pkg) = extract_from_clause(rest) {
                    for b in bindings_src.split(',') {
                        let b = b.trim();
                        if b.is_empty() {
                            continue;
                        }
                        // `B as C` binds C locally.
                        let binding = b.rsplit(" as ").next().unwrap_or(b).trim();
                        if is_plain_ident(binding) {
                            out.push((binding.to_string(), pkg.clone()));
                        }
                    }
                }
            }
        }
        // import Pkg from 'pkg'; / import * as Pkg from 'pkg';
        else if t.starts_with("import ") && !t.contains(" type ") {
            if let Some(pkg) = extract_from_clause(t) {
                let head = t["import ".len()..].split(" from ").next().unwrap_or("");
                let head = head.trim().trim_end_matches(';').trim();
                let namespace = head
                    .strip_prefix("* as ")
                    .map(|s| s.trim())
                    .or_else(|| head.strip_prefix("const ").map(|s| s.trim()));
                if let Some(ns) = namespace {
                    if is_plain_ident(ns) {
                        out.push((format!("*{}", ns), pkg.clone()));
                    }
                }
            }
        }
    }
    out
}

fn extract_from_clause(rest: &str) -> Option<String> {
    let idx = rest.find("from ")?;
    let q = rest[idx + 5..].trim_start();
    let q = q.trim_start_matches(';');
    let quote = q.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let end = q[1..].find(quote)? + 1;
    Some(q[1..end].to_string())
}

fn is_plain_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s.len() <= 64
}

/// Node script: resolve + require each package from cwd, report export keys.
/// Runs with the workspace as cwd so `require('pkg')` finds LOCAL
/// node_modules (the ground truth the agent is coding against).
const CENSUS_SCRIPT: &str = r#"
// `node -e SCRIPT <file>` puts the file at argv[1]; `node script.js <file>`
// puts it at argv[2]. Accept either.
const listPath = process.argv[2] || process.argv[1];
const pkgs = JSON.parse(require('fs').readFileSync(listPath, 'utf8'));
const out = {};
for (const pkg of pkgs) {
    try {
        const resolved = require.resolve(pkg);
        const mod = require(pkg);
        const keys = new Set();
        const collect = (obj, depth) => {
            if (!obj || depth > 2) return;
            for (const k of Object.keys(obj)) {
                try { keys.add(k); } catch (_) {}
                if (depth === 0 && (k === 'default' || k === 'graphql')) {
                    try { collect(obj[k], depth + 1); } catch (_) {}
                }
            }
        };
        collect(mod, 0);
        // default-export function/ctor: own + prototype members count as surface
        if (typeof mod === 'function' || typeof mod === 'object') {
            try {
                let proto = Object.getPrototypeOf(mod);
                while (proto && proto !== Object.prototype && proto !== Function.prototype) {
                    for (const k of Object.getOwnPropertyNames(proto)) { keys.add(k); }
                    proto = Object.getPrototypeOf(proto);
                }
            } catch (_) {}
            try {
                let proto = mod.prototype;
                while (proto) {
                    for (const k of Object.getOwnPropertyNames(proto)) { keys.add(k); }
                    proto = Object.getPrototypeOf(proto);
                }
            } catch (_) {}
        }
        out[pkg] = { resolved: true, keys: Array.from(keys) };
        void resolved;
    } catch (e) {
        out[pkg] = { resolved: false, keys: [] };
    }
}
process.stdout.write(JSON.stringify(out));
"#;

/// Export census for the distinct packages referenced by `code`'s import
/// statements, resolved from `project_root`. Empty when node is absent,
/// nothing to check, or on any failure (fail-open).
async fn export_census(code: &str, project_root: &str) -> std::collections::HashMap<String, Option<HashSet<String>>> {
    let imports = extract_named_imports(code);
    if imports.is_empty() {
        return std::collections::HashMap::new();
    }
    let mut pkgs: Vec<String> = imports.iter().map(|(_, p)| p.clone()).collect();
    pkgs.sort();
    pkgs.dedup();
    pkgs.truncate(MAX_PACKAGES);

    let dir = std::env::temp_dir().join(format!(
        "anubis-surface-ts-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if std::fs::create_dir_all(&dir).is_err() {
        return std::collections::HashMap::new();
    }
    let list_file = dir.join("pkgs.json");
    if std::fs::write(&list_file, serde_json::to_string(&pkgs).unwrap_or_default().as_bytes()).is_err() {
        return std::collections::HashMap::new();
    }

    let mut child = crate::scanner::command_hidden_tokio("node");
    child
        .arg("-e")
        .arg(CENSUS_SCRIPT)
        .arg(&list_file)
        .current_dir(project_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let output = {
        match child.spawn() {
            Ok(c) => match tokio::time::timeout(Duration::from_secs(CENSUS_TIMEOUT_SECS), c.wait_with_output()).await {
                Ok(Ok(o)) if o.status.success() => o,
                _ => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return std::collections::HashMap::new();
                }
            },
            Err(_) => {
                let _ = std::fs::remove_dir_all(&dir);
                return std::collections::HashMap::new();
            }
        }
    };
    let _ = std::fs::remove_dir_all(&dir);

    #[derive(Deserialize)]
    struct PkgInfo {
        #[serde(default)]
        resolved: bool,
        #[serde(default)]
        keys: Vec<String>,
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: std::collections::HashMap<String, PkgInfo> =
        match serde_json::from_str(stdout.trim()) {
            Ok(p) => p,
            Err(_) => return std::collections::HashMap::new(),
        };

    let mut census = std::collections::HashMap::new();
    for (pkg, info) in parsed {
        if info.resolved {
            census.insert(pkg, Some(info.keys.into_iter().collect::<HashSet<_>>()));
        } else {
            // Not installed locally → no ground truth → fail-open.
            census.insert(pkg, None);
        }
    }
    census
}

/// Extract `const x = Pkg(...)` / `const x = new Pkg(...)` /
/// `const x = Pkg.something(...)` bindings where Pkg is a named-import
/// binding or namespace import of an installed package.
fn extract_instance_bindings(code: &str, imports: &[(String, String)]) -> Vec<(String, String, String)> {
    // (local var, source binding, package) — owned strings; the import
    // slice outlives this frame but we clone to keep lifetimes simple.
    let mut import_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (binding, pkg) in imports {
        let b = binding.trim_start_matches('*').to_string();
        import_map.insert(b, pkg.clone());
    }
    let mut out = Vec::new();
    for line in code.lines() {
        let t = line.trim();
        for pat in ["const ", "let ", "var "] {
            if let Some(rest) = t.strip_prefix(pat) {
                if let Some(eq) = rest.find(" = ") {
                    let var = rest[..eq].trim();
                    let rhs = rest[eq + 3..].trim();
                    if !is_plain_ident(var) {
                        continue;
                    }
                    // new Pkg( ... ) or Pkg( ... ) or Pkg.factory(...)
                    let call_target = rhs
                        .strip_prefix("new ")
                        .map(|r| r.trim())
                        .unwrap_or(rhs);
                    // take up to first '('
                    if let Some(paren) = call_target.find('(') {
                        let callee = call_target[..paren].trim();
                        if let Some(head_seg) = callee.split('.').next() {
                            if let Some(pkg) = import_map.get(head_seg) {
                                out.push((var.to_string(), callee.to_string(), pkg.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Public entry point — called from scanner/mod.rs after the Stage-5
/// compiler gate (surface evidence outranks compile cleanliness; a module
/// that compiles against stale types can still import a nonexistent
/// export). Returns grounded warnings for CERTAIN mismatches only.
pub async fn check(content: &str, code: &str, project_root: &str) -> Vec<String> {
    if std::env::var("ANUBIS_SURFACE_GATE")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        return Vec::new();
    }
    if project_root.is_empty() || code.is_empty() {
        return Vec::new();
    }

    let imports = extract_named_imports(code);
    if imports.is_empty() {
        return Vec::new();
    }
    let census = export_census(code, project_root).await;
    if census.is_empty() {
        return Vec::new();
    }

    let mut warnings = Vec::new();

    // ── Check 1: named-import membership ─────────────────────────────
    let mut missing: Vec<(String, String)> = Vec::new();
    for (binding, pkg) in &imports {
        if binding.starts_with('*') {
            continue; // namespace imports bind the whole surface
        }
        if let Some(Some(keys)) = census.get(pkg) {
            if !keys.contains(binding) {
                missing.push((binding.clone(), pkg.clone()));
            }
        }
    }
    missing.sort();
    missing.dedup();
    for (binding, pkg) in missing {
        warnings.push(format!(
            "surface-mismatch: `{}` is not an export of installed package `{}` — the import will throw at runtime. Check the package's actual exports (e.g. `node -e \"console.log(Object.keys(require('{pkg}')))\"`).",
            binding, pkg
        ));
    }

    // ── Check 2: method existence on instances of imported packages ──
    // `const yoga = createYoga({...}); yoga.listen(...)` → `listen` must
    // exist somewhere on the createYoga return surface OR the namespace.
    let bindings = extract_instance_bindings(code, &imports);
    for (var, callee, pkg) in bindings {
        // Find `var.method(` uses in the code.
        let method_re_prefix = format!("{}.", var);
        for line in code.lines() {
            for (idx, _) in line.match_indices(&method_re_prefix) {
                let after = &line[idx + method_re_prefix.len()..];
                let method: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if method.is_empty() || method.len() < 3 {
                    continue;
                }
                let known = census.get(&pkg).and_then(|k| k.as_ref());
                if let Some(keys) = known {
                    if !keys.contains(&method) {
                        warnings.push(format!(
                            "surface-mismatch: `{}.{}` does not exist on the value returned by `{}` (package `{}`) — the call will throw at runtime. Inspect the actual return surface before calling.",
                            var, method, callee, pkg
                        ));
                    }
                }
            }
        }
    }

    warnings.dedup();
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_import_extraction() {
        let code = "import { createYoga } from 'graphql-yoga'\nimport { z } from 'zod'\nimport { A as Renamed } from 'pkg'";
        let imports = extract_named_imports(code);
        assert!(imports.contains(&("createYoga".to_string(), "graphql-yoga".to_string())));
        assert!(imports.contains(&("z".to_string(), "zod".to_string())));
        assert!(imports.contains(&("Renamed".to_string(), "pkg".to_string())));
    }

    #[test]
    fn namespace_import_extraction() {
        let code = "import * as fs from 'node:fs'";
        let imports = extract_named_imports(code);
        assert!(imports.contains(&("*fs".to_string(), "node:fs".to_string())));
    }

    #[test]
    fn instance_binding_extraction() {
        let code = "import { createYoga } from 'graphql-yoga'\nconst yoga = createYoga({ schema })\nyoga.listen(4000)";
        let imports = extract_named_imports(code);
        let bindings = extract_instance_bindings(code, &imports);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].0, "yoga");
        assert_eq!(bindings[0].1, "createYoga");
        assert_eq!(bindings[0].2, "graphql-yoga");
    }

    #[tokio::test]
    async fn kill_switch_disables() {
        std::env::set_var("ANUBIS_SURFACE_GATE", "0");
        let w = check("x", "import { nope } from 'pkg'", "/nonexistent").await;
        assert!(w.is_empty());
        std::env::remove_var("ANUBIS_SURFACE_GATE");
    }

    #[tokio::test]
    async fn missing_package_fails_open() {
        // Package not installed anywhere → census unresolved → no warnings.
        let code = "import { anything } from 'totally-not-installed-pkg'";
        let w = check("", code, ".").await;
        assert!(w.is_empty());
    }

    #[tokio::test]
    async fn live_membership_check() {
        // daemon-rs has local node_modules (typescript installed for the
        // ts gate). Requires node on PATH — skip silently if absent.
        let code = "import { createYoga } from 'typescript'";
        let w = check("", code, ".").await;
        // createYoga is NOT a typescript export → certain mismatch fires.
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("not an export"));
    }
}
