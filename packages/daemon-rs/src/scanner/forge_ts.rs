//! TypeScript/JavaScript FORGE runner — extracted from forge_pipeline.rs (M1 chunk 9).
//!
//! Verifies TypeScript/JavaScript source for:
//!   1. Import packages — npm registry lookup (full import path)
//!   2. Named import symbols — verified against cached package API surface
//!   3. Undefined variables — tree-sitter AST (`ts_ast_extractor`)
//!   4. Aliased method calls — Node.js `require()` introspection
//!   5. Destructured imports — runtime export verification
//!   6. Prefix-extension calls — bare calls that look like extensions
//!   7. TypeScript Compiler API — `ts.createProgram` + TS2339 diagnostics
//!   8. Factory-derived receiver methods — DOM/Node global prototype intro
//!
//! `COMMON_TS_EXPORTS` stays in `forge_pipeline.rs` because `ts_introspect`
//! references it via `crate::scanner::forge_pipeline::COMMON_TS_EXPORTS`.
//! Referenced here through the same path.

use crate::scanner::forge_types::ForgeResult;
use crate::scanner::package_index::ImportStatus;

// Static regex pattern for named import extraction
static NAMED_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"import\s*(?:type\s+)?\{([^}]+)\}\s*from\s*["']([^"']+)["']"#
    ).unwrap()
});

// Namespace import: `import * as ALIAS from "module"`
static NAMESPACE_IMPORT_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r#"import\s+\*\s+as\s+(\w+)\s+from\s*["']([^"']+)["']"#
    ).unwrap()
});

use once_cell::sync::Lazy;

pub(crate) async fn run_forge_ts(content: &str, language: &str, project_root: &str) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();

    // Step 1: Extract FULL import paths (not truncated at /).
    // extract_lookup_terms truncates at /, losing subpath info.
    // extract_ts_import_paths captures full paths like @react-router/config/routes.
    let full_paths = crate::scanner::ts_introspect::extract_ts_import_paths(content);
    result.claims_extracted = full_paths.len();

    // Step 2: Verify each import's package name against npm registry.
    // Uses npm_package_from_path to extract the correct npm package name
    // from the full import path.
    for path_raw in &full_paths {
        let pkg_name = crate::scanner::ts_introspect::npm_package_from_path(path_raw);

        let status = crate::scanner::package_index::verify_import_with_language(language, &pkg_name).await;
        match status {
            ImportStatus::NotFound => {
                let mut msg = format!(
                    "hallucinated-import: `{}` — package `{}` not found in npm registry",
                    path_raw, pkg_name
                );
                if let Some(suggestion) = crate::scanner::package_index::suggest_correct_import(&pkg_name) {
                    msg.push_str(&format!(" — did you mean `{}`?", suggestion));
                }
                result.warnings.push(msg);
                result.claims_hallucinated += 1;
            }
            ImportStatus::Verified => {
                result.claims_verified += 1;
            }
            ImportStatus::NetworkError | ImportStatus::Skipped => {
                result.claims_unknown += 1;
            }
        }
    }

    // Step 2b: Named import symbol verification.
    // For each `import { X, Y } from "package"`, check if X/Y exist in
    // the cached package's API surface. Only flags when package IS cached
    // but symbol is NOT — safe (no FP when package isn't cached).
    // COMMON_TS_EXPORTS is defined at module level (shared with ts_introspect).
    if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
        let cached_libs = cache.list_libraries();
        let named_re = &*NAMED_RE;
        for caps in named_re.captures_iter(content) {
            let names_str = caps.get(1).unwrap().as_str();
            let pkg_path = caps.get(2).unwrap().as_str();
            // Skip relative imports (./foo, ../bar, .) — local files, not npm packages
            if pkg_path.starts_with('.') {
                continue;
            }
            // Skip Node.js built-in modules (node:fs, node:path, etc.)
            if pkg_path.starts_with("node:") {
                continue;
            }
            let pkg_name = crate::scanner::ts_introspect::npm_package_from_path(pkg_path);
            let matching_libs: Vec<&str> = cached_libs
                .iter()
                .map(|(l, _, _)| l.as_str())
                .filter(|l| l.contains(&pkg_name) || pkg_name.contains(l))
                .collect();
            if matching_libs.is_empty() {
                continue;
            }
            for sym_raw in names_str.split(',') {
                let sym = sym_raw.trim()
                    .strip_prefix("type ").unwrap_or(sym_raw).trim()
                    .split(" as ").next().unwrap_or(sym_raw).trim()
                    .split_whitespace().next().unwrap_or("");
                if sym.is_empty() || sym == "*" || sym.len() < 2 {
                    continue;
                }
                // Skip common framework/library exports that are always valid
                // but may not be individually cached (large export surfaces).
                // Testing globals (`describe`, `it`, etc.) live in
                // TESTING_GLOBALS — see comment above COMMON_TS_EXPORTS.
                // Use `is_common_ts_export` to also honor user-provided
                // `extra_ts_exports` config (council A7).
                if crate::scanner::forge_pipeline::is_common_ts_export(sym)
                    || crate::scanner::ts_ast_extractor::TESTING_GLOBALS.contains(sym)
                {
                    continue;
                }
                let found = matching_libs.iter().any(|lib| cache.lookup(lib, sym).is_some());
                if !found {
                    result.warnings.push(format!(
                        "hallucinated-import: `{}` not found in package `{}`",
                        sym, pkg_name
                    ));
                    result.claims_hallucinated += 1;
                    result.claims_extracted += 1;
                }
            }
        }
    }

    // Step 2c: Namespace import member verification.
    // For `import * as ALIAS from 'package'` + `ALIAS.TypeName`:
    // verify TypeName is an actual export. Catches wrong type names
    // like CreateContextOptions vs CreateExpressContextOptions via
    // Levenshtein fuzzy match. FP-safe: requires ≥5 cached symbols.
    let ns_warnings = verify_ts_namespace_members(content);
    if !ns_warnings.is_empty() {
        result.claims_extracted += ns_warnings.len();
        result.claims_hallucinated += ns_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(ns_warnings);
    }

    // Step 3: Undefined variable detection via tree-sitter AST (FORGE 2026 pattern).
    // Replaces Node.js subprocess with deterministic AST parsing. Eliminates
    // prose contamination that produced 8 FORGE FPs per TS benchmark run.
    // Tree-sitter only extracts structurally valid identifiers, naturally
    // filtering English prose words like "deps", "Now", "the", "include".
    let undefined_names = crate::scanner::ts_ast_extractor::extract_undefined_variables(content);

    // Filter against cross-response session symbols (imports from previous
    // responses). Without this, `useTodoStore` imported in response 5 gets
    // flagged as undefined in response 7. The tree-sitter scope checker only
    // sees the current response's content.
    let session_syms = crate::scanner::project_index::get_session_symbols(project_root, "typescript");
    let session_names: std::collections::HashSet<&str> = session_syms
        .lines()
        .filter_map(|l| l.split(": ").nth(1))
        .collect();
    for name in &undefined_names {
        if session_names.contains(name.as_str()) {
            continue; // Known from previous response — skip
        }
        result.warnings.push(format!(
            "hallucinated-variable: `{}` — referenced but not defined in scope",
            name
        ));
        result.claims_hallucinated += 1;
    }
    result.claims_extracted += undefined_names.len();

    // Step 4: Method verification via Node.js introspection.
    // Builds import alias map (e.g., React→react), introspects each
    // package's exports via require(), verifies method calls exist.
    // Catches hallucinations like st.text_field vs st.text_input.
    let alias_map = crate::scanner::ts_introspect::build_ts_alias_map(content);
    if !alias_map.is_empty() {
        let method_warnings = crate::scanner::ts_introspect::verify_ts_methods(content, &alias_map, project_root).await;
        result.claims_extracted += method_warnings.len();
        result.claims_hallucinated += method_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(method_warnings);
    }

    // Step 5: Destructured import verification.
    // For `import { useState } from 'react'` + `useEffectState()`:
    // verifies destructured names against runtime exports via Node.js.
    // Only checks lowercase names (functions/hooks) — CamelCase are
    // TypeScript types, not in require() output.
    let destructured_map = crate::scanner::ts_introspect::build_ts_destructured_map(content);
    if !destructured_map.is_empty() {
        let destructure_warnings = crate::scanner::ts_introspect::verify_ts_destructured_calls(content, &destructured_map, project_root).await;
        result.claims_extracted += destructure_warnings.len();
        result.claims_hallucinated += destructure_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(destructure_warnings);

        // Step 6: Prefix-extension calls — bare calls that look like
        // hallucinated extensions of real destructured imports.
        // e.g., useEffectState() looks like extension of useEffect.
        let names: Vec<String> = destructured_map.keys().cloned().collect();
        let prefix_warnings = crate::scanner::ts_introspect::verify_ts_prefix_extension_calls(content, &names);
        result.claims_extracted += prefix_warnings.len();
        result.claims_hallucinated += prefix_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(prefix_warnings);
    }

    // Step 7: TypeScript Compiler API method hallucination detection.
    // Approach A from METHOD_DETECTION_PLAN.md: invokes ts.createProgram()
    // + getPreEmitDiagnostics() via Node.js subprocess, filters for TS2339
    // (Property does not exist on type). Highest-accuracy TS method detection.
    //
    // Catches DELULU samples like:
    //   - response.parseBody() vs response.json() (Response has no parseBody)
    //
    // Limitation: only fires when receiver's type is resolvable. Without
    // package type declarations (e.g., @types/mongodb not installed), the
    // receiver resolves to `any` and TS2339 won't fire. Returns empty when
    // typescript package isn't available (no false positives).
    let ts_compiler_diags =
        crate::scanner::ts_method_checker::verify_ts_methods_via_compiler(content, project_root).await;
    // Fragment-blindness guard (20260818 task-015 FP class): tsc runs on the
    // EXTRACTED fragment (disk imports + newString of ONE edit), so an
    // identifier declared elsewhere in the response/file correctly reads as
    // "Cannot find name" to tsc but is NOT a hallucination. Suppress
    // "Cannot find name 'X'" diagnostics when X is declared ANYWHERE in the
    // full scan content (param, const/let/var, function/class/interface/
    // type/import binding). Mid-stream truncated writes lose this evidence
    // naturally, so genuine typos still fire.
    let ts_compiler_diags: Vec<_> = ts_compiler_diags
        .into_iter()
        .filter(|diag| {
            if diag.message.starts_with("Cannot find name ") {
                if let Some(name) = extract_undeclared_candidate(&diag.message) {
                    return !name_declared_in_content(content, &name);
                }
            }
            true
        })
        .collect();
    if !ts_compiler_diags.is_empty() {
        for diag in &ts_compiler_diags {
            result.warnings.push(crate::scanner::ts_method_checker::format_warning(diag));
        }
        result.claims_extracted += ts_compiler_diags.len();
        result.claims_hallucinated += ts_compiler_diags.len();
    }

    // Step 8: Factory-derived receiver method verification via global
    // prototype introspection.
    //
    // Catches method hallucinations on receivers whose type comes from a
    // DOM/Node global factory (`fetch`, `new Response(...)`,
    // `new AbortController()`, ...) rather than an npm import. Existing
    // Steps 4-5 only handle receivers bound to import aliases; this
    // complements them for global APIs.
    //
    //   `const response = await fetch(url);`
    //   `response.parseBody()`  ← Response has no parseBody → flagged
    //
    // Graceful degradation: if Node.js is missing or the global isn't
    // defined (older Node), introspection returns an error and the step
    // emits zero warnings. FPR-safe: only fires when receiver is
    // explicitly bound to a detected factory call.
    let factory_map = crate::scanner::ts_introspect::build_ts_factory_receiver_map(content);
    if !factory_map.is_empty() {
        let factory_warnings =
            crate::scanner::ts_introspect::verify_ts_factory_methods(content, &factory_map).await;
        result.claims_extracted += factory_warnings.len();
        result.claims_hallucinated += factory_warnings
            .iter()
            .filter(|w| w.contains("hallucinated"))
            .count();
        result.warnings.extend(factory_warnings);
    }

    // Step 8: Known-arity hooks/functions check.
    // React hooks (useState, useCallback, useMemo, useEffect, useReducer,
    // useLayoutEffect, useRef) are NOT in the npm symbol cache, so the
    // generic check_call_arity in arity.rs skips them. Hard-coded table
    // of well-known signatures catches hallucinated extra-arg patterns
    // like useState(x, {initialValue: x}) or useCallback(fn, [], {triggerFocus: true}).
    let hook_warnings = check_known_ts_arities(content);
    if !hook_warnings.is_empty() {
        result.claims_extracted += hook_warnings.len();
        result.claims_hallucinated += hook_warnings.iter().filter(|w| w.contains("hallucinated")).count();
        result.warnings.extend(hook_warnings);
    }

    // Deterministic Prisma misuse check (no network, no cache).
    // Catches: prisma.X.update({ where: { id: V.id }, data: V }) — passing
    // the whole input (which contains id) as data tries to update the PK.
    let prisma_warnings = detect_prisma_id_in_data(content);
    if !prisma_warnings.is_empty() {
        result.claims_extracted += prisma_warnings.len();
        result.claims_hallucinated += prisma_warnings.len();
        result.warnings.extend(prisma_warnings);
    }

    result.latency_ms = start.elapsed().as_millis() as u64;
    result
}

/// Check calls to well-known TS/JS framework functions against their
/// documented arity. Catches hallucinated extra arguments without
/// requiring the symbol cache to have framework entries.
///
/// Count comma-separated arguments at depth 0 inside a TS call's argument list.
///
/// TS-specific variant of `arity::count_call_args`. The generic counter treats
/// `<` and `>` as depth changers (for Rust/Java generics like
/// `HashMap<String, i32>`). That breaks on TS arrow functions (`=>`),
/// decrementing depth without a matching `<` and producing wrong counts.
///
/// This version ignores `<`/`>` entirely (TS generics in call args are rare;
/// miscounts there are less harmful than breaking all arrow callbacks).
fn count_ts_call_args(args: &str) -> usize {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return 0;
    }
    let mut depth: i32 = 0;
    let mut count = 1usize;
    let mut in_string = false;
    let mut string_char = ' ';
    let mut prev_escape = false;
    for ch in trimmed.chars() {
        if in_string {
            if prev_escape {
                prev_escape = false;
            } else if ch == '\\' {
                prev_escape = true;
            } else if ch == string_char {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => { in_string = true; string_char = ch; }
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// Currently covers React hooks + a few DOM APIs that LLMs commonly
/// hallucinate extra arguments on. Designed to be conservative: only
/// flags when actual > expected (extra args), never when actual <
/// expected (missing args could be optional).
fn check_known_ts_arities(content: &str) -> Vec<String> {
    // Local TS-specific arity counter (handles arrow `=>` correctly).

    // Table of (function_name, expected_arity_max).
    // Uses MAX arity (most permissive documented overload) to avoid FPs.
    const KNOWN_ARITIES: &[(&str, usize)] = &[
        // React hooks — React 18 docs
        ("useState", 1),           // useState(initialState)
        ("useReducer", 3),         // useReducer(reducer, initialArg?, init?)
        ("useContext", 1),         // useContext(context)
        ("useEffect", 2),          // useEffect(setup, deps?)
        ("useLayoutEffect", 2),    // useLayoutEffect(setup, deps?)
        ("useCallback", 2),        // useCallback(fn, deps)
        ("useMemo", 2),            //useMemo(factory, deps)
        ("useRef", 1),             // useRef(initialValue)
        ("useImperativeHandle", 3),// useImperativeHandle(ref, create, deps?)
        ("useDebugValue", 2),      // useDebugValue(value, format?)
        ("useDeferredValue", 2),   // useDeferredValue(value, initialValue?) (React 19)
        ("useTransition", 1),      // useTransition(config?)
        ("useId", 0),              // useId()
        ("useSyncExternalStore", 3),// useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot?)
        // Common DOM
        ("alert", 1),
        ("confirm", 1),
        ("prompt", 2),
    ];

    let mut warnings = Vec::new();
    let mut checked: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for (name, expected) in KNOWN_ARITIES {
        if !checked.insert(name) {
            continue;
        }
        // Match `name(` as a bare call (not a method on a receiver).
        // Args are extracted via balanced-paren scan, NOT a `[^;]*` regex,
        // so callback bodies containing semicolons (e.g. useCallback(() => {
        // foo(); }, [])) parse correctly.
        let pattern = format!(r"(?:^|[^a-zA-Z0-9_\.]){}\s*\(", regex::escape(name));
        let re = match regex::Regex::new(&pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for m in re.find_iter(content) {
            // Start of args = end of match (just past the opening paren).
            let args_start = m.end();
            let bytes = content.as_bytes();
            let mut depth: i32 = 1;
            let mut i = args_start;
            let mut in_string: Option<u8> = None; // b'\'', b'"', or b'`'
            let mut prev: u8 = 0;
            while i < bytes.len() && depth > 0 {
                let c = bytes[i];
                match in_string {
                    Some(quote) => {
                        if prev == b'\\' {
                            // escaped char inside string, keep consuming
                        } else if c == quote {
                            in_string = None;
                        }
                    }
                    None => {
                        match c {
                            b'(' => depth += 1,
                            b')' => depth -= 1,
                            b'\'' | b'"' | b'`' => in_string = Some(c),
                            _ => {}
                        }
                    }
                }
                prev = c;
                i += 1;
            }
            if depth != 0 {
                continue; // unbalanced, skip
            }
            // `i` now points to the closing paren + 1.
            let args = &content[args_start..i.saturating_sub(1)];
            let actual = count_ts_call_args(args);
            if actual > *expected {
                warnings.push(format!(
                    "hallucinated-parameter: `{}({})` — `{}` accepts at most {} argument{} but called with {}",
                    name, args.trim(), name, expected,
                    if *expected == 1 { "" } else { "s" }, actual
                ));
            }
        }
    }

    warnings
}

// ---------------------------------------------------------------------------
// Prisma primary-key-in-data misuse detection
// ---------------------------------------------------------------------------
//
// Benchmark miss (task-03-ts-trpc): updateUser mutation used
//   prisma.user.update({ where: { id: input.id }, data: input })
// where `input` is `{ id, email, name }`. Passing the whole `input` (which
// contains the primary key) as `data:` tells Prisma to update the immutable
// id field — runtime error / unintended overwrite. Correct pattern:
//   const { id, ...data } = input;
//   prisma.user.update({ where: { id }, data });
//
// Detection: regex with backreference — flags only when the SAME identifier
// is used for `where.id` (via `.id`) AND passed wholesale as `data`.
// FP risk: very low. Legitimate code destructures or constructs data explicitly.

static PRISMA_WHERE_ID_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    // Captures IDENT used as `IDENT.id` in a where-clause: `where: { id: IDENT.id }`.
    regex::Regex::new(r#"where:\s*\{\s*id:\s*([A-Za-z_$][\w$]*)\.id\b"#).unwrap()
});

static PRISMA_UPDATE_BLOCK_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    // Greedily match `.update(` up to the first `));` or `);` — captures the call body.
    // We then scan the body for `data: IDENT` manually (no backrefs in Rust regex).
    regex::Regex::new(r#"\.update\(\s*(\{[\s\S]*?\})\s*\)"#).unwrap()
});

fn detect_prisma_id_in_data(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    for update_caps in PRISMA_UPDATE_BLOCK_RE.captures_iter(content) {
        let block = match update_caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        // Find the IDENT used as `IDENT.id` in the where-clause.
        let where_idents: Vec<&str> = PRISMA_WHERE_ID_RE
            .captures_iter(block)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .collect();
        if where_idents.is_empty() {
            continue;
        }
        // Check if the SAME IDENT appears as `data: IDENT` (whole-variable pass).
        for ident in where_idents {
            let data_pat_owned = format!(r#"\bdata:\s*{}\s*[,}}]"#, regex::escape(ident));
            let data_re = match regex::Regex::new(&data_pat_owned) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if data_re.is_match(block) {
                warnings.push(format!(
                    "prisma-id-in-data: `{}` is used for `where.id` AND passed wholesale as `data` — primary key would be in update payload (destructure: `const {{ id, ...data }} = {}`)",
                    ident, ident
                ));
                break; // one warning per update block
            }
        }
    }
    warnings
}

/// From `Cannot find name 'X'.` / `Cannot find name 'X'. Did you mean 'Y'?`
/// extract X (the quoted name after the first quote).
fn extract_undeclared_candidate(message: &str) -> Option<String> {
    let start = message.find('\'')? + 1;
    let end = message[start..].find('\'')? + start;
    let name = &message[start..end];
    if name.is_empty() {
        return None;
    }
    let first = name.chars().next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    Some(name.to_string())
}

/// True when `name` has a declaration shape ANYWHERE in the scan content:
/// function/class/interface/type/enum/import binding, const/let/var
/// assignment, or a parameter position (`name` followed by `: Type`, `,`,
/// `)`, `=`, or `?`). Conservative toward suppression only when the
/// binding text genuinely exists - a bare USE of the name never matches
/// (`jobId)` inside a call is checked but `updateJobStatus(jobId)` has
/// `jobId` followed by `)` - that IS a param-position shape only when it
/// is inside a parameter LIST; we accept the false-positive suppression
/// risk because FN cost >> FP cost).
pub(crate) fn name_declared_in_content(content: &str, name: &str) -> bool {
    if name.len() < 2 {
        return false;
    }
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
    for line in content.lines() {
        let t = line.trim_start();
        if t.starts_with("import ") && line.contains(name) {
            return true;
        }
        for kw in ["function ", "class ", "interface ", "type ", "enum "] {
            if let Some(rest) = t.strip_prefix(kw) {
                if rest.starts_with(name) {
                    if rest[name.len()..].chars().next().is_none_or(|c| !is_ident(c)) {
                        return true;
                    }
                }
            }
        }
        for kw in ["const ", "let ", "var "] {
            if let Some(rest) = t.strip_prefix(kw) {
                if rest.starts_with(name) {
                    if rest[name.len()..].chars().next().map(|c| !is_ident(c)).unwrap_or(true) {
                        return true;
                    }
                }
            }
        }
        let mut search = 0usize;
        while let Some(pos) = line[search..].find(name) {
            let abs = search + pos;
            let before_ok = abs == 0 || !is_ident(line[..abs].chars().last().unwrap());
            let after = line[abs + name.len()..].trim_start();
            if before_ok
                && (after.starts_with(':')
                    || after.starts_with(',')
                    || after.starts_with(')')
                    || after.starts_with('=')
                    || after.starts_with('?'))
            {
                return true;
            }
            search = abs + name.len();
        }
    }
    false
}
#[cfg(test)]
mod prisma_id_in_data_tests {
    use super::detect_prisma_id_in_data;

    #[test]
    fn benchmark_pattern_flagged() {
        // Exact benchmark task-03-ts-trpc pattern.
        let code = r#"
export const updateUser = publicProcedure
  .input(z.object({ id: z.number(), email: z.string(), name: z.string() }))
  .mutation(async ({ input }) => {
    return prisma.user.update({
      where: { id: input.id },
      data: input,
    });
  });
"#;
        let w = detect_prisma_id_in_data(code);
        assert!(w.iter().any(|x| x.contains("input")), "got {:?}", w);
    }

    #[test]
    fn destructured_data_not_flagged() {
        let code = r#"
const { id, ...data } = input;
return prisma.user.update({ where: { id }, data });
"#;
        let w = detect_prisma_id_in_data(code);
        assert!(w.is_empty(), "got {:?}", w);
    }

    #[test]
    fn different_vars_not_flagged() {
        let code = r#"
prisma.user.update({ where: { id: userId }, data: { name: "x" } });
"#;
        let w = detect_prisma_id_in_data(code);
        assert!(w.is_empty(), "got {:?}", w);
    }
}

#[cfg(test)]
mod arity_tests {
    use super::check_known_ts_arities;

    #[test]
    fn use_callback_three_args_with_semicolon_body_caught() {
        // Regression: DELULU typescript-parameter-f41e6c8be563.
        // useCallback with extra third arg, body contains semicolons
        // inside arrow function — `[^;]*` regex was truncating args list.
        let code = "  useCallback(() => {
    if (inputRef.current) {
      inputRef.current.click();
    }
  }, [], { triggerFocus: true });";
        let warnings = check_known_ts_arities(code);
        assert!(
            warnings.iter().any(|w| w.contains("useCallback") && w.contains("3")),
            "expected useCallback arity violation, got: {:?}",
            warnings
        );
    }

    #[test]
    fn use_state_extra_arg_caught() {
        let code = "useState(shouldActivate, { initialValue: shouldActivate });";
        let warnings = check_known_ts_arities(code);
        assert!(warnings.iter().any(|w| w.contains("useState")));
    }

    #[test]
    fn bare_call_only_no_method_calls() {
        // foo.useState() should NOT match (method on object).
        let code = "instance.useState(x, y);";
        let warnings = check_known_ts_arities(code);
        assert!(
            warnings.is_empty(),
            "method-call should not match bare-call arity check, got: {:?}",
            warnings
        );
    }
}

/// Verify that `ALIAS.TypeName` accesses in namespace imports reference
/// actual exports of the source package.
///
/// Catches wrong type names like `trpcExpress.CreateContextOptions` when
/// the real export is `CreateExpressContextOptions`. Uses Levenshtein
/// distance for fuzzy suggestions.
///
/// FP safety: only fires when the cached library has ≥ 5 symbols
/// (adequate coverage). Below that, the cache may simply be incomplete.
/// "Not found without suggestion" only fires with ≥ 20 cached symbols.
fn verify_ts_namespace_members(content: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    let Ok(cache) = crate::symbols::cache::SymbolCache::open() else {
        return warnings;
    };
    let cached_libs = cache.list_libraries();

    for caps in NAMESPACE_IMPORT_RE.captures_iter(content) {
        let alias = caps.get(1).unwrap().as_str();
        let pkg_path = caps.get(2).unwrap().as_str();
        if pkg_path.starts_with('.') || pkg_path.starts_with("node:") {
            continue;
        }
        let pkg_name = crate::scanner::ts_introspect::npm_package_from_path(pkg_path);

        // Find matching cached libraries + total symbol count for coverage check.
        let matching: Vec<(&str, usize)> = cached_libs
            .iter()
            .filter(|(l, _, _)| l.contains(&pkg_name) || pkg_name.contains(l))
            .map(|(l, _, count)| (l.as_str(), *count))
            .collect();
        if matching.is_empty() {
            continue;
        }
        let total_syms: usize = matching.iter().map(|(_, c)| c).sum();
        if total_syms < 5 {
            continue; // Cache too sparse — can't distinguish real hallucination from gap.
        }

        // Extract PascalCase member accesses: ALIAS.TypeName.
        // Lowercase members are functions/values — covered by Steps 4-8.
        let member_re_str = format!(r"\b{}\.([A-Z]\w*)", regex::escape(alias));
        let Ok(member_re) = regex::Regex::new(&member_re_str) else {
            continue;
        };

        // Collect all cached export names for fuzzy matching (once per lib).
        // Only PascalCase names — types/interfaces/classes.
        let mut all_names: Vec<String> = Vec::new();
        for (lib, _) in &matching {
            for sym in cache.lookup_prefix(lib, "") {
                if sym.name.len() >= 3
                    && sym.name.chars().next().map_or(false, |c| c.is_uppercase())
                {
                    all_names.push(sym.name.clone());
                }
            }
        }
        all_names.sort();
        all_names.dedup();

        let mut checked = std::collections::HashSet::new();
        for mcaps in member_re.captures_iter(content) {
            let member = mcaps.get(1).unwrap().as_str();
            if !checked.insert(member.to_string()) {
                continue;
            }
            if crate::scanner::forge_pipeline::is_common_ts_export(member)
                || crate::scanner::ts_ast_extractor::TESTING_GLOBALS.contains(member)
            {
                continue;
            }

            // Exact match against any matching lib.
            let found = matching
                .iter()
                .any(|(lib, _)| cache.lookup(lib, member).is_some());
            if found {
                continue;
            }

            // Fuzzy match: Levenshtein distance ≤ max(3, len * 40%).
            let threshold = std::cmp::max(3, member.len() * 2 / 5);
            let mut best: Option<(String, usize)> = None;
            for name in &all_names {
                let dist =
                    crate::scanner::levenshtein::capped(member, name, threshold + 1);
                if dist <= threshold {
                    match &best {
                        None => best = Some((name.clone(), dist)),
                        Some((_, d)) if dist < *d => best = Some((name.clone(), dist)),
                        _ => {}
                    }
                }
            }

            match best {
                Some((suggestion, _)) => {
                    warnings.push(format!(
                        "hallucinated-import-name: `{}` not found in `{}` — did you mean `{}`?",
                        member, pkg_name, suggestion
                    ));
                }
                None if total_syms >= 20 => {
                    warnings.push(format!(
                        "hallucinated-import-name: `{}` not found in package `{}`",
                        member, pkg_name
                    ));
                }
                None => {} // Sparse cache — can't be certain.
            }
        }
    }

    warnings
}

use std::collections::{HashMap, HashSet};

/// Detect fabricated package-lock.json integrity hashes.
///
/// Real integrity format: `sha512-<base64>` (SHA-512, ~88 base64 chars) or
/// `sha256-<base64>` (SHA-256, ~44 base64 chars).
///
/// Fabrication patterns:
/// 1. Wrong hash prefix (not sha512-/sha256-/sha1-)
/// 2. Duplicate integrity hash across different packages
/// 3. Shared long suffix (≥20 chars) across different packages
static PKG_LOCK_ENTRY_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#""([^"]+)":\s*\{[^{}]*?"integrity"\s*:\s*"([^"]+)""#).unwrap()
});

pub fn detect_pkg_lock_integrity_fabrication(content: &str) -> Vec<String> {
    if !content.contains("lockfileVersion") && !content.contains("\"integrity\"") {
        return Vec::new();
    }

    let mut entries: Vec<(String, String)> = Vec::new();
    for caps in PKG_LOCK_ENTRY_RE.captures_iter(content) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let integrity = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
        if !integrity.is_empty() {
            entries.push((name, integrity));
        }
    }

    if entries.len() < 2 {
        return Vec::new();
    }

    let mut warnings: Vec<String> = Vec::new();
    let mut seen: HashMap<&str, &str> = HashMap::new();
    let mut suffix_map: HashMap<String, Vec<String>> = HashMap::new();

    for (pkg_id, integrity) in &entries {
        // Check 1: wrong hash prefix
        let valid_prefix = integrity.starts_with("sha512-")
            || integrity.starts_with("sha256-")
            || integrity.starts_with("sha1-");
        if !valid_prefix {
            warnings.push(format!(
                "hallucinated-integrity: package-lock `{}` has unrecognized integrity format `{}` (expected sha512-/sha256-/sha1-)",
                pkg_id, integrity
            ));
        }

        // Check 2: exact duplicate
        if let Some(prev) = seen.get(integrity.as_str()) {
            if prev != pkg_id {
                warnings.push(format!(
                    "hallucinated-integrity: package-lock `{}` and `{}` share identical integrity hash",
                    prev, pkg_id
                ));
            }
        } else {
            seen.insert(integrity.as_str(), pkg_id);
        }

        // Check 3: shared suffix
        if integrity.len() >= 20 {
            let suffix = integrity[integrity.len() - 20..].to_string();
            suffix_map.entry(suffix).or_default().push(pkg_id.clone());
        }
    }

    for (suffix, pkgs) in &suffix_map {
        let unique: Vec<&str> = pkgs.iter().map(|s| s.as_str()).collect::<HashSet<_>>().into_iter().collect();
        if unique.len() > 1 {
            warnings.push(format!(
                "hallucinated-integrity: different package-lock entries share identical hash suffix `...{}`: {}",
                suffix, unique.join(", ")
            ));
        }
    }

    warnings.dedup();
    warnings
}

#[cfg(test)]
mod pkg_lock_integrity_tests {
    use super::*;

    #[test]
    fn wrong_format_flagged() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "integrity": "bogus-hash-without-prefix"
    },
    "node_modules/express": {
      "integrity": "sha512-abc12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"
    }
  }
}"#;
        let w = detect_pkg_lock_integrity_fabrication(content);
        assert!(w.iter().any(|s| s.contains("lodash") && s.contains("unrecognized")),
            "expected format warning for lodash, got: {:?}", w);
    }

    #[test]
    fn exact_duplicate_flagged() {
        let hash = "sha512-samebase64hashhere123456789012345678901234567890123456789012345678901234567890123456789012345";
        let content = format!(r#"{{
  "lockfileVersion": 3,
  "packages": {{
    "node_modules/lodash": {{
      "integrity": "{}"
    }},
    "node_modules/express": {{
      "integrity": "{}"
    }}
  }}
}}"#, hash, hash);
        let w = detect_pkg_lock_integrity_fabrication(&content);
        assert!(w.iter().any(|s| s.contains("identical integrity")),
            "expected duplicate warning, got: {:?}", w);
    }

    #[test]
    fn distinct_valid_hashes_not_flagged() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "integrity": "sha512-aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa1111bbbb2222cccc3333dddd4444eeee5555ff"
    },
    "node_modules/express": {
      "integrity": "sha512-zzzz9999yyyy8888xxxx7777wwww6666vvvv5555uuuu4444zzzz9999yyyy8888xxxx7777wwww6666vvvv5555u"
    }
  }
}"#;
        let w = detect_pkg_lock_integrity_fabrication(content);
        assert!(w.iter().all(|s| !s.contains("identical") && !s.contains("shared")),
            "should not flag distinct hashes, got: {:?}", w);
    }

    #[test]
    fn non_pkg_lock_content_not_flagged() {
        let w = detect_pkg_lock_integrity_fabrication("const integrity = 'simple';");
        assert!(w.is_empty(), "non-package-lock content should not trigger, got: {:?}", w);
    }
}

#[cfg(test)]
mod namespace_member_tests {
    use super::*;

    fn seed_trpc_symbols() {
        let cache = crate::symbols::cache::SymbolCache::open().unwrap();
        let lib = "@trpc/server/adapters/express";
        let mut syms: Vec<crate::symbols::types::Symbol> = Vec::new();
        for name in &[
            "CreateExpressContextOptions",
            "createExpressMiddleware",
            "NodeHTTPCreateContextFunctionOptions",
            "FetchRequest",
            "FetchCreateContextFnOptions",
            "ExpressCreateContextFunctionOptions",
        ] {
            let mut s = crate::symbols::types::Symbol::new(lib, "10.45.2", *name);
            s.kind = crate::symbols::types::SymbolKind::Interface;
            syms.push(s);
        }
        cache.insert_many(&syms).unwrap();
    }

    fn cleanup_trpc_symbols() {
        let cache = crate::symbols::cache::SymbolCache::open().unwrap();
        let _ = cache.remove_library("@trpc/server/adapters/express", "10.45.2");
    }

    #[test]
    fn wrong_type_name_flagged_with_suggestion() {
        seed_trpc_symbols();
        let content = r#"
import * as trpcExpress from '@trpc/server/adapters/express';
const createContext = ({ req, res }: trpcExpress.CreateContextOptions) => ({});
"#;
        let warnings = verify_ts_namespace_members(content);
        cleanup_trpc_symbols();

        let found = warnings.iter().find(|w| w.contains("CreateContextOptions"));
        assert!(found.is_some(), "expected CreateContextOptions warning, got: {:?}", warnings);
        let w = found.unwrap();
        assert!(w.contains("CreateExpressContextOptions"),
            "expected suggestion, got: {}", w);
    }

    #[test]
    fn correct_type_name_not_flagged() {
        seed_trpc_symbols();
        let content = r#"
import * as trpcExpress from '@trpc/server/adapters/express';
const createContext = ({ req, res }: trpcExpress.CreateExpressContextOptions) => ({});
"#;
        let warnings = verify_ts_namespace_members(content);
        cleanup_trpc_symbols();

        let found = warnings.iter().find(|w| w.contains("CreateExpressContextOptions"));
        assert!(found.is_none(), "should not flag real export, got: {:?}", warnings);
    }
}
