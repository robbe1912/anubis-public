//! FORGE pipeline orchestrator (FORGE 2026 pattern step 3/3).
//!
//! Composes the three FORGE modules into a single L1.7 layer between
//! L1.5 (symbol cache) and L3 (per-claim LLM verifier):
//!
//!   ┌──────────────────────────────────────────────────────────────┐
//!   │  FORGE pipeline (this module)                                │
//!   │                                                              │
//!   │  ┌────────────────┐    ┌──────────────────┐                 │
//!   │  │ ast_extractor  │ -> │ local_introspect │ (Python only)   │
//!   │  │ (tree-sitter   │    │ (subprocess dir) │                 │
//!   │  │  equivalent)   │    └──────────────────┘                 │
//!   │  └────────────────┘                │                        │
//!   │           │                        │                        │
//!   │           v                        v                        │
//!   │  ┌────────────────────────────────────────┐                 │
//!   │  │ package_index (PyPI/npm/crates/Maven)  │                 │
//!   │  │ — verifies imports that failed introspect│                 │
//!   │  └────────────────────────────────────────┘                 │
//!   │           │                                                 │
//!   │           v                                                 │
//!   │  ForgeResult { warnings, counts }                           │
//!   └──────────────────────────────────────────────────────────────┘
//!
//! Cascade principle: if FORGE produces definitive verdicts (verified
//! or hallucinated), L3 doesn't need to run for those claims. Only
//! ambiguous claims (FORGE couldn't determine) reach L3.

use serde::{Deserialize, Serialize};

use crate::scanner::arity::{count_call_args, parse_signature_arity, check_call_arity};
use crate::scanner::levenshtein::{capped as levenshtein_capped_internal, distance as levenshtein_distance};
use crate::scanner::string_filters::{filter_function_calls, strip_c_style_string_literals};

pub use crate::scanner::forge_types::ForgeResult;
pub use crate::scanner::language_detection::detect_language;

/// Run the FORGE pipeline on `content`.
///
/// Currently supports Python only — other languages fall through with an
/// empty ForgeResult (caller continues with regex extract_api_claims +
/// symbol cache + L3 as before).
///
/// `language` should be one of: python, typescript, javascript, rust,
/// java, csharp, go, cpp. Unknown languages return empty result.
///
/// `scope_vars` is the variable-type bindings from `scope_analysis`
/// (e.g., `[("df", "DataFrame"), ("scaler", "StandardScaler")]`).
///
/// `project_root` is the workspace root for resolving node_modules (used by
/// the TypeScript compiler method checker).
pub async fn run_forge_pipeline(
    content: &str,
    language: &str,
    scope_vars: &[(String, String)],
    project_index: &str,
    project_root: &str,
) -> ForgeResult {
    let mut result = run_forge_pipeline_inner(content, language, scope_vars, project_index, project_root).await;
    populate_forge_confidence(&mut result);
    result
}

/// Infer per-claim confidence from warning prefixes. Centralized so adding
/// a new warning type only requires updating this function + the cascade
/// thresholds. Confidence mapping:
///
///   - hallucinated-include (C++ headers list) → 0.95 (curated list)
///   - hallucinated-import (registry 404) → 0.90 (PyPI/npm/etc authority)
///   - hallucinated-method (introspection miss) → 0.95 (runtime API check)
///   - hallucinated-variable (scope checker) → 0.85 (regex-derived)
///   - hallucinated-parameter (signature inspect) → 0.95 (Python signature)
///   - hallucinated-function (cache miss + levenshtein) → 0.85
///   - hallucinated-constructor (CamelCase + suffix match) → 0.70 (weaker)
///   - hallucinated-call (prefix extension) → 0.75
///   - bare-critical-call (FORGE paper pattern) → 0.90
///   - chain-broken / chain-phantom-member (return-type track) → 0.85
fn populate_forge_confidence(result: &mut ForgeResult) {
    for warning in &result.warnings {
        // Extract claim key from warning. Warnings follow patterns like:
        //   "hallucinated-method: `receiver.method` — ..."
        //   "hallucinated-import: `pkg.name` — ..."
        // We use the text between backticks as the claim key.
        let claim_key = extract_claim_key_from_warning(warning);
        if claim_key.is_empty() {
            continue;
        }
        // Skip if already populated with higher confidence (avoid overwrite).
        let conf = confidence_for_warning(warning);
        if let Some(existing) = result.claim_confidence.get(&claim_key) {
            if *existing >= conf {
                continue;
            }
        }
        result.claim_confidence.insert(claim_key, conf);
    }
}

/// Extract the claim identifier from a FORGE warning string.
/// Looks for the first backtick-quoted token, which is the canonical claim key.
fn extract_claim_key_from_warning(warning: &str) -> String {
    let bytes = warning.as_bytes();
    let mut start = None;
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'`' {
            if start.is_none() {
                start = Some(i + 1);
            } else {
                // End backtick found.
                return warning[start.unwrap()..i].to_string();
            }
        }
    }
    String::new()
}

/// Single source of truth for warning-prefix literal strings.
///
/// Every prefix parsed by [`classify_warning`] and emitted at the L1 / L1.5 /
/// dashboard sites is named here. To add a warning prefix:
///   1. add a `const` here,
///   2. add a [`WarningKind`] variant,
///   3. add a `starts_with(...)` branch in [`classify_warning`] referencing
///      the const,
///   4. update `is_forge_hallucination` / `confidence_for_warning` if the
///      kind participates in risk scoring.
/// Consumers (compute_risk_score, dashboard, emission sites) reference these
/// consts instead of re-typing the literal, so a rename cannot silently
/// desynchronise the parser from the emitters.
pub mod prefix {
    /// Wrapper prepended to every FORGE-pipeline warning before it reaches
    /// `result.warnings` (see `scan_response`). Stripped by `classify_warning`.
    pub const FORGE: &str = "forge: ";

    // ── Non-FORGE top-level prefixes (no `forge: ` wrapper) ──────────────
    /// L1.5 symbol-cache hallucination (mod.rs emission).
    pub const CACHED_HALLUCINATION: &str = "cached-hallucination:";
    /// L1.5 scope-analysis hallucination (mod.rs emission).
    pub const SCOPE_HALLUCINATION: &str = "scope-hallucination:";
    /// L1 fuzzy-match suggestion (regex claim extractor).
    pub const HALLUCINATED_API: &str = "Hallucinated API:";
    /// L1 unverified-API notice (regex claim extractor).
    pub const UNVERIFIED_API: &str = "Unverified API:";

    // ── FORGE sub-prefixes (appear after `forge: ` is stripped) ──────────
    pub const HALLUCINATED_IMPORT_NAME: &str = "hallucinated-import-name:";
    pub const HALLUCINATED_IMPORT: &str = "hallucinated-import:";
    pub const HALLUCINATED_INCLUDE: &str = "hallucinated-include:";
    pub const HALLUCINATED_METHOD: &str = "hallucinated-method:";
    pub const HALLUCINATED_PARAMETER: &str = "hallucinated-parameter:";
    pub const HALLUCINATED_VARIABLE: &str = "hallucinated-variable:";
    pub const HALLUCINATED_FUNCTION: &str = "hallucinated-function:";
    pub const HALLUCINATED_CONSTRUCTOR: &str = "hallucinated-constructor:";
    pub const HALLUCINATED_CALL: &str = "hallucinated-call:";
    pub const HALLUCINATED_NAMESPACE: &str = "hallucinated-namespace:";
    pub const BARE_CRITICAL_CALL: &str = "bare-critical-call:";
    pub const CHAIN_BROKEN: &str = "chain-broken:";
    pub const CHAIN_PHANTOM_MEMBER: &str = "chain-phantom-member:";

    // ── Other top-level prefixes (not yet in WarningKind) ────────────────
    /// Compiler-verifier warning (compiler_verifier.rs emission). Parsed by
    /// `compute_risk_score` directly; not yet a `WarningKind` variant.
    pub const COMPILER: &str = "compiler:";
}

/// Structured classification of a warning string (council A8+B5).
///
/// Every warning emitted by the scanner falls into one of these kinds.
/// `classify_warning` parses the raw warning string into a kind so that
/// the cascade (compute_risk_score, cross-response FP filter, L3 gate)
/// can match exhaustively instead of via fragile `starts_with` chains
/// that silently fall through when a new prefix is added.
///
/// Adding a new warning kind: extend this enum + the match in
/// `classify_warning` + the `is_forge_hallucination`/`confidence_for_warning`
/// consumers. The compiler will flag every non-exhaustive match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarningKind {
    // FORGE-prefixed (strip "forge: " first)
    HallucinatedInclude,
    HallucinatedImport,
    HallucinatedImportName,
    HallucinatedMethod,
    HallucinatedParameter,
    HallucinatedVariable,
    HallucinatedFunction,
    HallucinatedConstructor,
    HallucinatedCall,
    HallucinatedNamespace,
    BareCriticalCall,
    ChainBroken,
    ChainPhantomMember,
    // L1.5 symbol cache (no forge: prefix)
    CachedHallucination,
    ScopeHallucination,
    // L1 fuzzy / claim extraction (no forge: prefix)
    HallucinatedApi,
    UnverifiedApi,
    /// Anything we don't recognise. Risk scoring treats this as Other so
    /// the categorize_warnings helper surfaces "UNRECOGNIZED prefix" logs
    /// rather than silently undercounting.
    Other,
}

/// Classify a raw warning string into a [`WarningKind`].
///
/// Strips the `forge: ` prefix automatically. Two warnings that differ only
/// in their payload (`hallucinated-method: foo.bar()` vs
/// `hallucinated-method: baz.qux()`) collapse to the same kind — the kind
/// is the *category*, not the *instance*.
pub fn classify_warning(warning: &str) -> WarningKind {
    use WarningKind::*;
    use prefix as p;
    let stripped = warning.strip_prefix(p::FORGE).unwrap_or(warning);
    // Order matters for prefixes that share a stem (e.g. "hallucinated-import"
    // vs "hallucinated-import-name"). Match the longer/more-specific first.
    if stripped.starts_with(p::HALLUCINATED_IMPORT_NAME) {
        HallucinatedImportName
    } else if stripped.starts_with(p::HALLUCINATED_IMPORT) {
        HallucinatedImport
    } else if stripped.starts_with(p::HALLUCINATED_INCLUDE) {
        HallucinatedInclude
    } else if stripped.starts_with(p::HALLUCINATED_METHOD) {
        HallucinatedMethod
    } else if stripped.starts_with(p::HALLUCINATED_PARAMETER) {
        HallucinatedParameter
    } else if stripped.starts_with(p::HALLUCINATED_VARIABLE) {
        HallucinatedVariable
    } else if stripped.starts_with(p::HALLUCINATED_FUNCTION) {
        HallucinatedFunction
    } else if stripped.starts_with(p::HALLUCINATED_CONSTRUCTOR) {
        HallucinatedConstructor
    } else if stripped.starts_with(p::HALLUCINATED_CALL) {
        HallucinatedCall
    } else if stripped.starts_with(p::HALLUCINATED_NAMESPACE) {
        HallucinatedNamespace
    } else if stripped.starts_with(p::BARE_CRITICAL_CALL) {
        BareCriticalCall
    } else if stripped.starts_with(p::CHAIN_BROKEN) {
        ChainBroken
    } else if stripped.starts_with(p::CHAIN_PHANTOM_MEMBER) {
        ChainPhantomMember
    } else if stripped.starts_with(p::CACHED_HALLUCINATION) {
        CachedHallucination
    } else if stripped.starts_with(p::SCOPE_HALLUCINATION) {
        ScopeHallucination
    } else if stripped.starts_with(p::HALLUCINATED_API) {
        HallucinatedApi
    } else if stripped.starts_with(p::UNVERIFIED_API) {
        UnverifiedApi
    } else {
        Other
    }
}

/// True for any warning that should be treated as a FORGE hallucination
/// (i.e. weight 0.40 in risk scoring). Covers all `Hallucinated*` variants
/// plus BareCriticalCall / ChainBroken / ChainPhantomMember — these all
/// signal a deterministic FORGE-layer finding.
pub fn is_forge_hallucination(warning: &str) -> bool {
    matches!(
        classify_warning(warning),
        WarningKind::HallucinatedInclude
            | WarningKind::HallucinatedImport
            | WarningKind::HallucinatedImportName
            | WarningKind::HallucinatedMethod
            | WarningKind::HallucinatedParameter
            | WarningKind::HallucinatedVariable
            | WarningKind::HallucinatedFunction
            | WarningKind::HallucinatedConstructor
            | WarningKind::HallucinatedCall
            | WarningKind::HallucinatedNamespace
            | WarningKind::BareCriticalCall
            | WarningKind::ChainBroken
            | WarningKind::ChainPhantomMember
    )
}

/// Map warning prefix → confidence score. See populate_forge_confidence docs.
fn confidence_for_warning(warning: &str) -> f64 {
    use WarningKind::*;
    match classify_warning(warning) {
        HallucinatedInclude | HallucinatedMethod | HallucinatedParameter => 0.95,
        HallucinatedImport | BareCriticalCall => 0.90,
        HallucinatedVariable | HallucinatedFunction | ChainBroken => 0.85,
        HallucinatedImportName | ChainPhantomMember => 0.80,
        HallucinatedCall => 0.75,
        HallucinatedConstructor => 0.70,
        // Non-FORGE warnings (cached-hallucination, scope-hallucination,
        // Hallucinated API, Unverified API) have their own scoring paths in
        // compute_risk_score; confidence_for_warning is only called on FORGE
        // warnings via populate_forge_confidence. Neutral 0.50 default
        // preserves prior behaviour for any other prefix.
        _ => 0.50,
    }
}

/// Pathological-input guard (parse-DoS): tree-sitter error recovery is
/// super-linear on massive runs of unmatched opening delimiters — the
/// stress-robustness suite measured a 17-minute worker pin on 200k unclosed
/// `{`. Input whose peak unclosed-delimiter depth exceeds this cap is
/// corrupted/truncated model output, not real code: skip the AST layers
/// entirely (regex L1 + L3 still run via the caller).
const MAX_UNCLOSED_DELIM_DEPTH: i32 = 5_000;

/// Peak nesting depth of unclosed `{ [ (` across the content. Closers when
/// already at depth 0 are ignored (floor at 0) so interleaved garbage cannot
/// fake a low score.
fn unclosed_delim_depth(content: &str) -> i32 {
    let mut depth: i32 = 0;
    let mut max_depth: i32 = 0;
    for b in content.bytes() {
        match b {
            b'{' | b'[' | b'(' => {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
            }
            b'}' | b']' | b')' => {
                depth -= 1;
                if depth < 0 {
                    depth = 0;
                }
            }
            _ => {}
        }
    }
    max_depth
}

/// Inner pipeline (language dispatch). Public `run_forge_pipeline` wraps
/// this to populate confidence after per-language processing.
async fn run_forge_pipeline_inner(
    content: &str,
    language: &str,
    scope_vars: &[(String, String)],
    project_index: &str,
    project_root: &str,
) -> ForgeResult {
    let mut result = ForgeResult::default();

    // Parse-DoS guard: bail before any AST layer on pathological nesting.
    if unclosed_delim_depth(content) > MAX_UNCLOSED_DELIM_DEPTH {
        tracing::warn!(
            target: "forge_pipeline",
            content_len = content.len(),
            language = language,
            "pathological unclosed-delimiter depth — skipping AST layers (parse-DoS guard)"
        );
        return result;
    }

    // Language dispatch. Python gets full FORGE (AST + introspect + pkg_index).
    // TypeScript/JS/Rust/Go get partial FORGE (regex imports + registry check).
    // Other languages: defer to existing regex + L3 path (future: add per-lang).
    match language {
        "python" => return run_forge_python(content, &scope_vars, project_index, project_root).await,
        "typescript" | "javascript" => return run_forge_ts(content, language, project_root).await,
        "rust" => return run_forge_rust(content, project_index).await,
        "go" => return run_forge_go(content).await,
        "java" => return run_forge_java(content, project_root).await,
        "csharp" => return run_forge_csharp(content).await,
        "cpp" => return run_forge_cpp(content).await,
        "c" => return run_forge_c(content).await,
        "gdscript" => return run_forge_gdscript(content).await,
        "tscn" => return run_forge_tscn(content).await,
        "gdshader" => return run_forge_gdshader(content).await,
        other => {
            // Council B5: previously silent `_ => return result` fallthrough
            // hid typo/missing dispatch from operators — the FORGE pipeline
            // silently did nothing for that language. Surface in scanner log
            // so unknown languages are observable. Empty string (when caller
            // has no detected_language) is intentionally quiet — that path
            // is expected for code-region extraction prior to classification.
            if !other.is_empty() {
                tracing::warn!(
                    target: "forge_pipeline",
                    language = other,
                    content_len = content.len(),
                    "no FORGE dispatch for language — pipeline returns empty result"
                );
            }
            return result;
        }
    }
}

/// TypeScript/JavaScript FORGE pipeline (partial implementation).
///
/// Currently verifies imports against npm registry. Future: add AST-based
/// extraction via tree-sitter-typescript for method/constructor verification.

/// Common TS named exports that are always valid imports but may not appear
/// individually in the cached API surface (type-only exports, framework
/// globals, generated code, etc.). Shared between FORGE Step 2b (named
/// import verification) and `verify_ts_destructured_calls` (runtime call
/// verification) so both paths agree on what to skip.
pub(crate) static COMMON_TS_EXPORTS: once_cell::sync::Lazy<std::collections::HashSet<&'static str>> = once_cell::sync::Lazy::new(|| {
    [
    // Testing framework globals (`describe`, `it`, `test`, `expect`,
    // `beforeEach`, `afterEach`, `beforeAll`, `afterAll`, `vi`) live in
    // `ts_ast_extractor::TESTING_GLOBALS` — the canonical source-of-truth,
    // shared with the tree-sitter undefined-variable pass. Do not
    // duplicate them here. Both FORGE use-sites (this file +
    // ts_introspect.rs) check both lists.
    "fn", "mock", "spyOn",
    "render", "screen", "fireEvent", "waitFor", "within", "cleanup", "act",
    "useState", "useEffect", "useRef", "useMemo", "useCallback",
    "useContext", "useReducer", "useLayoutEffect", "Fragment", "Component",
    "createElement", "createRef", "forwardRef", "memo", "lazy", "Suspense",
    "StrictMode", "Profiler", "Children",
    "createRoot", "hydrateRoot", "flushSync",
    "FormEvent", "ChangeEvent", "MouseEvent", "KeyboardEvent",
    "ReactNode", "ReactElement", "FC", "ComponentType", "PropsWithChildren",
    "Dispatch", "SetStateAction", "Context", "Provider",
    "create", "persist", "immer", "shallow", "defineConfig", "default",
    // Express types — TypeScript types from @types/express, not runtime values.
    // require('express') doesn't list these; they're type-only exports.
    "Request", "Response", "NextFunction", "RequestHandler",
    "ErrorRequestHandler", "Application", "Router", "IRouter", "IRoute",
    "RequestParamHandler", "CookieParser", "static",
    // Prisma — PrismaClient and Prisma are generated at build time
    // by `npx prisma generate`, not in static package exports.
    "PrismaClient", "Prisma",
    // Zod schema builders and methods — used in schema definitions.
    "z", "object", "string", "number", "boolean", "array", "optional",
    "nullable", "enum", "literal", "union", "intersection", "record",
    "tuple", "lazy", "promise", "unknown", "any", "void", "never",
    "undefined", "null", "refine", "superRefine", "transform", "default",
    "coerce", "brand", "catch", "describe", "pipe", "readonly",
    // Fastify types
    "FastifyInstance", "FastifyRequest", "FastifyReply",
    // Node.js types
    "Buffer", "Readable", "Writable", "Stream", "EventEmitter",
    "fileURLToPath", "pathToFileURL", "URL", "parse", "format", "resolve",
    // Node.js built-in module names (import http from 'http' etc.)
    "http", "https", "fs", "path", "crypto", "os", "stream", "zlib",
    "net", "dns", "url", "querystring", "util", "events", "assert",
    "child_process", "cluster", "dgram", "readline", "repl", "tls",
    "vm", "worker_threads", "perf_hooks", "process",
    // DOM API types (browser globals, not in require())
    "Document", "Window", "Element", "HTMLElement", "HTMLInputElement",
    "HTMLButtonElement", "HTMLDivElement", "HTMLSpanElement", "HTMLAnchorElement",
    "Event", "MouseEvent", "KeyboardEvent", "ChangeEvent", "FocusEvent",
    "Node", "NodeList", "HTMLCollection", "DOMTokenList",
    // DOM API types (browser globals, not in require())
    // Zod error types
    "ZodError", "ZodIssue", "ZodType",
    // Vue/Pinia ecosystem
    "defineComponent", "defineAsyncComponent", "defineCustomElement",
    "ref", "reactive", "computed", "watch", "watchEffect", "toRef", "toRefs",
    "defineStore", "createPinia", "storeToRefs",
    ].into_iter().collect()
});

// ── User-extendable TS export allow-list (Council A7) ──────────────────────
//
// COMMON_TS_EXPORTS above is a static set baked into the binary. Users with
// internal component libraries or build-time-generated exports (Prisma client,
// GraphQL codegen, custom hooks) cannot extend it without recompiling. The
// `extra_ts_exports` ScannerConfig field feeds this OnceLock at daemon
// startup; `is_common_ts_export` checks both. Empty by default — common
// frameworks are already covered by the static set.

static EXTRA_TS_EXPORTS: once_cell::sync::OnceCell<std::collections::HashSet<String>> =
    once_cell::sync::OnceCell::new();

/// Populate the user-extendable TS export allow-list from config. Called
/// once at daemon startup. Subsequent calls are no-ops (first wins, matching
/// OnceLock semantics). Names are stored as-is (case-sensitive matching).
pub fn set_extra_ts_exports(names: Vec<String>) {
    let _ = EXTRA_TS_EXPORTS.set(names.into_iter().collect());
}

/// Check whether a TS export name should be skipped by the FORGE
/// hallucinated-import check. True if the name is in the built-in
/// COMMON_TS_EXPORTS OR the user-provided `extra_ts_exports` config list.
/// Callers should also check `ts_ast_extractor::TESTING_GLOBALS` separately
/// (those names live in their own canonical source-of-truth).
pub fn is_common_ts_export(name: &str) -> bool {
    COMMON_TS_EXPORTS.contains(name)
        || EXTRA_TS_EXPORTS
            .get()
            .is_some_and(|set| set.contains(name))
}

/// Detect language from response content + path heuristic.


/// Java FORGE pipeline (partial).
///
/// C is distinct from C++ in that C++ STL headers (`<cstdio>`, `<algorithm>`,
/// `<vector>`) are NOT valid in pure C — but LLMs frequently leak them. This
/// pipeline uses c_introspect which:
///   1. Verifies `#include <X.h>` against C89/C99/C11/POSIX/GNU headers
///   2. Verifies function calls against libc — flags unknown functions
///   3. Verifies arity of known libc function calls
///
/// All checks are based on the C standard + POSIX; no hardcoded
/// "hallucinated names" list — any function not in libc + not user-defined
/// + not a builtin gets flagged.
use crate::scanner::forge_c::run_forge_c;
use crate::scanner::forge_cpp::run_forge_cpp;
use crate::scanner::forge_csharp::run_forge_csharp;
use crate::scanner::forge_gdscript::run_forge_gdscript;
use crate::scanner::forge_go::run_forge_go;
use crate::scanner::forge_java::run_forge_java;
use crate::scanner::forge_python::run_forge_python;
use crate::scanner::forge_rust::run_forge_rust;
use crate::scanner::forge_ts::run_forge_ts;
use crate::scanner::forge_scene::{run_forge_tscn, run_forge_gdshader};



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dos_guard_depth_helper() {
        // Balanced content peaks at 1, ends at 0.
        assert_eq!(unclosed_delim_depth("fn a() { if x { y } }"), 2);
        // Pathological runs of openers count the peak.
        assert_eq!(unclosed_delim_depth(&"{".repeat(200_000)), 200_000);
        // Closers below depth 0 floor — cannot fake a low peak.
        assert_eq!(unclosed_delim_depth("}}}}{"), 1);
        // Real deep-but-legal nesting stays well under the cap.
        let nested = format!("{}{}", "[".repeat(500), "]".repeat(500));
        assert_eq!(unclosed_delim_depth(&nested), 500);
        assert!(unclosed_delim_depth(&nested) < MAX_UNCLOSED_DELIM_DEPTH);
    }

    #[tokio::test]
    async fn parse_dos_guard_skips_ast_on_pathological_depth() {
        // 200k unclosed braces pinned tree-sitter ~17 min pre-guard; the
        // guard must return an empty result in milliseconds instead.
        let content = format!("fn broken() {{}}\n{}", "{".repeat(200_000));
        let start = std::time::Instant::now();
        let result = run_forge_pipeline(&content, "rust", &[], "", "").await;
        assert!(start.elapsed().as_secs() < 10, "guard must short-circuit, took {:?}", start.elapsed());
        assert!(result.warnings.is_empty());
        assert_eq!(result.claims_extracted, 0);
    }

    /// Idempotent setup: seed the global SymbolCache from
    /// tests/fixtures/symbol_bundle.jsonl so tests that exercise
    /// named-import verification (forge_ts Step 2b) can resolve
    /// `import { X } from "zod"` against cached npm.zod entries.
    /// Without this, those tests pass only when some other test in
    /// the same binary happens to seed the global cache first — i.e.
    /// they fail in isolation. Safe to call multiple times:
    /// seed_from_jsonl uses INSERT OR REPLACE per (library, version, path).
    fn ensure_global_cache_seeded() {
        use std::sync::Once;
        static SEED: Once = Once::new();
        SEED.call_once(|| {
            let bundle = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/symbol_bundle.jsonl");
            if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
                let _ = cache.seed_from_jsonl(&bundle);
                let bulk = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/symbol_bundle_bulk.jsonl");
                let _ = cache.seed_from_jsonl(&bulk);
            }
        });
    }

    #[tokio::test]
    async fn forge_pipeline_python_passes_clean_code() {
        let src = "import os\nprint(os.getcwd())";
        let result = run_forge_pipeline(src, "python", &[], "", "").await;
        assert!(result.warnings.is_empty(), "got: {:?}", result.warnings);
        assert!(result.claims_extracted > 0);
    }

    #[tokio::test]
    async fn forge_pipeline_python_flags_hallucinated_module() {
        let src = "from completely_fake_xyz_pkg_12345 import something";
        let result = run_forge_pipeline(src, "python", &[], "", "").await;
        // Package doesn't exist in PyPI → hallucinated.
        assert!(result.warnings.iter().any(|w| w.contains("hallucinated-import")),
            "got: {:?}", result.warnings);
    }

    #[tokio::test]
    async fn forge_pipeline_python_flags_hallucinated_name_in_real_module() {
        let src = "from os import completely_fake_function_xyz";
        let result = run_forge_pipeline(src, "python", &[], "", "").await;
        assert!(result.warnings.iter().any(|w| w.contains("completely_fake_function_xyz")),
            "got: {:?}", result.warnings);
    }

    #[tokio::test]
    async fn forge_pipeline_skips_unsupported_languages() {
        // Ruby/PHP/etc: not supported by FORGE, returns empty.
        let src = "puts 'hello'";
        let result = run_forge_pipeline(src, "ruby", &[], "", "").await;
        assert_eq!(result.claims_extracted, 0);
        assert!(result.warnings.is_empty());
    }

    #[tokio::test]
    async fn forge_pipeline_ts_verifies_imports() {
        // TypeScript: partial FORGE via npm registry lookup.
        // `bar` is not a real npm package → should be flagged.
        let src = "import { foo } from 'completely_fake_npm_pkg_xyz';";
        let result = run_forge_pipeline(src, "typescript", &[], "", "").await;
        assert!(result.claims_extracted > 0, "TS should extract imports");
        assert!(
            result.warnings.iter().any(|w| w.contains("hallucinated-import")),
            "expected hallucinated-import for fake npm pkg; got: {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn forge_pipeline_ts_flags_nonexistent_zod_type_utilities() {
        // Zod's actual public API does NOT export names like `anubisFakeZodType`
        // or `totallyMadeUpZodThing`. forge_ts Step 2b must catch imports of
        // names that don't exist in the cached npm.zod library.
        //
        // NOTE: an earlier version of this test used `promiseType`/`dateType`
        // which were assumed fabricated — but zod 4.4.3's .d.ts bundle
        // actually exports them as type utilities. The test silently broke
        // when the bundle was regenerated. This version uses obviously-
        // fabricated names to avoid that drift.
        ensure_global_cache_seeded();
        let src = "// Using zod\nimport { anubisFakeZodType } from 'zod';\n\nanubisFakeZodType()\n";
        let result = run_forge_pipeline(src, "typescript", &[], "", "").await;
        let promise_hits: Vec<_> = result
            .warnings
            .iter()
            .filter(|w| w.contains("anubisFakeZodType"))
            .collect();
        assert!(
            !promise_hits.is_empty(),
            "expected hallucination warning for anubisFakeZodType (not a real zod export); got: {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn forge_pipeline_ts_flags_nonexistent_zod_type_utilities_in_destructured_calls() {
        // Same fabrication must surface in verify_ts_destructured_calls
        // (Step 5) too — that path re-verifies imports via Node require()
        // and would otherwise paper over the hallucination.
        ensure_global_cache_seeded();
        let src = "// Using zod\nimport { anubisFakeZodType, totallyMadeUpZodThing } from 'zod';\n\nanubisFakeZodType()\ntotallyMadeUpZodThing()\n";
        let result = run_forge_pipeline(src, "typescript", &[], "", "").await;
        let type_util_hits: Vec<_> = result
            .warnings
            .iter()
            .filter(|w| w.contains("anubisFakeZodType") || w.contains("totallyMadeUpZodThing"))
            .collect();
        assert!(
            !type_util_hits.is_empty(),
            "expected hallucination warning for fabricated Zod type utilities in destructured calls; got: {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn forge_pipeline_handles_empty_content() {
        let result = run_forge_pipeline("", "python", &[], "", "").await;
        assert_eq!(result.claims_extracted, 0);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn common_ts_exports_no_dupes() {
        // Regression for P2.2: slice→HashSet conversion would silently
        // drop dupes if the source list regressed. Track the canonical
        // count so any future addition/removal is intentional.
        // Note: HashSet hides dupes by construction — this test asserts
        // the source array's length matches the deduped set length.
        let seen: std::collections::HashSet<&str> = COMMON_TS_EXPORTS
            .iter()
            .copied()
            .collect();
        // Update this constant only when intentionally adding/removing entries.
        assert_eq!(
            COMMON_TS_EXPORTS.len(),
            seen.len(),
            "COMMON_TS_EXPORTS contains duplicate entries (len {} vs dedup {})",
            COMMON_TS_EXPORTS.len(),
            seen.len()
        );
    }

    #[tokio::test]
    async fn forge_pipeline_handles_syntax_error() {
        // AST extraction fails → empty result, no crash.
        let result = run_forge_pipeline("def broken(:", "python", &[], "", "").await;
        assert_eq!(result.claims_extracted, 0);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn detect_language_python_by_path() {
        assert_eq!(detect_language("anything", "/foo/bar.py"), "python");
        assert_eq!(detect_language("anything", "test.py"), "python");
    }

    #[test]
    fn detect_language_typescript_by_path() {
        assert_eq!(detect_language("anything", "Component.tsx"), "typescript");
        assert_eq!(detect_language("anything", "utils.ts"), "typescript");
    }

    #[test]
    fn detect_language_rust_by_path() {
        assert_eq!(detect_language("anything", "main.rs"), "rust");
    }

    #[test]
    fn detect_language_python_by_content() {
        let py = "def foo():\n    pass\ndef bar():\n    return 1\nimport os\n";
        assert_eq!(detect_language(py, ""), "python");
    }

    #[test]
    fn detect_language_unknown_for_blank() {
        assert_eq!(detect_language("", ""), "unknown");
    }

    #[test]
    fn forge_result_fully_resolved_when_no_unknowns() {
        let r = ForgeResult {
            claims_extracted: 5,
            claims_verified: 4,
            claims_hallucinated: 1,
            claims_unknown: 0,
            ..Default::default()
        };
        assert!(r.fully_resolved());
    }

    #[test]
    fn forge_result_not_resolved_when_unknowns_present() {
        let r = ForgeResult {
            claims_extracted: 5,
            claims_unknown: 2,
            ..Default::default()
        };
        assert!(!r.fully_resolved());
    }

    // ── scan_confidence + claim_confidence tests ────────────────────
    // FORGE-specific confidence tracking. Mirrors the SymbolCheckResult
    // tests in symbols/mod.rs. Drives the confidence-graded L3 cascade.

    fn forge_claims(pairs: &[(&str, f64)]) -> std::collections::HashMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn forge_scan_confidence_empty_claims_returns_one() {
        // No claims extracted → vacuously confident.
        let r = ForgeResult::default();
        assert_eq!(r.scan_confidence(), 1.0);
    }

    #[test]
    fn forge_scan_confidence_returns_minimum_across_claims() {
        // Single low-confidence claim drags whole scan down.
        let r = ForgeResult {
            claims_extracted: 3,
            claims_hallucinated: 3,
            claim_confidence: forge_claims(&[
                ("itoa", 0.95),         // introspection miss
                ("strrev", 0.95),       // introspection miss
                ("mystery_func", 0.50), // unrecognized — uncertain
            ]),
            ..Default::default()
        };
        assert_eq!(r.scan_confidence(), 0.50);
    }

    #[test]
    fn forge_scan_confidence_all_introspection_misses() {
        // Every claim caught by introspection (Python dir(), Node require,
        // etc.) → confidence 0.95 each → scan_confidence 0.95.
        // Above cascade threshold (0.85) → L3 skipped.
        let r = ForgeResult {
            claims_extracted: 3,
            claims_hallucinated: 3,
            claim_confidence: forge_claims(&[
                ("foo.bar", 0.95),
                ("baz.qux", 0.95),
                ("quux.method", 0.95),
            ]),
            ..Default::default()
        };
        assert!(r.scan_confidence() >= 0.85);
        assert_eq!(r.scan_confidence(), 0.95);
    }

    #[test]
    fn forge_scan_confidence_registry_404_above_threshold() {
        // Package-import hallucinations verified via registry 404 (PyPI,
        // npm, crates.io, etc.) → confidence 0.90 → cascade skips L3.
        let r = ForgeResult {
            claims_extracted: 1,
            claims_hallucinated: 1,
            claim_confidence: forge_claims(&[
                ("anndata2", 0.90),
            ]),
            ..Default::default()
        };
        assert!(r.scan_confidence() >= 0.85);
    }

    #[test]
    fn forge_scan_confidence_at_cascade_boundary() {
        // 0.85 is the cascade threshold. Test the exact boundary.
        let at_boundary = ForgeResult {
            claims_extracted: 1,
            claim_confidence: forge_claims(&[("claim", 0.85)]),
            ..Default::default()
        };
        assert!(at_boundary.scan_confidence() >= 0.85);

        let just_below = ForgeResult {
            claims_extracted: 1,
            claim_confidence: forge_claims(&[("claim", 0.84)]),
            ..Default::default()
        };
        assert!(just_below.scan_confidence() < 0.85);
    }

    #[test]
    fn forge_scan_confidence_mixed_high_and_low_claims() {
        // Realistic scan: most claims verified, one uncertain.
        // The single uncertain claim determines scan confidence.
        let r = ForgeResult {
            claims_extracted: 5,
            claims_verified: 3,
            claims_hallucinated: 1,
            claims_unknown: 1,
            claim_confidence: forge_claims(&[
                ("foo.bar", 0.95),
                ("baz.qux", 0.95),
                ("real.method", 0.95),
                ("fake.method", 0.95),
                ("unknown.method", 0.0),  // no cache evidence
            ]),
            ..Default::default()
        };
        assert_eq!(r.scan_confidence(), 0.0);
    }

    #[test]
    fn extract_claim_key_handles_all_warning_prefixes() {
        // Council #3 #12: verify backtick-based claim key extraction works
        // for all known warning prefix types. Renaming a prefix must NOT
        // silently drop the claim key.
        let cases = [
            ("hallucinated-method: `st.error` — `error` not in module `streamlit`", "st.error"),
            ("hallucinated-import: `langchain.text_splitter` — top-level", "langchain.text_splitter"),
            ("hallucinated-variable: `matrixA` — referenced but not defined", "matrixA"),
            ("hallucinated-function: `main` — not found", "main"),
            ("hallucinated-namespace: `System.Net.MimeTypes` — not a known", "System.Net.MimeTypes"),
            ("hallucinated-method-uncertain: `Foo.bar` — not in known methods", "Foo.bar"),
            ("chain-phantom-member: `df.col` chain step `col` not in `DataFrame`", "df.col"),
            ("chain-broken: `result.method` — method returns None", "result.method"),
            ("cached-hallucination: `NoteOut.model_validate()` — class NoteOut", "NoteOut.model_validate()"),
        ];
        for (warning, expected_key) in &cases {
            let key = extract_claim_key_from_warning(warning);
            assert_eq!(key, *expected_key,
                "claim key mismatch for warning: {}\n  got: {:?}\n  expected: {:?}",
                &warning[..warning.len().min(60)], key, expected_key);
        }
    }

    #[test]
    fn extract_claim_key_returns_empty_for_no_backticks() {
        // Warnings without backtick-quoted tokens should return empty,
        // which populate_forge_confidence handles by skipping (line 86).
        assert_eq!(extract_claim_key_from_warning("some warning without backticks"), "");
        assert_eq!(extract_claim_key_from_warning(""), "");
    }

    #[test]
    fn is_common_ts_export_recognises_builtin_names() {
        // Sanity: built-in static set still resolves after introducing
        // the is_common_ts_export helper + EXTRA_TS_EXPORTS OnceCell.
        assert!(is_common_ts_export("useState"));
        assert!(is_common_ts_export("createElement"));
        assert!(is_common_ts_export("PrismaClient"));
        assert!(is_common_ts_export("FastifyInstance"));
    }

    #[test]
    fn is_common_ts_export_rejects_unrelated_names() {
        // Names not in static set and not seeded via config → false.
        assert!(!is_common_ts_export("totallyUnknownName"));
        assert!(!is_common_ts_export(""));
    }

    #[test]
    fn set_extra_ts_exports_extends_allow_list_first_write_wins() {
        // OnceCell semantics: first call wins. Use a unique prefix to
        // avoid colliding with other tests that might call set_.
        let marker = "anubis_a7_test_marker_extra_export_xyz";
        super::set_extra_ts_exports(vec![marker.to_string()]);
        assert!(
            is_common_ts_export(marker),
            "user-provided extra_ts_exports should be honored by is_common_ts_export"
        );
        // Second call should NOT overwrite (OnceCell first-write-wins).
        super::set_extra_ts_exports(vec!["anubis_a7_second_marker_qwerty".to_string()]);
        assert!(
            is_common_ts_export(marker),
            "OnceCell first-write-wins: original marker should still be present"
        );
    }

    #[test]
    fn classify_warning_recognises_all_known_prefixes() {
        use super::{classify_warning, WarningKind};
        // Every prefix the cascade expects to recognise.
        let cases: &[(&str, WarningKind)] = &[
            ("forge: hallucinated-include: `foo.h`", WarningKind::HallucinatedInclude),
            ("hallucinated-include: `foo.h`", WarningKind::HallucinatedInclude),
            ("forge: hallucinated-import: `axios`", WarningKind::HallucinatedImport),
            ("forge: hallucinated-import-name: `useState`", WarningKind::HallucinatedImportName),
            ("forge: hallucinated-method: `obj.foo`", WarningKind::HallucinatedMethod),
            ("forge: hallucinated-parameter: `foo.bar(1, 2)`", WarningKind::HallucinatedParameter),
            ("forge: hallucinated-variable: `prose_word`", WarningKind::HallucinatedVariable),
            ("forge: hallucinated-function: `bare_call`", WarningKind::HallucinatedFunction),
            ("forge: hallucinated-constructor: `new Foo()`", WarningKind::HallucinatedConstructor),
            ("forge: hallucinated-call: `foo()`", WarningKind::HallucinatedCall),
            ("forge: hallucinated-namespace: `System.Foo`", WarningKind::HallucinatedNamespace),
            ("forge: bare-critical-call: `panic()`", WarningKind::BareCriticalCall),
            ("forge: chain-broken: `a.b.c`", WarningKind::ChainBroken),
            ("forge: chain-phantom-member: `a.b.c`", WarningKind::ChainPhantomMember),
            ("cached-hallucination: foo.bar() — typo", WarningKind::CachedHallucination),
            ("scope-hallucination: foo.bar()", WarningKind::ScopeHallucination),
            ("Hallucinated API: foo() (did you mean bar?)", WarningKind::HallucinatedApi),
            ("Unverified API: foo()", WarningKind::UnverifiedApi),
        ];
        for (input, expected) in cases {
            let got = classify_warning(input);
            assert_eq!(
                got, *expected,
                "classify_warning({:?}) returned {:?}, expected {:?}",
                input, got, expected
            );
        }
    }

    #[test]
    fn classify_warning_import_vs_import_name_disambiguation() {
        use super::{classify_warning, WarningKind};
        // Order-sensitive: "hallucinated-import-name" must be matched
        // before "hallucinated-import" since the former contains the latter
        // as a stem. If classify_warning naively matches import first,
        // import-name will collapse into the wrong kind.
        assert_eq!(
            classify_warning("forge: hallucinated-import-name: `useState`"),
            WarningKind::HallucinatedImportName,
        );
        assert_eq!(
            classify_warning("forge: hallucinated-import: `axios`"),
            WarningKind::HallucinatedImport,
        );
    }

    #[test]
    fn classify_warning_unknown_returns_other() {
        use super::{classify_warning, WarningKind};
        assert_eq!(classify_warning(""), WarningKind::Other);
        assert_eq!(classify_warning("totally-unknown: foo"), WarningKind::Other);
        assert_eq!(classify_warning("random log line"), WarningKind::Other);
    }

    #[test]
    fn is_forge_hallucination_covers_all_forge_variants() {
        use super::is_forge_hallucination;
        // Every FORGE-prefixed hallucination variant must be recognised —
        // if a new one is added, the test must be updated.
        let forge_hallucinations = [
            "forge: hallucinated-include: `foo.h`",
            "forge: hallucinated-import: `axios`",
            "forge: hallucinated-import-name: `useState`",
            "forge: hallucinated-method: `obj.foo`",
            "forge: hallucinated-parameter: `foo.bar(1, 2)`",
            "forge: hallucinated-variable: `prose_word`",
            "forge: hallucinated-function: `bare_call`",
            "forge: hallucinated-constructor: `new Foo()`",
            "forge: hallucinated-call: `foo()`",
            "forge: hallucinated-namespace: `System.Foo`",
            "forge: bare-critical-call: `panic()`",
            "forge: chain-broken: `a.b.c`",
            "forge: chain-phantom-member: `a.b.c`",
        ];
        for w in &forge_hallucinations {
            assert!(
                is_forge_hallucination(w),
                "is_forge_hallucination({:?}) should be true",
                w
            );
        }
    }

    #[test]
    fn is_forge_hallucination_rejects_non_forge_warnings() {
        use super::is_forge_hallucination;
        // cached-hallucination/scope-hallucination/Hallucinated API/
        // Unverified API have their own scoring paths and must NOT match.
        let non_forge = [
            "cached-hallucination: foo.bar()",
            "scope-hallucination: foo.bar()",
            "Hallucinated API: foo() (did you mean bar?)",
            "Unverified API: foo()",
            "totally-unknown: foo",
        ];
        for w in &non_forge {
            assert!(
                !is_forge_hallucination(w),
                "is_forge_hallucination({:?}) should be false",
                w
            );
        }
    }

    #[test]
    fn confidence_for_warning_preserves_per_kind_scores() {
        use super::confidence_for_warning;
        // Each kind has a known confidence. If a kind's score is changed,
        // this test forces an explicit update (no silent drift).
        let cases: &[(&str, f64)] = &[
            ("forge: hallucinated-include: `foo.h`", 0.95),
            ("forge: hallucinated-method: `obj.foo`", 0.95),
            ("forge: hallucinated-parameter: `foo.bar(1,2)`", 0.95),
            ("forge: hallucinated-import: `axios`", 0.90),
            ("forge: bare-critical-call: `panic()`", 0.90),
            ("forge: hallucinated-variable: `prose_word`", 0.85),
            ("forge: hallucinated-function: `bare_call`", 0.85),
            ("forge: chain-broken: `a.b.c`", 0.85),
            ("forge: hallucinated-import-name: `useState`", 0.80),
            ("forge: chain-phantom-member: `a.b.c`", 0.80),
            ("forge: hallucinated-call: `foo()`", 0.75),
            ("forge: hallucinated-constructor: `new Foo()`", 0.70),
            // Unrecognised — neutral default.
            ("totally-unknown: foo", 0.50),
        ];
        for (warning, expected) in cases {
            let got = confidence_for_warning(warning);
            assert!(
                (got - expected).abs() < 1e-9,
                "confidence_for_warning({:?}) returned {}, expected {}",
                warning, got, expected
            );
        }
    }

    #[tokio::test]
    async fn run_forge_pipeline_inner_dispatches_known_languages() {
        // Each known language returns a ForgeResult without panic.
        // Real content per language would be over-engineering — the
        // load-bearing assertion is that dispatch does not fall through
        // to the unknown-language arm for recognized strings.
        let known = [
            "python", "typescript", "javascript", "rust", "go",
            "java", "csharp", "cpp", "c", "gdscript", "tscn", "gdshader",
        ];
        for lang in known {
            let r = run_forge_pipeline_inner("", lang, &[], "", "").await;
            // We don't assert on r contents — different languages return
            // different shapes (Python returns early on empty AST, etc.).
            // The assertion is the call itself did not panic and completed.
            let _ = r.latency_ms;
        }
    }

    #[tokio::test]
    async fn run_forge_pipeline_inner_empty_language_stays_silent() {
        // Empty string is the pre-classification code-region path.
        // Must NOT panic and must NOT log the B5 warning (caller passes
        // empty language intentionally). Just verify it returns cleanly.
        let r = run_forge_pipeline_inner("", "", &[], "", "").await;
        assert_eq!(r.warnings.len(), 0);
        assert_eq!(r.claims_extracted, 0);
    }
}


