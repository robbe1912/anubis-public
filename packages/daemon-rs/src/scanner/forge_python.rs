//! Python FORGE runner — extracted from forge_pipeline.rs (M1 chunk 10).
//!
//! Implements the full FORGE pipeline for Python source:
//!   1.  AST extraction via pyo3 (`ast_extractor::extract_python_apis`)
//!   1b. Undefined variable detection (`ast_extractor::extract_undefined_variables`)
//!   2.  Local introspection (`local_introspect::verify_against_introspection`)
//!   2b. Parameter checking via `inspect.signature`
//!   3.  Package index verification for imports that failed introspection
//!       (two-tier submodule detection → PyPI registry lookup)
//!
//! `project_index` and `project_root` are accepted for signature parity with
//! other per-language runners; Python FORGE doesn't currently use them.

use crate::scanner::ast_extractor::{extract_python_apis, ApiKind};
use crate::scanner::forge_types::ForgeResult;
use crate::scanner::local_introspect::{introspect_python_module, verify_against_introspection};
use crate::scanner::package_index::{verify_import_with_language, ImportStatus};

pub(crate) async fn run_forge_python(
    content: &str,
    scope_vars: &[(String, String)],
    _project_index: &str,
    project_root: &str,
) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();

    // F2: Java-shape guard. Java import lines (`import a.b.C;`) are valid
    // Python syntax (dotted module + trailing `;` as empty statement), so a
    // Java block misrouted here (first-fence-wins detection, multi-language
    // responses) parses cleanly into ApiKind::Import claims and dies at the
    // PyPI 404 → "package not found in PyPI" FP. Detect the shape and bail
    // before any Python machinery runs. Mirrors the F1 signal in
    // language_detection.rs — that one fixes the route, this one contains
    // the blast radius if a misroute still happens.
    {
        static JAVA_SHAPE_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let java_shaped = JAVA_SHAPE_RE
            .get_or_init(|| {
                regex::Regex::new(r"(?m)^\s*import\s+(?:static\s+)?[a-z_]\w*\.[\w.]+\s*;").unwrap()
            })
            .is_match(content);
        if java_shaped {
            tracing::debug!(
                target: "scanner",
                "FORGE python: Java-shaped content (dotted semicolon imports) — skipping Python pipeline"
            );
            result.latency_ms = start.elapsed().as_millis() as u64;
            return result;
        }
    }

    // Step 1: AST extraction.
    let calls = match extract_python_apis(content).await {
        Ok(calls) => calls,
        Err(e) => {
            tracing::debug!(
                target: "scanner",
                error = %e,
                "FORGE: AST extraction failed, deferring to regex path"
            );
            return result;
        }
    };
    result.claims_extracted = calls.len();

    // Session-defined python symbols (F8 store, same-language only): used by
    // both undefined-variable suppression (step 1b) and ctor chain-broken
    // suppression (step 2a, R1/R2).
    let session_defined: std::collections::HashSet<String> =
        crate::scanner::project_index::get_session_symbols(
            project_root,
            "python",
        )
        .lines()
        .filter_map(|l| l.strip_prefix("session: "))
        .map(|s| s.to_string())
        .collect();

    // Step 1b: Undefined variable detection (Gap 2).
    // Catches DELULU samples like `matrixA` used but never defined (should be `A`).
    // Uses same Python subprocess, runs ast scope checker.
    if let Ok(undefined) =
        crate::scanner::ast_extractor::extract_undefined_variables(content).await
    {
        // Same-content + cross-response suppression: a name defined anywhere in
        // this response (regex local-var extraction incl. Python bare
        // assignments) or seen as a session symbol in this project (F8 store,
        // same-language only) is not hallucinated. The pyo3 scope checker only
        // sees the current fragment; agent responses routinely reference names
        // defined in earlier responses of the same session (module-level
        // `_SessionLocal`, decorator-injected `query` params).
        let local_vars = crate::scanner::extract_local_variables(content);
        // Common Django/DRF symbols that are imported at the top of real project files
        // but may not be in the code block being analyzed. LLMs often assume these
        // standard imports are present (like `from rest_framework import viewsets`).
        const DJANGO_DRF_SKIP: &[&str] = &[
            "viewsets",
            "get_object_or_404",
            "ValidationError",
            "render",
            "redirect",
            "reverse",
            "HttpResponse",
            "JsonResponse",
            "QueryDict",
            "Http404",
        ];

        for name in &undefined {
            // Skip names defined in this response or earlier in the session
            if local_vars.contains(name) || session_defined.contains(name) {
                continue;
            }

            // Skip Django/DRF framework symbols that are standard imports
            if DJANGO_DRF_SKIP.contains(&name.as_str()) {
                continue;
            }

            // Skip names that look like library module aliases (single char
            // like 'A' vs 'matrixA' would be caught by prompt+suffix context).
            // Only flag if name length ≥ 3 to avoid false positives on short vars.
            if name.len() >= 3 {
                result.warnings.push(format!(
                    "hallucinated-variable: `{}` — referenced but not defined in scope",
                    name
                ));
            }
        }
        result.claims_extracted += undefined.len();
    }

    if calls.is_empty() && result.warnings.is_empty() {
        result.latency_ms = start.elapsed().as_millis() as u64;
        return result;
    }

    // Step 2: Local introspection (verifies imports + typed methods).
    let introspect_warnings = verify_against_introspection(&calls, scope_vars).await;

    // Step 2a: Detect chain-broken patterns for Method calls whose receiver
    // type couldn't be inferred. Closes the gap that let
    // `resp = requests.get(...); resp.parse_json()` slip through — analyze_scope's
    // regex only matches `var = ClassName(` (uppercase type), missing the much
    // more common `var = module.function(` pattern. Without this signal,
    // verify_against_introspection silently skips the call and the L2.5
    // cascade skips L3, shipping the hallucination.
    // The `chain-broken` prefix triggers `has_introspection_warning` in mod.rs,
    // forcing L3 escalation.
    let assignments =
        match crate::scanner::ast_extractor::extract_python_assignments(content).await {
            Ok(m) => {
                tracing::info!(
                    target: "scanner",
                    content_len = content.len(),
                    assignment_count = m.len(),
                    sample_keys = ?m.keys().take(5).collect::<Vec<_>>(),
                    "FORGE: extract_python_assignments OK"
                );
                m
            }
            Err(e) => {
                tracing::warn!(
                    target: "scanner",
                    error = %e,
                    content_len = content.len(),
                    content_preview = %content.chars().take(120).collect::<String>(),
                    "FORGE: assignment extraction FAILED — falling back to empty map"
                );
                std::collections::HashMap::new()
            }
        };
    let unresolved_warnings =
        crate::scanner::local_introspect::detect_unresolved_receivers(
            &calls,
            scope_vars,
            &assignments,
            content,
            &session_defined,
        );
    let unresolved_count = unresolved_warnings.len();
    if unresolved_count > 0 {
        tracing::info!(
            target: "scanner",
            unresolved_count,
            sample_warnings = ?unresolved_warnings.iter().take(3).collect::<Vec<_>>(),
            "FORGE: chain-broken emitted — will force L3 escalation"
        );
    }
    result.warnings.extend(unresolved_warnings);

    // Step 2b: Parameter checking via inspect.signature (Gap 3).
    // Catches hallucinated kwargs like column(..., nullable=False) where
    // nullable isn't a valid parameter of the function.
    let param_warnings = crate::scanner::local_introspect::check_python_parameters(content).await;

    // Count modules introspected for observability.
    let import_count = calls
        .iter()
        .filter(|c| c.kind == ApiKind::Import)
        .count();
    result.modules_introspected = import_count; // upper bound; some may have errored

    // Step 3: Package index verification for imports that failed introspection.
    // Two-tier submodule detection:
    //   (a) Full dotted path failed (e.g., langchain_core.schema)
    //   (b) Check top-level path (e.g., langchain_core)
    //   If (a) failed but (b) succeeded -> hallucinated SUBMODULE (deterministic).
    //   If both failed -> package doesn't exist at all, defer to package_index.
    let mut package_warnings: Vec<String> = Vec::new();
    let mut package_unknown_count = 0;
    for call in &calls {
        if call.kind != ApiKind::Import {
            continue;
        }
        let info = introspect_python_module(&call.name).await;
        if info.error.is_some() {
            // Module failed to import. Try top-level only.
            let top_level = call.name.split('.').next().unwrap_or(&call.name);
            let top_info = if top_level == call.name {
                // No dots — same as full path, already failed.
                None
            } else {
                Some(introspect_python_module(top_level).await)
            };

            match top_info {
                Some(top) if top.error.is_none() => {
                    // Top-level imports OK but submodule failed.
                    // This is a hallucinated SUBMODULE path — deterministic.
                    let submodule = &call.name[top_level.len() + 1..];
                    package_warnings.push(format!(
                        "hallucinated-import: `{}` — top-level `{}` exists but submodule `{}` does not",
                        call.name, top_level, submodule
                    ));
                    result.claims_hallucinated += 1;
                }
                _ => {
                    // Top-level also failed (or no top-level different from full).
                    // Defer to PyPI registry check for top-level existence.
                    let status = verify_import_with_language("python", top_level).await;
                    match status {
                        ImportStatus::NotFound => {
                            // Definitively hallucinated package.
                            package_warnings.push(format!(
                                "hallucinated-import: `{}` — package not found in PyPI registry",
                                call.name
                            ));
                            result.claims_hallucinated += 1;
                        }
                        ImportStatus::Verified => {
                            // Package exists in PyPI but not installed locally. Can't
                            // verify imported names. Defer to L3.
                            package_unknown_count += 1;
                            tracing::debug!(
                                target: "scanner",
                                module = %call.name,
                                "FORGE: package exists in PyPI but not installed locally; deferring to L3"
                            );
                        }
                        ImportStatus::NetworkError | ImportStatus::Skipped => {
                            package_unknown_count += 1;
                        }
                    }
                }
            }
        } else {
            // Module imported successfully. verify_against_introspection
            // already handled the imported_names check.
            result.claims_verified += 1;
        }
    }

    // Merge warnings: introspection first (more specific), then parameters,
    // then package_index.
    let introspection_warning_count = introspect_warnings.len();
    let param_warning_count = param_warnings.len();
    result.warnings.extend(introspect_warnings);
    result.warnings.extend(param_warnings);
    result.warnings.extend(package_warnings);

    // Tally counts.
    result.claims_hallucinated += introspection_warning_count;
    result.claims_hallucinated += unresolved_count;
    result.claims_hallucinated += param_warning_count;
    result.claims_verified += result
        .claims_extracted
        .saturating_sub(result.claims_hallucinated)
        .saturating_sub(package_unknown_count);
    result.claims_unknown = package_unknown_count;

    result.latency_ms = start.elapsed().as_millis() as u64;
    result
}

#[cfg(test)]
mod session_fp_tests {
    use super::*;

    #[tokio::test]
    async fn same_response_assignment_suppresses_undefined_variable() {
        // Repro of task-002 `_SessionLocal` FP: module-level assignment AND
        // usage in the SAME response. The pyo3 fragment scope checker may not
        // link them; the local-vars union must suppress the warning.
        let content = "\
import sqlalchemy

_engine = sqlalchemy.create_engine(\"sqlite:///notes.db\")
_SessionLocal = sqlalchemy.orm.sessionmaker(bind=_engine)

def get_session():
    return _SessionLocal()
";
        let result = run_forge_python(content, &[], "", "").await;
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("_SessionLocal")),
            "same-response assignment must suppress _SessionLocal FP, got: {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn session_symbol_suppresses_undefined_variable() {
        // F8 mechanism: a name defined in an EARLIER response of the same
        // session (session-symbol store, function/class names) must not flag
        // as hallucinated in a later fragment that references it.
        let root = "fp-test-session-suppression";
        crate::scanner::project_index::accumulate_session_symbols(
            root,
            "def compute_totals(notes):\n    return sum(notes)\n",
            "python",
        );
        let content = "\
def run():
    return compute_totals([])
";
        let result = run_forge_python(content, &[], "", root).await;
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| w.contains("compute_totals")),
            "session-defined compute_totals must be suppressed, got: {:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn truly_undefined_variable_still_flagged() {
        let content = "\
def run():
    return matrixA
";
        let result = run_forge_python(content, &[], "", "").await;
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("matrixA") && w.contains("hallucinated-variable")),
            "genuinely undefined matrixA must still be flagged, got: {:?}",
            result.warnings
        );
    }
}
