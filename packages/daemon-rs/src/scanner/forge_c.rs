//! C language FORGE runner — extracted from forge_pipeline.rs (M1 chunk 5b).
//!
//! Verifies C source for:
//!   1. Header includes (#include) — against a curated list of known headers
//!   2. Function calls — unknown names + arity
//!   3. Undefined variables — catches typos like `widht` for `width`
//!
//! All verification delegates to `c_introspect` module. No internal
//! forge_pipeline.rs dependencies — fully self-contained.

use crate::scanner::forge_types::ForgeResult;

/// Run FORGE pipeline on C source content.
pub(crate) async fn run_forge_c(content: &str) -> ForgeResult {
    let start = std::time::Instant::now();
    let mut result = ForgeResult::default();

    // Step 1: header verification.
    let include_warnings = crate::scanner::c_introspect::verify_c_includes(content);
    if !include_warnings.is_empty() {
        result.claims_extracted += include_warnings.len();
        result.claims_hallucinated += include_warnings
            .iter()
            .filter(|w| w.contains("hallucinated"))
            .count();
        result.warnings.extend(include_warnings);
    }

    // Step 2: function call verification (unknown names + arity).
    let func_warnings = crate::scanner::c_introspect::verify_c_function_calls(content);
    if !func_warnings.is_empty() {
        result.claims_extracted += func_warnings.len();
        result.claims_hallucinated += func_warnings
            .iter()
            .filter(|w| w.contains("hallucinated"))
            .count();
        result.warnings.extend(func_warnings);
    }

    // Step 3: undefined variable check (catches typos like `widht` for `width`).
    let undefined = crate::scanner::c_introspect::verify_c_undefined_variables(content);
    for name in &undefined {
        if name.len() >= 3 {
            // Consult SymbolCache: if this name exists as a symbol in ANY
            // cached library (populated by metadata fetchers), it's a real
            // symbol — don't flag as hallucinated. Mirrors forge_csharp.rs.
            if let Ok(cache) = crate::symbols::cache::SymbolCache::open() {
                if !cache.lookup_global(name).is_empty() {
                    continue;
                }
            }
            result.warnings.push(format!(
                "hallucinated-variable: `{}` — referenced but not defined in scope", name
            ));
            result.claims_hallucinated += 1;
        }
    }
    result.claims_extracted += undefined.len();

    result.latency_ms = start.elapsed().as_millis() as u64;
    result
}
