//! Godot scene + shader FORGE runners — extracted from forge_pipeline.rs (M1 chunk 11b).

use crate::scanner::forge_types::ForgeResult;

/// Run FORGE checks on a Godot scene file (`.tscn`).
pub(crate) async fn run_forge_tscn(content: &str) -> ForgeResult {
    let mut result = ForgeResult::default();
    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("tscn: cache open failed: {e}");
            return result;
        }
    };
    let r = crate::scanner::tscn_introspect::verify_tscn(content, &cache);
    result.warnings = r.warnings;
    result.claims_extracted = r.claims_extracted;
    result.claims_hallucinated = r.claims_hallucinated;
    result.claims_verified = r.claims_extracted.saturating_sub(r.claims_hallucinated);
    result
}

/// Run FORGE checks on a Godot shader file (`.gdshader`).
///
/// Delegates to [`gdshader_introspect::verify_gdshader`] which uses closed
/// keyword lists (no cache needed — the shader grammar is a small, stable set).
pub(crate) async fn run_forge_gdshader(content: &str) -> ForgeResult {
    let mut result = ForgeResult::default();
    let r = crate::scanner::gdshader_introspect::verify_gdshader(content);
    result.warnings = r.warnings;
    result.claims_extracted = r.claims_extracted;
    result.claims_hallucinated = r.claims_hallucinated;
    result.claims_verified = r.claims_extracted.saturating_sub(r.claims_hallucinated);
    result
}
