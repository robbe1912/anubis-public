//! Unified fallback chain placeholder (COLD-001 stub, COLD-005 implementation).
//!
//! Per master plan COLD-005 [deps: 004]: "unified fallback chain replaces
//! mod.rs:2882-2946 sequential calls. 80 LOC." The current sequential
//! calls in `scan_response` are:
//!
//! 1. `lsp_gate::suppress_fps` (LSP FP gate, rust-analyzer/gopls)
//! 2. `compiler_cache::global().lookup_or_compute(...)` (compiler FP gate, all langs)
//!
//! COLD-005 will replace this with a single `fallback_chain(warnings, ctx)`
//! call that internally dispatches to LSP first (project-aware), then
//! compiler gate (single-file fallback). This stub captures the interface
//! + future plan; the actual implementation lands in COLD-005.

use std::collections::HashSet;

/// Result of running the fallback chain. COLD-005 will populate this;
/// for now it's a placeholder so callers can write against the future API.
#[derive(Debug, Default, Clone)]
pub struct FallbackResult {
    /// Symbols confirmed as genuine hallucinations (kept in warnings).
    pub genuine: HashSet<String>,
    /// Source chain that confirmed each symbol (LSP, compiler, etc.)
    /// — for tracing + dashboard.
    pub source_tags: Vec<&'static str>,
}

/// Run the unified fallback chain. COLD-005 implements this; stub
/// returns `None` so callers fall through to the existing sequential
/// dispatch in `scan_response`.
///
/// When implemented: returns `Some(FallbackResult)` if the chain ran to
/// completion, `None` if it short-circuited (e.g. all warnings filtered
/// by an earlier layer).
pub fn run_fallback_chain(
    _warnings: &[String],
    _code: &str,
    _language: &str,
    _project_root: &std::path::Path,
) -> Option<FallbackResult> {
    // COLD-005 will implement. Return None so existing dispatch in
    // scan_response keeps running unchanged.
    None
}
