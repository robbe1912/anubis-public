//! ForgeResult type — extracted from forge_pipeline.rs (M1 chunk 5a).
//!
//! Shared output type for all per-language FORGE runners. Currently defined
//! in forge_pipeline.rs but extracted here so future per-language runner
//! modules (forge/c.rs, forge/rust.rs, etc.) can reference it without a
//! circular dependency on forge_pipeline.rs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// FORGE pipeline output. Counts support cascade decisions + observability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForgeResult {
    /// User-visible hallucination warnings, formatted for `result.warnings`.
    pub warnings: Vec<String>,
    /// Total claims extracted by AST.
    pub claims_extracted: usize,
    /// Claims definitively verified as real.
    pub claims_verified: usize,
    /// Claims definitively identified as hallucinated.
    pub claims_hallucinated: usize,
    /// Claims FORGE couldn't verify (deferred to L3).
    pub claims_unknown: usize,
    /// Modules successfully introspected (for observability).
    pub modules_introspected: usize,
    /// Total wall-clock time spent in FORGE (ms).
    pub latency_ms: u64,
    /// Per-claim confidence scores in [0.0, 1.0]. Used by the confidence-
    /// graded cascade to decide which claims warrant L3 escalation.
    pub claim_confidence: HashMap<String, f64>,
}

impl ForgeResult {
    /// True if FORGE resolved every claim (no unknowns for L3 to handle).
    pub fn fully_resolved(&self) -> bool {
        self.claims_unknown == 0 && self.claims_extracted > 0
    }

    /// Scan-level confidence: minimum per-claim confidence across all claims
    /// FORGE processed. Returns 1.0 when FORGE didn't process any claims.
    pub fn scan_confidence(&self) -> f64 {
        if self.claim_confidence.is_empty() {
            return 1.0;
        }
        self.claim_confidence.values().copied().fold(1.0_f64, f64::min)
    }
}
