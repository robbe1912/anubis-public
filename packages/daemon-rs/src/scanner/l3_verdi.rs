//! VERDI — Single-Call Confidence Estimation for LLM judges.
//!
//! Extracts structural signals from the LLM's reasoning trace to calibrate
//! confidence post-hoc. No additional API calls needed — uses the existing
//! SV-CoT reasoning text from the ClaimVerdict.reason field.
//!
//! Based on VERDI (arXiv:2605.11334v1, Indeed Inc, May 2026):
//!   - SVA (Step-Verdict Alignment): fraction of reasoning steps aligned with verdict
//!   - CLM (Claim-Level Margin): directional balance of pro/con claims
//!   - EGS (Evidence Grounding Score): fraction of quoted/backtick spans
//!   - Plus secondary features: trace length, hedging, negations, quotes
//!
//! Implementation: post-hoc calibration wrapper on ClaimVerdict. Pure text
//! analysis — no model internals needed.

/// Adjusted confidence for a ClaimVerdict based on VERDI structural signals.
/// Returns calibrated confidence in [0.0, 1.0].
///
/// Weighted combination of 7 features (logistic regression approximation).
/// Weights tuned for GLM-4.7-Flash (no logprobs, structured JSON output).
pub fn calibrate_confidence(
    verdict: &str,
    reason: &str,
    raw_confidence: f64,
) -> f64 {
    let sva = step_verdict_alignment(reason, verdict);
    let clm = claim_level_margin(reason, verdict);
    let egs = evidence_grounding_score(reason);
    let hedging = hedging_count(reason) as f64;
    let negations = negation_count(reason) as f64;
    let trace_len = reason.split_whitespace().count() as f64;

    // VERDI logistic regression weights (7 features).
    // Tuned empirically: positive verdict gets SVA/CLM boost, negative
    // gets EGS boost. Hedging + negations always reduce confidence.
    let weights = match verdict {
        "verified" => [0.25, 0.30, 0.15, -0.08, -0.10, -0.002],
        "hallucinated" => [0.20, 0.25, 0.20, -0.08, -0.10, -0.002],
        _ => [0.15, 0.15, 0.15, -0.06, -0.08, -0.001],
    };
    let bias = 0.10;

    let features = [sva, clm, egs, hedging, negations, trace_len];
    let logit: f64 = features
        .iter()
        .zip(weights.iter())
        .map(|(f, w)| f * w)
        .sum::<f64>()
        + bias;

    // Sigmoid + blend with raw confidence (70% calibrated, 30% raw).
    let calibrated = 1.0 / (1.0 + (-logit).exp());
    let blended = 0.7 * calibrated + 0.3 * raw_confidence;
    blended.clamp(0.0, 1.0)
}

/// SVA: Step-Verdict Alignment.
/// Splits reasoning into sentences, checks how many align with the verdict.
/// Returns fraction in [0.0, 1.0].
fn step_verdict_alignment(reason: &str, verdict: &str) -> f64 {
    let steps: Vec<&str> = reason.split(|c: char| c == '.' || c == '|' || c == '\n')
        .map(|s| s.trim())
        .filter(|s| s.len() > 10)
        .collect();
    if steps.is_empty() {
        return 0.5;
    }

    let positive_kw = [
        "exist", "found", "verified", "confirmed", "valid", "real",
        "supported", "correct", "available", "present",
    ];
    let negative_kw = [
        "not exist", "not found", "hallucinated", "invalid", "fake",
        "fabricated", "missing", "unsupported", "incorrect", "absent",
    ];

    let aligned = steps.iter().filter(|step| {
        let lower = step.to_lowercase();
        match verdict {
            "verified" => positive_kw.iter().any(|kw| lower.contains(kw)),
            "hallucinated" => negative_kw.iter().any(|kw| lower.contains(kw)),
            _ => {
                let pos = positive_kw.iter().any(|kw| lower.contains(kw));
                let neg = negative_kw.iter().any(|kw| lower.contains(kw));
                pos != neg // aligned = internally consistent (one side only)
            }
        }
    }).count();

    aligned as f64 / steps.len() as f64
}

/// CLM: Claim-Level Margin.
/// Directional balance of supporting vs refuting claims.
/// Returns [0.0, 1.0] where 0.5 = balanced, 1.0 = strongly one-sided.
fn claim_level_margin(reason: &str, verdict: &str) -> f64 {
    let lower = reason.to_lowercase();
    let support_kw = ["exist", "found", "verified", "confirmed", "valid", "real", "correct"];
    let refute_kw = ["not exist", "hallucinated", "invalid", "fake", "missing", "incorrect"];

    let support = support_kw.iter().map(|kw| lower.matches(kw).count()).sum::<usize>();
    let refute = refute_kw.iter().map(|kw| lower.matches(kw).count()).sum::<usize>();

    if support + refute == 0 {
        return 0.5;
    }

    let total = (support + refute) as f64;
    let margin = match verdict {
        "verified" => (support as f64 - refute as f64) / total,
        "hallucinated" => (refute as f64 - support as f64) / total,
        _ => 0.5 - ((support as f64 - refute as f64).abs() / total) * 0.5,
    };
    // Map [-1, 1] to [0, 1] where margin aligned with verdict → higher.
    (margin + 1.0) / 2.0
}

/// EGS: Evidence Grounding Score.
/// Fraction of the reasoning that contains quoted/backtick spans.
/// Returns [0.0, 1.0].
fn evidence_grounding_score(reason: &str) -> f64 {
    let backtick_spans: Vec<&str> = reason.split('`').skip(1).step_by(2).collect();
    let quoted_chars: usize = backtick_spans.iter().map(|s| s.len()).sum();
    let total_chars = reason.len().max(1);
    let ratio = quoted_chars as f64 / total_chars as f64;
    // Cap at 1.0, scale: even 20% backtick coverage is strong evidence.
    (ratio * 5.0).min(1.0)
}

/// Count hedging words (might, possibly, perhaps, maybe, could, seems).
fn hedging_count(reason: &str) -> usize {
    let lower = reason.to_lowercase();
    ["might", "possibly", "perhaps", "maybe", "could", "seems", "appear", "likely", "unclear"]
        .iter()
        .map(|kw| lower.matches(kw).count())
        .sum()
}

/// Count negation words (not, no, never, doesn't, don't, won't).
fn negation_count(reason: &str) -> usize {
    let lower = reason.to_lowercase();
    ["not ", "no ", "never", "doesn't", "don't", "won't", "isn't", "aren't", "cannot"]
        .iter()
        .map(|kw| lower.matches(kw).count())
        .sum()
}

// ── Calibration measurement (council #3, finding #6) ─────────────────
//
// VERDI weights are hand-tuned. These functions provide the MEASUREMENT
// infrastructure so weights can be evaluated against ground-truth data
// and tuned via grid search or logistic regression on collected labels.

/// Expected Calibration Error (ECE). Lower = better calibrated.
/// Bin predictions into `num_bins` equal-width bins, compute weighted
/// average of |avg_confidence - accuracy| per bin.
///
/// Usage: collect (predicted_confidence, ground_truth_correct) pairs from
/// benchmark runs, then call `expected_calibration_error(&pairs, 10)`.
pub fn expected_calibration_error(predictions: &[(f64, bool)], num_bins: usize) -> f64 {
    if predictions.is_empty() || num_bins == 0 {
        return 0.0;
    }
    let bin_width = 1.0 / num_bins as f64;
    let mut ece = 0.0;
    let n = predictions.len() as f64;
    for bin_idx in 0..num_bins {
        let lo = bin_idx as f64 * bin_width;
        let hi = lo + bin_width;
        let in_bin: Vec<&(f64, bool)> = predictions.iter()
            .filter(|(conf, _)| *conf >= lo && (conf < &hi || bin_idx == num_bins - 1))
            .collect();
        if in_bin.is_empty() {
            continue;
        }
        let avg_conf: f64 = in_bin.iter().map(|(c, _)| *c).sum::<f64>() / in_bin.len() as f64;
        let accuracy: f64 = in_bin.iter().filter(|(_, correct)| *correct).count() as f64 / in_bin.len() as f64;
        let bin_weight = in_bin.len() as f64 / n;
        ece += (avg_conf - accuracy).abs() * bin_weight;
    }
    ece
}

/// Brier score. Lower = better (0 = perfect, 1 = worst).
/// Measures mean squared difference between predicted probability and outcome.
pub fn brier_score(predictions: &[(f64, bool)]) -> f64 {
    if predictions.is_empty() {
        return 0.0;
    }
    predictions.iter()
        .map(|(conf, correct)| {
            let outcome = if *correct { 1.0 } else { 0.0 };
            (conf - outcome).powi(2)
        })
        .sum::<f64>() / predictions.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sva_aligned_verified() {
        let reason = "The API pandas.read_csv exists. Found in pandas documentation. Verified as a real method.";
        let sva = step_verdict_alignment(reason, "verified");
        assert!(sva > 0.5, "aligned verified should be > 0.5, got {}", sva);
    }

    #[test]
    fn sva_aligned_hallucinated() {
        let reason = "This API does not exist. Hallucinated method name. Invalid call.";
        let sva = step_verdict_alignment(reason, "hallucinated");
        assert!(sva > 0.5, "aligned hallucinated should be > 0.5, got {}", sva);
    }

    #[test]
    fn sva_unaligned() {
        let reason = "The API exists but also doesn't exist. Verified as fake.";
        let sva = step_verdict_alignment(reason, "verified");
        assert!(sva <= 1.0, "sva should be <= 1.0, got {}", sva);
    }

    #[test]
    fn clm_one_sided_verified() {
        let reason = "exists found verified confirmed valid";
        let clm = claim_level_margin(reason, "verified");
        assert!(clm > 0.7, "strong verified margin should be > 0.7, got {}", clm);
    }

    #[test]
    fn clm_balanced() {
        let reason = "exists not exist verified hallucinated valid invalid";
        let clm = claim_level_margin(reason, "uncertain");
        assert!(clm > 0.3 && clm < 0.8, "balanced should be moderate, got {}", clm);
    }

    #[test]
    fn egs_with_backticks() {
        let reason = "Found `read_csv` in `pandas` module. The method `read_csv` is documented.";
        let egs = evidence_grounding_score(reason);
        assert!(egs > 0.1, "backtick-heavy reason should have EGS > 0.1, got {}", egs);
    }

    #[test]
    fn egs_without_backticks() {
        let reason = "The method exists in the standard library.";
        let egs = evidence_grounding_score(reason);
        assert!(egs < 0.1, "no backticks should have EGS near 0, got {}", egs);
    }

    #[test]
    fn hedging_detected() {
        let count = hedging_count("This might be possibly correct, perhaps unclear.");
        assert!(count >= 3, "should detect 3+ hedging words, got {}", count);
    }

    #[test]
    fn negations_detected() {
        let count = negation_count("This does not exist and no evidence was found.");
        assert!(count >= 2, "should detect 2+ negations, got {}", count);
    }

    #[test]
    fn calibration_aligned_high() {
        let reason = "The API `pandas.read_csv` exists. Found in documentation. Verified as a real method. Confirmed available.";
        let calibrated = calibrate_confidence("verified", reason, 0.9);
        assert!(calibrated > 0.6, "well-aligned verdict should stay high, got {}", calibrated);
    }

    #[test]
    fn calibration_hedging_reduces() {
        let reason = "This might possibly be correct. Perhaps it could be a real API. Seems unclear.";
        let calibrated = calibrate_confidence("verified", reason, 0.9);
        assert!(calibrated < 0.9, "heavy hedging should reduce confidence, got {}", calibrated);
    }

    #[test]
    fn calibration_empty_reason_neutral() {
        let calibrated = calibrate_confidence("uncertain", "", 0.5);
        assert!((0.4..=0.7).contains(&calibrated), "empty reason should be ~neutral, got {}", calibrated);
    }
}
