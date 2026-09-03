// Eval corpus — port of legacy TS eval harness
// (packages/eval/src/{case-loader,runner,metrics}.ts).
//
// Feeds each case's diff.patch through scanner::scan_response and compares
// the verdict to expected.json. With no LLM API key in the ScanContext,
// only Layers 1 (regex API-claim check), 1.5 (symbol cache), and the local
// project index are exercised; Layer 3 (LLM validator) is skipped.
//
// Two tests:
//   1. `eval_corpus_no_hard_false_positives_on_real_prs` — strict CI gate on
//      cases-real/ (30 real-PR ALLOW cases). Zero hard FPs allowed.
//   2. `eval_corpus_full_precision_recall` — measurement only, NO gate.
//      Walks cases-real/ + cases/ (17 mixed) + cases-escalate-v2/ (10
//      ESCALATE). Reports per-class precision/recall/F1.
//
// ========================================================================
// BASELINE MEASUREMENT (2026-07-23, no Layer 3, no symbol cache populated)
// ========================================================================
// Total: 57 cases (30 real + 17 mixed + 10 escalate-v2)
//
//                    tp   fp   fn   precision  recall   f1
//   ALLOW             7    8   36     0.4667   0.1628  0.2414
//   BLOCK             0    0    4     0.0000   0.0000  0.0000
//   ESCALATE          5   37    5     0.1190   0.5000  0.1923
//
// User-experienced FPR on ALLOW cases: 0.8372 [0.7003, 0.9188] Wilson 95%
//
// Read: without Layer 3, the scanner CANNOT distinguish hallucinations
// from correct code. BLOCK recall is 0% (missed all 4 BLOCK cases). ALLOW
// precision is 47% (allowed 8 of 17 hallucinated cases through). The only
// signal that fires is "Unverified API" — which fires on every line that
// references any uncached library, producing an 84% over-escalation rate.
//
// CONCLUSION FOR TASK D (block-and-retry): CANNOT be built on top of the
// current scanner. Block-and-retry requires either (a) Layer 3 wired with
// a real LLM API key, (b) symbol cache populated for common libraries,
// or both. Re-measure after those land before revisiting D.
//
// This test stays #[ignore]'d from CI — run manually with
//   cargo test --test eval_corpus eval_corpus_full_precision_recall -- --ignored --nocapture
// to capture baseline shifts as Layer 3 / cache population lands.

use std::fs;
use std::path::{Path, PathBuf};

use anubis_daemon::scanner::{scan_response, ScanContext, ScanResultData};
use serde::Deserialize;

// ─── Schemas ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct Expected {
    verdict: String, // "ALLOW" | "BLOCK" | "ESCALATE"
    #[serde(default)]
    layer: Option<String>,
    #[serde(default)]
    difficulty: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CaseMeta {
    language: String,
    #[serde(default)]
    library: Option<String>,
    #[serde(default)]
    notes: String,
}

// ─── Loader ──────────────────────────────────────────────────────────

struct EvalCase {
    id: String,
    corpus: &'static str, // "real", "mixed", "escalate-v2"
    diff: String,
    expected: Expected,
    meta: CaseMeta,
    after_path: PathBuf,
    after_content: String,
}

fn load_cases(root: &Path, corpus: &'static str) -> Vec<EvalCase> {
    let mut entries: Vec<PathBuf> = fs::read_dir(root)
        .unwrap_or_else(|e| panic!("eval cases dir {root:?} not readable: {e}"))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.split('-').next())
                    .map(|num| !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
        })
        .collect();
    entries.sort();

    entries
        .into_iter()
        .map(|dir| {
            let id = format!(
                "{}/{}",
                corpus,
                dir.file_name().and_then(|n| n.to_str()).unwrap_or_default()
            );

            let diff = read_required(&dir, "diff.patch", &id);
            let expected: Expected = serde_json::from_str(&read_required(&dir, "expected.json", &id))
                .unwrap_or_else(|e| panic!("case {id} invalid expected.json: {e}"));
            let meta: CaseMeta = serde_json::from_str(&read_required(&dir, "meta.json", &id))
                .unwrap_or_else(|e| panic!("case {id} invalid meta.json: {e}"));

            let after_path = fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("case {id} dir unreadable: {e}"))
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("after."))
                        .unwrap_or(false)
                })
                .unwrap_or_else(|| panic!("case {id} has no after.* file"));
            let after_content = fs::read_to_string(&after_path)
                .unwrap_or_else(|e| panic!("case {id} after.* unreadable: {e}"));

            EvalCase {
                id,
                corpus,
                diff,
                expected,
                meta,
                after_path,
                after_content,
            }
        })
        .collect()
}

fn read_required(dir: &Path, name: &str, case_id: &str) -> String {
    fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("case {case_id} missing {name}: {e}"))
}

// ─── Verdict mapping ─────────────────────────────────────────────────

fn map_result(r: &ScanResultData) -> &'static str {
    if !r.blocks.is_empty() {
        "BLOCK"
    } else if r.scan_failed {
        "ESCALATE"
    } else if !r.warnings.is_empty() {
        "ESCALATE"
    } else {
        "ALLOW"
    }
}

// ─── Metrics ─────────────────────────────────────────────────────────
//
// Confusion matrix convention: cells[actual][expected].
//   row index = what scanner produced (predicted class)
//   col index = what expected.json said (true class)
// Indices: 0=ALLOW, 1=BLOCK, 2=ESCALATE.

const LABELS: [&str; 3] = ["ALLOW", "BLOCK", "ESCALATE"];

struct Confusion {
    cells: [[usize; 3]; 3],
}

fn idx(v: &str) -> usize {
    match v {
        "ALLOW" => 0,
        "BLOCK" => 1,
        _ => 2,
    }
}

fn confusion(outcomes: &[(&str, &str)]) -> Confusion {
    let mut cells = [[0usize; 3]; 3];
    for (actual, expected) in outcomes {
        cells[idx(actual)][idx(expected)] += 1;
    }
    Confusion { cells }
}

#[derive(Debug, Clone, Copy)]
struct ClassMetrics {
    tp: usize,
    fp: usize,
    fn_: usize,
    precision: f64,
    recall: f64,
    f1: f64,
}

fn per_class(cm: &Confusion) -> [ClassMetrics; 3] {
    let mut out = [ClassMetrics {
        tp: 0,
        fp: 0,
        fn_: 0,
        precision: 0.0,
        recall: 0.0,
        f1: 0.0,
    }; 3];

    for c in 0..3 {
        let tp = cm.cells[c][c];
        // FP for class c = predicted c but true was something else
        //   = sum of row c except diagonal
        let fp = (0..3).filter(|&j| j != c).map(|j| cm.cells[c][j]).sum::<usize>();
        // FN for class c = true c but predicted something else
        //   = sum of column c except diagonal
        let fn_ = (0..3).filter(|&i| i != c).map(|i| cm.cells[i][c]).sum::<usize>();

        // Precision: tp/(tp+fp). If tp+fp == 0 (class never predicted), the
        // legacy TS harness returns 1.0 if tp>0 else 0.0 — we follow that
        // convention so a class the scanner never emits doesn't artificially
        // drag down aggregate precision.
        let precision = if tp + fp == 0 {
            if tp > 0 { 1.0 } else { 0.0 }
        } else {
            tp as f64 / (tp + fp) as f64
        };
        let recall = if tp + fn_ == 0 {
            if tp > 0 { 1.0 } else { 0.0 }
        } else {
            tp as f64 / (tp + fn_) as f64
        };
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };

        out[c] = ClassMetrics {
            tp,
            fp,
            fn_,
            precision,
            recall,
            f1,
        };
    }
    out
}

/// Wilson score 95% CI for a binomial proportion.
/// Returns (point, lower, upper).
fn wilson95(k: usize, n: usize) -> (f64, f64, f64) {
    if n == 0 {
        return (0.0, 0.0, 0.0);
    }
    let z = 1.96;
    let p = k as f64 / n as f64;
    let denom = 1.0 + (z * z) / n as f64;
    let center = (p + (z * z) / (2.0 * n as f64)) / denom;
    let margin =
        (z * ((p * (1.0 - p)) / n as f64 + (z * z) / (4.0 * n as f64 * n as f64)).sqrt()) / denom;
    let lower = (center - margin).max(0.0);
    let upper = (center + margin).min(1.0);
    (p, lower, upper)
}

// ─── Runner ──────────────────────────────────────────────────────────

/// Run scanner over every case, returning (case_id, actual, expected) per case.
/// Uses an empty llm_api_key so Layer 3 is skipped — only Layers 1 / 1.5 +
/// local project index are exercised.
async fn run_corpus(cases: &[EvalCase]) -> Vec<(String, String, String)> {
    let mut outcomes = Vec::with_capacity(cases.len());
    for case in cases {
        // Seed a temp project root with the case's after.<ext> source so
        // build_project_index has declarations to match API claims against.
        let tmp = tempfile::tempdir().unwrap();
        let ext = case
            .after_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("txt");
        fs::write(tmp.path().join(format!("src.{ext}")), &case.after_content).unwrap();

        let ctx = ScanContext {
            project_root: tmp.path().to_string_lossy().to_string(),
            logic_model: std::env::var("DELULU_LLM_MODEL")
                .unwrap_or_else(|_| "glm-4.7-flash".to_string()),
            llm_base_url: std::env::var("DELULU_LLM_BASE_URL")
                .unwrap_or_else(|_| "https://api.z.ai/api/coding/paas/v4".to_string()),
            // Empty key skips L3 (the daemon's cascade short-circuits when
            // llm_api_key is empty). Set DELULU_LLM_API_KEY to enable L3.
            llm_api_key: if std::env::var("DELULU_FORGE_ONLY").is_ok() {
                String::new()
            } else {
                std::env::var("DELULU_LLM_API_KEY").unwrap_or_default()
            },
            llm_extra_headers: vec![],
            request_class: String::new(),
            language: String::new(),
            cancel: tokio_util::sync::CancellationToken::new(),
        };

        let started = std::time::Instant::now();
        let result = scan_response(&case.diff, &ctx).await;
        let latency_ms = started.elapsed().as_millis();
        eprintln!(
            "  case={} lang={} lib={:?} verdict={} latency_ms={}",
            case.id, case.meta.language, case.meta.library,
            map_result(&result), latency_ms
        );
        let actual = map_result(&result).to_string();
        let expected = case.expected.verdict.clone();
        if actual != expected {
            eprintln!(
                "MISMATCH case={} lang={} lib={:?}: expected={} actual={}",
                case.id, case.meta.language, case.meta.library, expected, actual
            );
            eprintln!("  warnings: {:?}", result.warnings);
            eprintln!("  blocks:   {:?}", result.blocks);
            if !result.details.is_empty() {
                eprintln!("  details:  {:?}", result.details);
            }
        }
        outcomes.push((case.id.clone(), actual, expected));
    }
    outcomes
}

fn print_summary(cm: &Confusion, label: &str) {
    let pc = per_class(cm);
    eprintln!("=== {label} ===");
    eprintln!("confusion matrix [actual][expected], labels={:?}:", LABELS);
    for (i, label) in LABELS.iter().enumerate() {
        eprintln!(
            "  {label:<8} [{}, {}, {}]",
            cm.cells[i][0], cm.cells[i][1], cm.cells[i][2]
        );
    }
    eprintln!("per-class (one-vs-rest):");
    for (i, label) in LABELS.iter().enumerate() {
        let m = &pc[i];
        eprintln!(
            "  {label:<8} tp={} fp={} fn={} precision={:.4} recall={:.4} f1={:.4}",
            m.tp, m.fp, m.fn_, m.precision, m.recall, m.f1
        );
    }
    // User-experienced FPR: among expected=ALLOW cases, fraction predicted
    // as BLOCK or ESCALATE. Matches legacy TS harness userFPR.
    let fp_block_on_allow = cm.cells[1][0];
    let fp_escalate_on_allow = cm.cells[2][0];
    let tn_allow = cm.cells[0][0];
    let fpr_user = wilson95(
        fp_block_on_allow + fp_escalate_on_allow,
        fp_block_on_allow + fp_escalate_on_allow + tn_allow,
    );
    eprintln!(
        "FPR (user-experienced, on ALLOW cases, Wilson 95%): point={:.4} [{:.4}, {:.4}]",
        fpr_user.0, fpr_user.1, fpr_user.2
    );
}

// ─── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn eval_corpus_no_hard_false_positives_on_real_prs() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let cases_root = Path::new(manifest_dir).join("../eval/cases-real");
    if !cases_root.exists() {
        eprintln!("skipping eval_corpus: {cases_root:?} not present");
        return;
    }
    let cases = load_cases(&cases_root, "real");
    assert!(!cases.is_empty(), "no cases loaded from {cases_root:?}");

    let outcomes = run_corpus(&cases).await;
    let summary: Vec<(&str, &str)> = outcomes
        .iter()
        .map(|(_, a, e)| (a.as_str(), e.as_str()))
        .collect();
    let cm = confusion(&summary);
    print_summary(&cm, "eval_corpus (cases-real only)");

    // Gate: zero hard false positives on real PRs.
    let fp_block = cm.cells[1][0];
    assert_eq!(
        fp_block, 0,
        "{fp_block} cases were incorrectly BLOCKed — see mismatches above"
    );
}

#[tokio::test]
#[ignore = "baseline measurement only — run with --ignored. See header comment for current numbers."]
async fn eval_corpus_full_precision_recall() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let eval_root = Path::new(manifest_dir).join("../eval");

    let mut all_cases: Vec<EvalCase> = Vec::new();
    for (sub, corpus) in [
        ("cases-real", "real"),
        ("cases", "mixed"),
        ("cases-escalate-v2", "escalate-v2"),
    ] {
        let dir = eval_root.join(sub);
        if dir.exists() {
            all_cases.extend(load_cases(&dir, corpus));
        } else {
            eprintln!("skipping {sub}/ (not present)");
        }
    }
    if all_cases.is_empty() {
        eprintln!("skipping eval_corpus_full_precision_recall: no corpora present");
        return;
    }
    eprintln!("loaded {} cases total", all_cases.len());

    let outcomes = run_corpus(&all_cases).await;
    let summary: Vec<(&str, &str)> = outcomes
        .iter()
        .map(|(_, a, e)| (a.as_str(), e.as_str()))
        .collect();
    let cm = confusion(&summary);
    print_summary(&cm, "eval_corpus FULL (cases-real + cases + cases-escalate-v2)");

    // Per-corpus breakdown.
    for corpus in ["real", "mixed", "escalate-v2"] {
        let subset: Vec<(&str, &str)> = outcomes
            .iter()
            .filter(|(id, _, _)| id.starts_with(&format!("{corpus}/")))
            .map(|(_, a, e)| (a.as_str(), e.as_str()))
            .collect();
        if subset.is_empty() {
            continue;
        }
        let sub_cm = confusion(&subset);
        print_summary(&sub_cm, &format!("eval_corpus subset: {corpus}"));
    }

    // No gate. This test documents the baseline. See header comment for
    // the Task D verdict: scanner cannot detect hallucinations without
    // Layer 3 (LLM validator) + populated symbol cache.
}
