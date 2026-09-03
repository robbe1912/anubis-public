//! Stress: adversarial EVASION corpus — red-team recall measurement.
//!
//! Corpus: tests/stress_corpus/evasion/samples.jsonl (>=24 samples, ALL
//! ground_truth=false, 8 attack vectors × >=2 each):
//!   semantic_no_ids, mutation_direction, arity_error, kwargs_hallucination,
//!   tiny_lt100, unfenced, niche_lib, wrong_language.
//!
//! Same harness pattern as all_lang_bench (tempdir project root + TS-junction
//! scaffold, L3 falsification judge LIVE via Ollama, compiler gates ON).
//!
//! Usage:
//!   DELULU_LLM_MODEL=gemma4:e4b cargo test --release --test stress_evasion -- --nocapture --test-threads=1
//!
//! Hard sanity gates (panic): zero crashes, corpus >= 24 all-FALSE samples.
//! Recall is MEASURED, not gated — this is a red-team benchmark; misses are
//! the signal, not a failure.

use anubis_daemon::scanner::{scan_response, ScanContext};
use serde::Deserialize;
use std::path::Path;
use std::time::Instant;

#[derive(Deserialize, Debug, Clone)]
struct Sample {
    id: String,
    language: String,
    #[allow(dead_code)]
    library: String,
    code: String,
    prose_claim: String,
    ground_truth: String,
    #[allow(dead_code)]
    claim_type: String,
    /// Adversarial vector tag (semantic_no_ids, arity_error, ...).
    vector: String,
    /// "raw" = unfenced code + prose; default fenced.
    #[serde(default)]
    render: Option<String>,
    #[allow(dead_code)]
    citation: String,
}

impl Sample {
    fn fence(&self) -> &'static str {
        match self.language.as_str() {
            "python" => "python",
            "typescript" => "typescript",
            "rust" => "rust",
            "go" => "go",
            "java" => "java",
            "csharp" => "csharp",
            "cpp" => "cpp",
            "gdscript" => "gdscript",
            _ => "",
        }
    }

    /// Fenced agent-style response by default; "raw" renders code + prose
    /// with NO fence (attack vector: unfenced).
    fn render(&self) -> String {
        let claim = &self.prose_claim;
        if self.render.as_deref() == Some("raw") {
            return format!("{}\n\n{}\n", self.code, claim);
        }
        format!(
            "```{lang}\n{code}\n```\n\n{claim}\n",
            lang = self.fence(),
            code = self.code,
            claim = claim,
        )
    }

    fn is_false(&self) -> bool {
        self.ground_truth.eq_ignore_ascii_case("false")
    }
}

#[derive(Default)]
struct Metrics {
    tp: u32,
    fn_: u32,
    per_vector: std::collections::BTreeMap<String, (u32, u32)>, // vector -> (tp, fn)
    per_layer: std::collections::BTreeMap<String, u32>,          // catching layer -> count
    crashed: u32,
    misses: Vec<String>,
    latencies: Vec<u128>,
    rows: Vec<Row>,
}

struct Row {
    id: String,
    vector: String,
    language: String,
    caught: bool,
    layer: String,
    latency_ms: u128,
    content_chars: usize,
    first_warning: String,
}

/// Best-effort attribution of a warning to the layer that produced it,
/// from the warning-string conventions used across the scanner:
///   "FORGE..."            -> L2 AST pipeline (forge_pipeline::prefix::FORGE)
///   "claim-hallucinated"  -> L3 falsification judge (aggregate_claims)
///   compiler gate text    -> L2 rustc/tsc/javac/go gates
///   "behavior..."         -> L2.5 behavioral verification
///   cached/scope/Unverified -> L1.5 symbol cache / scope analysis
fn layer_of(w: &str) -> &'static str {
    let wl = w.to_ascii_lowercase();
    if wl.contains("claim-hallucinated") {
        "L3"
    } else if wl.contains("forge") {
        "L2-forge"
    } else if wl.contains("rustc")
        || wl.contains("javac")
        || wl.contains("error ts")
        || wl.contains("error[")
        || wl.contains("compiler")
        || wl.contains("compile error")
        || wl.contains("type error")
        || wl.contains("not enough arguments")
    {
        "L2-compiler"
    } else if wl.contains("behavior") {
        "L2.5-behavioral"
    } else if wl.contains("cached-hallucination")
        || wl.contains("scope-hallucination")
        || wl.contains("unverified api")
        || wl.contains("symbol cache")
        || wl.contains("l1.5")
    {
        "L1.5"
    } else {
        "L1/other"
    }
}

fn load_samples() -> Vec<Sample> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("stress_corpus")
        .join("evasion")
        .join("samples.jsonl");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let s: Sample = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("sample line {}: {} — {}", i + 1, e, &line[..line.len().min(120)])
        });
        out.push(s);
    }
    out
}

/// Scaffold so compiler gates see a real project (TS junction), mirroring
/// all_lang_bench.
fn scaffold(root: &Path) {
    let _ = std::fs::write(root.join("package.json"), r#"{"name":"bench","private":true}"#);
    let nm = root.join("node_modules");
    let _ = std::fs::create_dir_all(&nm);
    let global_root = std::process::Command::new("cmd")
        .args(["/c", "npm", "root", "-g"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(gr) = global_root {
        let src = Path::new(&gr).join("typescript");
        let dst = nm.join("typescript");
        if src.is_dir() && !dst.exists() {
            let _ = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&dst)
                .arg(&src)
                .output();
        }
    }
}

fn resolve_model() -> (String, String, String) {
    let model = std::env::var("DELULU_LLM_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "gemma4:e4b".to_string());
    let looks_ollama = model.contains(':') && !model.contains('.');
    let base_url = std::env::var("DELULU_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            if looks_ollama {
                "http://localhost:11434/v1".to_string()
            } else {
                "https://api.z.ai/api/coding/paas/v4".to_string()
            }
        });
    let api_key = std::env::var("DELULU_LLM_API_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "ollama".to_string());
    (model, base_url, api_key)
}

#[tokio::test]
async fn stress_evasion_red_team() {
    let samples = load_samples();
    assert!(
        samples.len() >= 24,
        "adversarial corpus must have >=24 samples, got {}",
        samples.len()
    );
    assert!(
        samples.iter().all(|s| s.is_false()),
        "red-team corpus must be all-FALSE"
    );
    let mut vector_counts = std::collections::BTreeMap::new();
    for s in &samples {
        *vector_counts.entry(s.vector.clone()).or_insert(0u32) += 1;
    }
    for (v, n) in &vector_counts {
        assert!(n >= &2, "vector {v} needs >=2 samples, got {n}");
    }

    let (model, base_url, api_key) = resolve_model();
    eprintln!("===================================================");
    eprintln!(" EVASION stress — {} samples, {} vectors, L3 LIVE", samples.len(), vector_counts.len());
    eprintln!(" model={model} | base_url={base_url} | api_key_len={}", api_key.len());
    eprintln!("===================================================");

    // L3 LIVE: falsification judge runs; only bulk docs-in-prompt off.
    std::env::set_var("ANUBIS_L3_DOCS_IN_PROMPT", "0");
    std::env::remove_var("SKIP_COMPILER_GATES");
    std::env::remove_var("DELULU_FORGE_ONLY");

    let project_tmp = tempfile::tempdir().expect("tempdir for project root");
    scaffold(project_tmp.path());

    let cancel = tokio_util::sync::CancellationToken::new();
    let ctx = ScanContext {
        project_root: project_tmp.path().to_string_lossy().to_string(),
        logic_model: model.clone(),
        llm_base_url: base_url.clone(),
        llm_api_key: api_key.clone(),
        llm_extra_headers: Vec::new(),
        request_class: String::new(),
        language: String::new(),
        cancel,
    };

    let mut m = Metrics::default();
    for sample in &samples {
        let content = sample.render();
        let content_chars = content.chars().count();
        let started = Instant::now();
        let result = scan_response(&content, &ctx).await;
        let latency_ms = started.elapsed().as_millis();
        let warned = !result.warnings.is_empty();
        let layer = result
            .warnings
            .first()
            .map(|w| layer_of(w).to_string())
            .unwrap_or_else(|| "-".to_string());
        let first_warning = result
            .warnings
            .first()
            .map(|w| w.chars().take(120).collect())
            .unwrap_or_default();

        eprintln!(
            "  [{:<9}] {:<28} vec={:<18} lang={:<11} caught={:<5} layer={:<14} ms={:<6} chars={:<4} {}",
            if warned { "CAUGHT" } else { "MISSED" },
            sample.id,
            sample.vector,
            sample.language,
            warned,
            layer,
            latency_ms,
            content_chars,
            first_warning
        );

        m.latencies.push(latency_ms);
        if warned {
            m.tp += 1;
            for w in &result.warnings {
                *m.per_layer.entry(layer_of(w).to_string()).or_insert(0) += 1;
            }
        } else {
            m.fn_ += 1;
            m.misses.push(sample.id.clone());
        }
        let e = m.per_vector.entry(sample.vector.clone()).or_insert((0, 0));
        if warned {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
        m.rows.push(Row {
            id: sample.id.clone(),
            vector: sample.vector.clone(),
            language: sample.language.clone(),
            caught: warned,
            layer,
            latency_ms,
            content_chars,
            first_warning,
        });
        if result.scan_failed {
            m.crashed += 1;
        }
    }

    let total = m.tp + m.fn_;
    let recall = m.tp as f64 / total.max(1) as f64 * 100.0;
    let mut sorted_lat = m.latencies.clone();
    sorted_lat.sort_unstable();
    let p50 = sorted_lat.get(sorted_lat.len() / 2).copied().unwrap_or(0);
    let p95 = sorted_lat
        .get(sorted_lat.len() * 95 / 100)
        .copied()
        .unwrap_or(0);

    eprintln!();
    eprintln!("── EVASION SUMMARY ──────────────────────────────────");
    eprintln!("  confusion : TP={} FN={} (all {} samples are FALSE — recall only)", m.tp, m.fn_, total);
    eprintln!("  RECALL    : {recall:.1}%  (red-team: misses are the signal)");
    eprintln!("  crashes   : {}", m.crashed);
    eprintln!("  latency   : p50={p50} ms  p95={p95} ms");
    eprintln!("  catching layers (per warning):");
    for (layer, n) in &m.per_layer {
        eprintln!("    {layer:<16} {n}");
    }
    eprintln!("  per-vector recall:");
    for (v, (tp, fnc)) in &m.per_vector {
        let tot = tp + fnc;
        eprintln!("    {v:<20} {:.0}%  ({tp}/{tot})", *tp as f64 / tot as f64 * 100.0);
    }
    eprintln!("  evaded ({}): {}", m.fn_, m.misses.join(", "));

    // Hard sanity gates: stability only, recall is measured not gated.
    assert_eq!(m.crashed, 0, "scanner must not crash on any adversarial sample");
}
