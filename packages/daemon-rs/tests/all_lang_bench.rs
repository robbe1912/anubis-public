//! All-language benchmark: every scanner feature ON (L1 + L1.5 + FORGE +
//! compiler gates + L3 falsification judge), 7 languages × 6 samples.
//!
//! Corpus: tests/all_lang_corpus/samples.jsonl (42 samples: 21 TRUE /
//! 21 FALSE — python, typescript, rust, go, java, csharp, cpp, gdscript).
//!
//! Usage:
//!   DELULU_LLM_MODEL=gemma4:e4b cargo test --release --test all_lang_bench -- --nocapture
//!
//! Hard sanity gates (panic): zero crashes, ≥8/21 FALSE caught (no-op guard).
//! Soft targets (warn): recall ≥60% weak / ≥80% strong, precision ≥90%.

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

    /// Agent-style markdown response: fenced code + prose claim about it.
    fn render(&self) -> String {
        format!(
            "```{lang}\n{code}\n```\n\n{claim}\n",
            lang = self.fence(),
            code = self.code,
            claim = self.prose_claim,
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
    fp: u32,
    tn: u32,
    per_lang: std::collections::BTreeMap<String, (u32, u32)>, // lang -> (tp, fn)
    crashed: u32,
    misses: Vec<String>,
    fps: Vec<String>,
    latencies: Vec<u128>,
}

fn load_samples() -> Vec<Sample> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("all_lang_corpus")
        .join("samples.jsonl");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let s: Sample = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("sample line {}: {} — {}", i + 1, e, &line[..line.len().min(120)]));
        out.push(s);
    }
    out
}

/// Scaffold so compiler gates see a real project (TS junction + rustup pin),
/// mirroring doc_injection_bench.
fn scaffold(root: &Path) {
    let _ = std::fs::write(root.join("package.json"), r#"{"name":"bench","private":true}"#);
    let nm = root.join("node_modules");
    let _ = std::fs::create_dir_all(&nm);
    let global_root = std::process::Command::new("cmd")
        .args(["/c", "npm", "root -g"])
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
async fn all_lang_bench_full_features() {
    let samples = load_samples();
    assert_eq!(samples.len(), 46, "corpus must have 46 samples");
    let n_false = samples.iter().filter(|s| s.is_false()).count();
    assert_eq!(n_false, 23, "corpus must be balanced 23T/23F");

    let (model, base_url, api_key) = resolve_model();
    eprintln!(
        "==================================================="
    );
    eprintln!(
        " all-language benchmark — 46 samples, 8 langs, ALL FEATURES ON"
    );
    eprintln!(
        " model={model} | base_url={base_url} | api_key_len={}",
        api_key.len()
    );
    eprintln!(
        "==================================================="
    );

    // NO_DOCS-arm kill switch: falsification judge + doc-excerpt matching
    // from ANUBIS_DOCS_DIR remain ON; only the bulk-injection path is off.
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
        let started = Instant::now();
        let result = scan_response(&content, &ctx).await;
        let latency_ms = started.elapsed().as_millis();
        let warned = !result.warnings.is_empty();

        eprintln!(
            "  [{:<9}] {:<28} lang={:<11} truth={:<5} warned={:<5} latency_ms={:<6} warns={}",
            "FULL",
            sample.id,
            sample.language,
            sample.ground_truth,
            warned,
            latency_ms,
            result.warnings.len()
        );
        for w in &result.warnings {
            let head: String = w.chars().take(140).collect();
            if sample.is_false() {
                eprintln!("      + {head}");
            } else {
                eprintln!("      ! FP {head}");
            }
        }

        m.latencies.push(latency_ms);
        if sample.is_false() {
            if warned {
                m.tp += 1;
            } else {
                m.fn_ += 1;
                m.misses.push(sample.id.clone());
            }
            let e = m.per_lang.entry(sample.language.clone()).or_insert((0, 0));
            if warned {
                e.0 += 1;
            } else {
                e.1 += 1;
            }
        } else if warned {
            m.fp += 1;
            m.fps.push(sample.id.clone());
        } else {
            m.tn += 1;
        }
        if result.scan_failed {
            m.crashed += 1;
        }
    }

    let total = m.tp + m.fn_;
    let recall = m.tp as f64 / total as f64 * 100.0;
    let precision = m.tp as f64 / (m.tp + m.fp).max(1) as f64 * 100.0;
    let mut sorted_lat = m.latencies.clone();
    sorted_lat.sort_unstable();
    let p50 = sorted_lat.get(sorted_lat.len() / 2).copied().unwrap_or(0);
    let p95 = sorted_lat
        .get(sorted_lat.len() * 95 / 100)
        .copied()
        .unwrap_or(0);

    eprintln!();
    eprintln!("── ALL-LANG SUMMARY ────────────────────────────────");
    eprintln!("  confusion    : TP={} FN={} FP={} TN={} (of {})", m.tp, m.fn_, m.fp, m.tn, samples.len());
    eprintln!("  recall       : {recall:.1}%  (target ≥60 weak / ≥80 strong)");
    eprintln!("  precision    : {precision:.1}%  (target ≥90)");
    eprintln!("  crashes      : {}", m.crashed);
    eprintln!("  latency p50  : {p50} ms   p95: {p95} ms");
    eprintln!("  per-language recall:");
    for (lang, (tp, fnc)) in &m.per_lang {
        let tot = tp + fnc;
        eprintln!("    {lang:<12} {:.1}%  ({tp}/{tot})", *tp as f64 / tot as f64 * 100.0);
    }
    eprintln!("  FN misses ({}): {}", m.fn_, m.misses.join(", "));
    eprintln!("  FP alarms ({}): {}", m.fp, m.fps.join(", "));

    // Hard sanity gates.
    assert_eq!(m.crashed, 0, "scanner must not crash on any sample");
    assert!(m.tp >= 8, "no-op guard: caught {} of 23 FALSE — scanner inert?", m.tp);
}
