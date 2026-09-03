//! Latency micro-benchmark: time scan_response() on 6 representative corpus
//! samples (python / typescript / rust / go / java / gdscript), 3 runs each,
//! two arms:
//!   A) FORGE_ONLY (DELULU_FORGE_ONLY=1) — deterministic layers only
//!   B) L3-live (all features, gemma4:e4b via ollama) — LLM judge enabled
//!
//! Usage:
//!   DELULU_LLM_MODEL=gemma4:e4b DELULU_LLM_BASE_URL=http://localhost:11434/v1 \
//!   DELULU_LLM_API_KEY=ollama ANUBIS_DOCS_DIR=<docs> \
//!   cargo test --release --test stress_latency -- --nocapture
//!
//! Emits one STATS line per (sample, arm) with per-run ms; parse with
//! parse_bench.py. Also asserts FORGE_ONLY arm never exceeds 20s (sanity —
//! compiler gates like tsc legitimately take 10-15s on TS samples).

use anubis_daemon::scanner::{scan_response, ScanContext};
use serde::Deserialize;
use std::path::Path;
use std::time::Instant;

#[derive(Deserialize, Debug, Clone)]
struct Sample {
    id: String,
    language: String,
    code: String,
    prose_claim: String,
    #[allow(dead_code)]
    ground_truth: String,
    #[allow(dead_code)]
    library: String,
    #[allow(dead_code)]
    claim_type: String,
    #[allow(dead_code)]
    citation: String,
}

const WANTED: &[&str] = &[
    "py_false_pandas_seperator",
    "ts_true_promise_all_waits",
    "rs_false_iter_map_to_string",
    "go_false_map_sorted_keys",
    "java_false_list_map_method",
    "gd_false_tween_new",
];

fn fence(lang: &str) -> &'static str {
    match lang {
        "python" => "python",
        "typescript" => "typescript",
        "rust" => "rust",
        "go" => "go",
        "java" => "java",
        "gdscript" => "gdscript",
        _ => "",
    }
}

fn load_samples() -> Vec<Sample> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("all_lang_corpus")
        .join("samples.jsonl");
    let raw = std::fs::read_to_string(&path).expect("read samples.jsonl");
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let s: Sample = serde_json::from_str(line).expect("parse sample");
        if WANTED.contains(&s.id.as_str()) {
            out.push(s);
        }
    }
    assert_eq!(out.len(), WANTED.len(), "must find all 6 target samples");
    out.sort_by_key(|s| WANTED.iter().position(|w| *w == s.id.as_str()).unwrap());
    out
}

/// Same scaffold as all_lang_bench: TS junction + package.json so compiler
/// gates see a real project.
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
    let base_url = std::env::var("DELULU_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://localhost:11434/v1".to_string());
    let api_key = std::env::var("DELULU_LLM_API_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "ollama".to_string());
    (model, base_url, api_key)
}

const RUNS: usize = 3;

#[tokio::test]
async fn stress_latency_microbench() {
    let samples = load_samples();
    let (model, base_url, api_key) = resolve_model();
    eprintln!("=== stress_latency: 6 samples x {RUNS} runs x 2 arms (model={model}) ===");

    let project_tmp = tempfile::tempdir().expect("tempdir");
    scaffold(project_tmp.path());
    let cancel = tokio_util::sync::CancellationToken::new();
    let mk_ctx = || ScanContext {
        project_root: project_tmp.path().to_string_lossy().to_string(),
        logic_model: model.clone(),
        llm_base_url: base_url.clone(),
        llm_api_key: api_key.clone(),
        llm_extra_headers: Vec::new(),
        request_class: String::new(),
        language: String::new(),
        cancel: cancel.clone(),
    };

    // ---- Arm A: FORGE_ONLY (deterministic layers + compiler gates, no L3) ----
    std::env::set_var("DELULU_FORGE_ONLY", "1");
    for s in &samples {
        let content = format!(
            "```{lang}\n{code}\n```\n\n{claim}\n",
            lang = fence(&s.language),
            code = s.code,
            claim = s.prose_claim,
        );
        // Untimed warmup: populates registry/symbol caches (first scan on
        // py_false_pandas_seperator takes ~6s cold from PyPI fetch).
        {
            let ctx = mk_ctx();
            let _ = scan_response(&content, &ctx).await;
        }
        for r in 1..=RUNS {
            let ctx = mk_ctx();
            let started = Instant::now();
            let res = scan_response(&content, &ctx).await;
            let ms = started.elapsed().as_millis();
            eprintln!(
                "STATS arm=forge_only sample={} lang={} run={} ms={} warns={} failed={}",
                s.id, s.language, r, ms, res.warnings.len(), res.scan_failed
            );
            // Deterministic arm includes compiler gates (tsc ≈10-15s on TS),
            // so the sanity bound must cover them.
            assert!(ms < 20000, "FORGE_ONLY arm must stay <20s, got {ms}ms on {}", s.id);
            assert!(!res.scan_failed, "FORGE_ONLY scan_failed on {}", s.id);
        }
    }

    // ---- Arm B: L3-live (all features) ----
    std::env::remove_var("DELULU_FORGE_ONLY");
    std::env::set_var("ANUBIS_L3_DOCS_IN_PROMPT", "0");
    for s in &samples {
        for r in 1..=RUNS {
            // Unique suffix per run: verdict cache (24h TTL) keys on content,
            // so identical content would return cached verdicts in ~0ms.
            let content = format!(
                "```{lang}\n{code}\n// bench run {r}\n```\n\n{claim}\n",
                lang = fence(&s.language),
                code = s.code,
                claim = s.prose_claim,
            );
            let ctx = mk_ctx();
            let started = Instant::now();
            let res = scan_response(&content, &ctx).await;
            let ms = started.elapsed().as_millis();
            let l3_fired = !res.validator_response.is_empty();
            eprintln!(
                "STATS arm=l3_live sample={} lang={} run={} ms={} warns={} l3_fired={} failed={}",
                s.id, s.language, r, ms, res.warnings.len(), l3_fired, res.scan_failed
            );
            assert!(ms > 1, "l3_live run {r} on {} returned in {ms}ms — verdict cache hit, not a real scan", s.id);
        }
    }
    eprintln!("=== stress_latency done ===");
}
