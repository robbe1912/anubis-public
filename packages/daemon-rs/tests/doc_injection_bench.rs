// Doc Injection v2 Benchmark — A/B runner for the v2 doc-injection redesign.
//
// Corpus: tests/doc_injection_corpus/samples.jsonl (48 samples, balanced
// TRUE/FALSE across Python / TypeScript / Rust, mixing api_existence and
// behavioral claims). Plan: .omo/plans/doc-injection-v2.md Section 7.
//
// What this measures
// ------------------
// Two arms, same scanner binary, same model, same corpus; the ONLY knob
// that differs is the L3 doc-injection kill switch
// (`ANUBIS_L3_DOCS_IN_PROMPT` env var, read by
// `scanner::build_library_docs_fallback`):
//
//   ARM OFF  — kill switch = "0"  (docs stripped from L3 prompt — baseline)
//   ARM LAZY — kill switch = "1"  (docs injected into L3 prompt — treatment)
//
// IMPORTANT: `scanner.doc_grounding` is NOT a real ScannerConfig field —
// it was a v1 hallucination. The v1 bench wrote it to YAML and read it back
// from a non-existent struct field, so both arms ran byte-identically (this
// is exactly what plan Section 1 calls out as "no actual effect was
// measured — all 20 verdicts byte-identical between baseline and treatment").
// The kill switch is the real, wired-through A/B knob. We still write the
// arm name into the temp config YAML for log readability, but the env var
// is what `build_library_docs_fallback` actually consults.
//
// For each arm, computes recall / precision / FP-rate / warning-emission /
// latency over the corpus, then prints a comparison row so delta is visible.
//
// Run
// ---
//   $env:DELULU_LLM_API_KEY = "<key>"        # required for L3 to fire
//   $env:DOC_INJECTION_ARM  = "both"         # "no_docs" | "with_docs" | "both" (default)
//                                            # (legacy aliases: "off" | "lazy" | "both")
//   $env:DELULU_LLM_MODEL   = "glm-4.7"      # strong baseline (legacy env)
//   # OR use the DOD-target env (preferred):
//   $env:DOC_INJECTION_MODEL = "gemma4:e4b"  # auto-uses http://localhost:11434/v1
//   cargo test --release --test doc_injection_bench -- --nocapture
//
// `DOC_INJECTION_MODEL` overrides `DELULU_LLM_MODEL` and auto-configures the
// Ollama base_url when the name starts with gemma*/qwen*/llama*. Override
// the auto URL by also setting `DELULU_LLM_BASE_URL`. Default model when
// neither env var is set: `glm-4.7-flash` (hosted).
//
// DELULU_FORGE_ONLY=1 strips the API key (L3 short-circuits). Use this for
// quick L1.5/L2-only smoke without the LLM. Kill switch has no effect when
// L3 never runs.
//
// Hard failure conditions (these mean the scanner is broken, not the corpus):
//   - 0 hits on FALSE samples (no-op scanner, like v1).
//   - Any sample panics the scanner.
//
// Soft targets print WARN lines (corpus is measurement, not a CI gate).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anubis_daemon::scanner::{scan_response, ScanContext, ScanResultData};
use serde::Deserialize;

// ─── Sample spec ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct Sample {
    id: String,
    language: String,
    claim_type: String,        // api_existence | behavioral
    ground_truth: String,      // "true" | "false"
    #[allow(dead_code)]
    library: String,
    #[allow(dead_code)]
    imports: Vec<String>,
    code: String,
    prose_claim: String,
    #[allow(dead_code)]
    citation: String,
    #[allow(dead_code)]
    rationale: String,
    #[allow(dead_code)]
    expected_layer: Option<String>,
    #[allow(dead_code)]
    tags: Option<Vec<String>>,
}

impl Sample {
    fn is_false(&self) -> bool {
        self.ground_truth.eq_ignore_ascii_case("false")
    }

    fn fence(&self) -> &'static str {
        match self.language.as_str() {
            "python" => "python",
            "typescript" => "typescript",
            "rust" => "rust",
            "go" => "go",
            _ => "",
        }
    }

    /// Render the sample as an agent-style markdown response so the scanner
    /// sees the same shape it would in production: a fenced code block
    /// followed by a prose claim about that code.
    fn render(&self) -> String {
        format!(
            "```{lang}\n{code}\n```\n\n{claim}\n",
            lang = self.fence(),
            code = self.code,
            claim = self.prose_claim,
        )
    }
}

fn load_samples() -> Vec<Sample> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("doc_injection_corpus")
        .join("samples.jsonl");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let s: Sample = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("samples.jsonl:{}: parse error: {}", i + 1, e));
        assert!(
            seen.insert(s.id.clone()),
            "samples.jsonl: duplicate id {}",
            s.id
        );
        assert!(
            s.ground_truth.eq_ignore_ascii_case("true")
                || s.ground_truth.eq_ignore_ascii_case("false"),
            "sample {}: ground_truth must be true|false, got {:?}",
            s.id,
            s.ground_truth
        );
        out.push(s);
    }
    assert!(
        !out.is_empty(),
        "samples.jsonl is empty — corpus not loaded"
    );
    out
}

// ─── Per-arm metrics ─────────────────────────────────────────────────

#[derive(Default, Debug)]
struct ArmMetrics {
    arm_name: String,
    n_samples: usize,
    n_true: usize,
    n_false: usize,
    // Confusion matrix from the scanner's warning emission:
    //   TP = FALSE sample AND scanner warned (correct catch)
    //   FN = FALSE sample AND scanner silent (missed hallucination)
    //   FP = TRUE sample AND scanner warned (false alarm)
    //   TN = TRUE sample AND scanner silent (correct pass)
    tp: usize,
    fn_: usize,
    fp: usize,
    tn: usize,
    // Coverage gauges. Two distinct signals:
    //
    // `docs_assisted_hits` — the scanner's own `result.docs_assisted` flag,
    //   which fires whenever `detect_libraries` / `search_docs` /
    //   `build_library_docs_fallback` populated the L3 RAG context (scanner
    //   mod.rs lines ~3297/3306/3331). Useful for confirming the doc
    //   *retrieval* path ran; misleading as an "A/B worked" signal because
    //   it fires whether or not L3 actually consulted the docs.
    //
    // `docs_cited_hits` — the TRUE "docs assisted" signal: L3 verdict
    //   reasons surfaced in `result.warnings` carry a `[DOC_N]` marker
    //   (per `l3_per_claim.rs` citation-forcing gate at line ~750). A hit
    //   here means the LLM actually grounded its verdict in a retrieved
    //   doc chunk — the citation-forcing pipeline's observable effect.
    //   Only meaningful on the WITH_DOCS arm (NO_DOCS arm has the kill
    //   switch set to "0" so `build_library_docs_fallback` returns "" and
    //   there is nothing to cite).
    docs_assisted_hits: usize,
    docs_cited_hits: usize,
    // Latency samples (ms).
    latencies_ms: Vec<u128>,
    // Per-language recall (TP / (TP + FN)) for spotting which language the
    // redesign helps most.
    per_lang_tp: HashMap<String, usize>,
    per_lang_fn: HashMap<String, usize>,
    // Per-claim-type recall (api_existence vs behavioral) — the redesign is
    // supposed to lift behavioral recall specifically.
    per_type_tp: HashMap<String, usize>,
    per_type_fn: HashMap<String, usize>,
    // Detailed misses for triage.
    misses: Vec<String>,
    false_alarms: Vec<String>,
}

impl ArmMetrics {
    fn new(name: &str, samples: &[Sample]) -> Self {
        let n_true = samples.iter().filter(|s| !s.is_false()).count();
        let n_false = samples.iter().filter(|s| s.is_false()).count();
        Self {
            arm_name: name.to_string(),
            n_samples: samples.len(),
            n_true,
            n_false,
            ..Default::default()
        }
    }

    fn record(&mut self, sample: &Sample, result: &ScanResultData, latency_ms: u128) {
        let warned = !result.warnings.is_empty();
        self.latencies_ms.push(latency_ms);
        if result.docs_assisted {
            self.docs_assisted_hits += 1;
        }
        // docs_cited_hits: L3 verdict reasons surface in `result.warnings`
        // via `aggregate_claims` (mod.rs:3693). The citation-forcing gate
        // (l3_per_claim.rs:750) requires a `[DOC_N]` or `[CITE: ...]`
        // marker on every verdict. A `[DOC_N]` hit means L3 actually
        // grounded its claim in a retrieved doc chunk — the citation-
        // forcing pipeline's observable effect.
        if result.warnings.iter().any(|w| w.contains("[DOC_")) {
            self.docs_cited_hits += 1;
        }
        if sample.is_false() {
            // FALSE sample: scanner SHOULD warn.
            if warned {
                self.tp += 1;
                *self.per_lang_tp.entry(sample.language.clone()).or_default() += 1;
                *self
                    .per_type_tp
                    .entry(sample.claim_type.clone())
                    .or_default() += 1;
            } else {
                self.fn_ += 1;
                *self.per_lang_fn.entry(sample.language.clone()).or_default() += 1;
                *self
                    .per_type_fn
                    .entry(sample.claim_type.clone())
                    .or_default() += 1;
                self.misses.push(sample.id.clone());
            }
        } else {
            // TRUE sample: scanner should NOT warn.
            if warned {
                self.fp += 1;
                self.false_alarms.push(sample.id.clone());
            } else {
                self.tn += 1;
            }
        }
    }

    fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_;
        if denom == 0 {
            return f64::NAN;
        }
        self.tp as f64 / denom as f64
    }

    fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            return f64::NAN;
        }
        self.tp as f64 / denom as f64
    }

    fn fp_rate(&self) -> f64 {
        let denom = self.fp + self.tn;
        if denom == 0 {
            return f64::NAN;
        }
        self.fp as f64 / denom as f64
    }

    fn warning_emission_rate(&self) -> f64 {
        // Of all FALSE samples, fraction where ≥1 user-visible warning surfaced.
        if self.n_false == 0 {
            return f64::NAN;
        }
        self.tp as f64 / self.n_false as f64
    }

    fn pct(&self, p: usize) -> f64 {
        let total = self.latencies_ms.len();
        if total == 0 {
            return 0.0;
        }
        let idx = ((p as f64 / 100.0) * (total as f64)).ceil() as usize;
        let idx = idx.clamp(1, total);
        let mut sorted = self.latencies_ms.clone();
        sorted.sort_unstable();
        sorted[idx - 1] as f64
    }

    fn lang_recall(&self, lang: &str) -> f64 {
        let tp = self.per_lang_tp.get(lang).copied().unwrap_or(0);
        let fn_ = self.per_lang_fn.get(lang).copied().unwrap_or(0);
        let denom = tp + fn_;
        if denom == 0 {
            return f64::NAN;
        }
        tp as f64 / denom as f64
    }

    fn type_recall(&self, t: &str) -> f64 {
        let tp = self.per_type_tp.get(t).copied().unwrap_or(0);
        let fn_ = self.per_type_fn.get(t).copied().unwrap_or(0);
        let denom = tp + fn_;
        if denom == 0 {
            return f64::NAN;
        }
        tp as f64 / denom as f64
    }
}

// ─── Config swap (A/B methodology) ───────────────────────────────────
//
// The real A/B knob is `ANUBIS_L3_DOCS_IN_PROMPT`, read per-call by
// `scanner::build_library_docs_fallback`. To swap arms we:
//   1. Capture the prior value of `USERPROFILE`, `HOME`, and
//      `ANUBIS_L3_DOCS_IN_PROMPT` so we can restore them after the arm.
//   2. Create a tempdir and write a marker `~/.anubis/config.yaml` (the
//      YAML records the arm name for log inspection; `ScannerConfig` has
//      no `doc_grounding` field so the YAML value is informational only).
//   3. Override the env vars: home → tempdir, kill switch → "0" (OFF arm)
//      or "1" (LAZY arm).
//   4. Run all samples in this arm.
//   5. Restore the original env vars.
//
// SAFETY: This test runs as a single #[tokio::test]; both arms are executed
// serially within the one test function so the env var swap is race-free.

struct HomeGuard {
    prev_userprofile: Option<std::ffi::OsString>,
    prev_home: Option<std::ffi::OsString>,
    prev_docs_kill_switch: Option<std::ffi::OsString>,
}

impl HomeGuard {
    fn capture() -> Self {
        // SAFETY: tests in this file are gated to a single serial test
        // function (see `doc_injection_bench_ab` below). No other test in
        // this binary touches USERPROFILE/HOME/ANUBIS_L3_DOCS_IN_PROMPT.
        Self {
            prev_userprofile: std::env::var_os("USERPROFILE"),
            prev_home: std::env::var_os("HOME"),
            prev_docs_kill_switch: std::env::var_os("ANUBIS_L3_DOCS_IN_PROMPT"),
        }
    }

    fn set(&self, home: &std::path::Path, docs_kill_switch: &str) {
        // SAFETY: see capture() comment.
        std::env::set_var("USERPROFILE", home);
        std::env::set_var("HOME", home);
        // Pin rustup's toolchain resolution to the REAL home. rustup resolves
        // its default toolchain via $RUSTUP_HOME (falls back to $HOME/.rustup)
        // — the redirected HOME above makes `rustc` (a rustup shim) fail with
        // "rustup could not choose a version of rustc to run", silently
        // killing the Rust compiler gate for every sample.
        if std::env::var_os("RUSTUP_HOME").is_none() {
            if let Some(real) = &self.prev_userprofile {
                let rustup_home = std::path::Path::new(real).join(".rustup");
                if rustup_home.is_dir() {
                    std::env::set_var("RUSTUP_HOME", &rustup_home);
                }
            }
        }
        // Kill switch: "0" disables L3 docs injection (OFF arm baseline);
        // "1" preserves default behavior (LAZY arm treatment).
        std::env::set_var("ANUBIS_L3_DOCS_IN_PROMPT", docs_kill_switch);
    }

    fn restore(self) {
        // SAFETY: see capture() comment.
        match self.prev_userprofile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }
        match self.prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match self.prev_docs_kill_switch {
            Some(v) => std::env::set_var("ANUBIS_L3_DOCS_IN_PROMPT", v),
            None => std::env::remove_var("ANUBIS_L3_DOCS_IN_PROMPT"),
        }
    }
}

fn write_arm_config(home: &std::path::Path, arm_label: &str) -> PathBuf {
    let anubis_dir = home.join(".anubis");
    fs::create_dir_all(&anubis_dir).expect("create .anubis dir");
    let cfg_path = anubis_dir.join("config.yaml");

    // The YAML records scanner endpoint + arm label for log readability.
    // `scanner.doc_grounding` is NOT a real ScannerConfig field — it is
    // ignored by serde (no `deny_unknown_fields`), kept here only as an
    // audit marker. The actual A/B swap is the env var set in HomeGuard.
    let api_key = std::env::var("DELULU_LLM_API_KEY").unwrap_or_default();
    let (model, base_url) = resolve_model_and_base_url();

    let yaml = format!(
        "proxy:\n  host: 127.0.0.1\n  port: 7878\nscanner:\n  model: {model}\n  base_url: {base_url}\n  api_key: {api_key}\n  # arm_label is informational only — ScannerConfig has no doc_grounding field.\n  # The real A/B knob is the ANUBIS_L3_DOCS_IN_PROMPT env var.\n  arm_label: {arm_label}\n"
    );
    fs::write(&cfg_path, yaml)
        .unwrap_or_else(|e| panic!("write {}: {}", cfg_path.display(), e));
    cfg_path
}

// ─── Symbol cache seeding (mirrors recall_corpus / delulu_compare) ────

fn seed_bundle() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures");
    if let Ok(c) = anubis_daemon::symbols::cache::SymbolCache::open() {
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_bulk.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_spring.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_rust_extended.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_npm.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_npm2.jsonl"));
    }
}

// ─── Model resolution (DOC_INJECTION_MODEL > DELULU_LLM_MODEL > default) ──
//
// Priority:
//   1. `DOC_INJECTION_MODEL` — preferred for this bench. When the value
//      names an Ollama-served model (gemma*/qwen*/llama*), the base_url
//      auto-points at `http://localhost:11434/v1` unless overridden via
//      `DELULU_LLM_BASE_URL`. This is the DOD-target path: weak-local
//      models are where the citation-forcing redesign is supposed to lift
//      recall, so the bench makes them one-env-var easy.
//   2. `DELULU_LLM_MODEL` + `DELULU_LLM_BASE_URL` — legacy pair (kept so
//      existing scripts that already set them keep working).
//   3. Defaults — `glm-4.7-flash` (the daemon's prior default scanner
//      model) against the hosted z.ai endpoint.
//
// `DOC_INJECTION_MODEL` overriding `DELULU_LLM_MODEL` means a single env
// var is enough to switch the entire pipeline; no need to remember to also
// flip the base_url when pointing at Ollama.

const DEFAULT_BENCH_MODEL: &str = "glm-4.7-flash";
const DEFAULT_BENCH_BASE_URL: &str = "https://api.z.ai/api/coding/paas/v4";
const OLLAMA_DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";

fn is_ollama_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower.starts_with("gemma")
        || lower.starts_with("qwen")
        || lower.starts_with("llama")
}

fn resolve_model_and_base_url() -> (String, String) {
    if let Ok(m) = std::env::var("DOC_INJECTION_MODEL") {
        if !m.trim().is_empty() {
            let base_url = std::env::var("DELULU_LLM_BASE_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| {
                    if is_ollama_model(&m) {
                        OLLAMA_DEFAULT_BASE_URL.to_string()
                    } else {
                        DEFAULT_BENCH_BASE_URL.to_string()
                    }
                });
            return (m, base_url);
        }
    }
    let model = std::env::var("DELULU_LLM_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BENCH_MODEL.to_string());
    let base_url = std::env::var("DELULU_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BENCH_BASE_URL.to_string());
    (model, base_url)
}

// ─── ScanContext construction ────────────────────────────────────────

/// Scaffold a toolchain-visible project in the benchmark tempdir so compiler
/// gates fire (design: `.omo/plans/compiler-gates-fix.md` Fix A).
///
/// - TS: junction `node_modules/typescript` → daemon-rs's local install, plus
///   a minimal package.json, so `typescript_available(project_root)` resolves
///   and `verify_ts_methods_via_compiler` can emit TS2339 catches.
/// - Rust: minimal Cargo workspace so rustc/cargo metadata resolve instead of
///   hitting `FetchWorkspaceError` on a bare tempdir.
fn scaffold_project_root(root: &std::path::Path) {
    use std::path::Path;

    // ── TS scaffold ────────────────────────────────────────────────────
    let _ = std::fs::write(
        root.join("package.json"),
        r#"{"name":"bench","private":true}"#,
    );

    let local_ts = std::env::current_dir()
        .map(|d| d.join("node_modules").join("typescript"))
        .ok()
        .filter(|p| p.is_dir());
    if let Some(src) = local_ts {
        let dst = root.join("node_modules").join("typescript");
        if !dst.exists() {
            let _ = std::fs::create_dir_all(root.join("node_modules"));
            // Junction first (cheap), recursive-copy fallback.
            let ok = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&dst)
                .arg(&src)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                copy_dir_recursive(&src, &dst);
            }
        }
    }

    // ── Rust scaffold ──────────────────────────────────────────────────
    // DELIBERATELY NO Cargo.toml: an empty manifest flips the rustc gate's
    // adaptive E0432/E0433 filter to "capture all external crate misses",
    // which FPs on legitimate `use tokio` snippets (deps unresolved in a
    // bare manifest). The primary gate compiles single-file in its own
    // work_dir and does not need a manifest — E0599/E0609 method errors
    // fire without cargo context.
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(src) {
        for entry in entries.flatten() {
            let path = entry.path();
            let target = dst.join(entry.file_name());
            if path.is_dir() {
                let _ = std::fs::create_dir_all(&target);
                copy_dir_recursive(&path, &target);
            } else {
                let _ = std::fs::copy(&path, &target);
            }
        }
    }
}

fn build_ctx(project_root: &std::path::Path) -> ScanContext {
    let (model, base_url) = resolve_model_and_base_url();
    ScanContext {
        project_root: project_root.to_string_lossy().to_string(),
        logic_model: model,
        llm_base_url: base_url,
        llm_api_key: if std::env::var("DELULU_FORGE_ONLY").is_ok() {
            String::new()
        } else {
            std::env::var("DELULU_LLM_API_KEY").unwrap_or_default()
        },
        llm_extra_headers: vec![],
        request_class: String::new(),
        language: String::new(),
        cancel: tokio_util::sync::CancellationToken::new(),
    }
}

// ─── Per-sample scan ─────────────────────────────────────────────────

async fn scan_sample(sample: &Sample, ctx: &ScanContext) -> (ScanResultData, u128) {
    let content = sample.render();
    let started = Instant::now();
    let result = scan_response(&content, ctx).await;
    let latency_ms = started.elapsed().as_millis();
    (result, latency_ms)
}

// ─── Arm runner ──────────────────────────────────────────────────────

async fn run_arm(
    arm_name: &str,
    doc_grounding: &str,
    samples: &[Sample],
) -> ArmMetrics {
    // Kill switch is the REAL A/B knob — `ScannerConfig` has no
    // `doc_grounding` field (the YAML value is informational only).
    // `build_library_docs_fallback` reads `ANUBIS_L3_DOCS_IN_PROMPT`
    // on every call: "0" → strip docs, anything else (incl. "1") → inject.
    let docs_kill_switch = match doc_grounding {
        "off" => "0",
        "lazy" => "1",
        other => panic!(
            "unknown arm doc_grounding={other:?} (expected \"off\" or \"lazy\")"
        ),
    };

    let home_tmp = tempfile::tempdir().expect("tempdir for arm home");
    let _cfg_path = write_arm_config(home_tmp.path(), arm_name);

    let guard = HomeGuard::capture();
    guard.set(home_tmp.path(), docs_kill_switch);

    // Re-read config so the tempdir's `.anubis/config.yaml` is exercised.
    // (`scanner.doc_grounding` does NOT exist on this struct — the YAML
    // value is purely informational. The kill switch above is what swaps
    // behavior between arms.)
    let cfg = anubis_daemon::config::load_config();
    let (resolved_model, resolved_base_url) = resolve_model_and_base_url();
    eprintln!(
        "=== ARM {arm_name} (kill_switch={docs_kill_switch} doc_grounding_yaml={doc_grounding:?}) | model={resolved_model} | base_url={resolved_base_url} | api_key_len={} | L3={}",
        cfg.scanner.api_key.len(),
        if cfg.scanner.api_key.is_empty() { "OFF" } else { "ON" }
    );

    let mut metrics = ArmMetrics::new(arm_name, samples);

    // Use a shared per-arm project tempdir so session_symbols accumulate
    // across samples the way they do in a real agent session.
    let project_tmp = tempfile::tempdir().expect("tempdir for project root");
    scaffold_project_root(project_tmp.path());
    let ctx = build_ctx(project_tmp.path());

    for sample in samples {
        let (result, latency_ms) = scan_sample(sample, &ctx).await;
        let warned = !result.warnings.is_empty();
        let docs_cited = result.warnings.iter().any(|w| w.contains("[DOC_"));
        eprintln!(
            "  [{arm_name:<9}] {:<32} lang={:<11} truth={:<5} warned={:<5} docs_assisted={:<5} docs_cited={:<5} latency_ms={latency_ms:<5} warns={}",
            sample.id,
            sample.language,
            sample.ground_truth,
            warned,
            result.docs_assisted,
            docs_cited,
            result.warnings.len()
        );
        if warned && sample.is_false() {
            for w in &result.warnings {
                eprintln!("      + {w}");
            }
        }
        if warned && !sample.is_false() {
            for w in &result.warnings {
                eprintln!("      ! FP {w}");
            }
        }
        metrics.record(sample, &result, latency_ms);
    }

    guard.restore();
    metrics
}

// ─── Metric report ───────────────────────────────────────────────────

fn print_arm_report(m: &ArmMetrics) {
    let recall = m.recall();
    let precision = m.precision();
    let fp_rate = m.fp_rate();
    let emission = m.warning_emission_rate();
    let p50 = m.pct(50);
    let p95 = m.pct(95);

    eprintln!();
    eprintln!("── ARM {} SUMMARY ──────────────────────────────────────────", m.arm_name);
    eprintln!(
        "  samples      : {} (TRUE={} FALSE={})",
        m.n_samples, m.n_true, m.n_false
    );
    eprintln!(
        "  confusion    : TP={} FN={} FP={} TN={} (total verdicts={})",
        m.tp,
        m.fn_,
        m.fp,
        m.tn,
        m.tp + m.fn_ + m.fp + m.tn
    );
    eprintln!(
        "  recall       : {:.1}%  (target ≥60% weak / ≥80% strong)",
        recall * 100.0
    );
    eprintln!(
        "  precision    : {:.1}%  (target ≥90%)",
        precision * 100.0
    );
    eprintln!(
        "  fp_rate      : {:.1}%  (target ≤10%)",
        fp_rate * 100.0
    );
    eprintln!(
        "  warn_emission: {:.1}%  (target ≥80%)",
        emission * 100.0
    );
    eprintln!(
        "  docs_assisted: {} / {} samples hit the doc-retrieval path (scanner flag)",
        m.docs_assisted_hits,
        m.n_samples
    );
    eprintln!(
        "  docs_cited   : {} / {} samples had L3 verdicts grounded in [DOC_N] chunks",
        m.docs_cited_hits,
        m.n_samples
    );
    eprintln!(
        "  latency p50  : {:.0} ms   p95: {:.0} ms",
        p50, p95
    );
    eprintln!("  per-language recall:");
    for lang in ["python", "typescript", "rust"] {
        eprintln!("    {lang:<11} {:.1}%", m.lang_recall(lang) * 100.0);
    }
    eprintln!("  per-claim-type recall:");
    for t in ["api_existence", "behavioral"] {
        eprintln!("    {t:<14} {:.1}%", m.type_recall(t) * 100.0);
    }
    if !m.misses.is_empty() {
        eprintln!(
            "  FN misses ({}): {}",
            m.misses.len(),
            m.misses.join(", ")
        );
    }
    if !m.false_alarms.is_empty() {
        eprintln!(
            "  FP alarms ({}): {}",
            m.false_alarms.len(),
            m.false_alarms.join(", ")
        );
    }
    eprintln!();
}

fn print_delta_report(off: &ArmMetrics, lazy: &ArmMetrics) {
    let d_recall = (lazy.recall() - off.recall()) * 100.0;
    let d_precision = (lazy.precision() - off.precision()) * 100.0;
    let d_emission = (lazy.warning_emission_rate() - off.warning_emission_rate()) * 100.0;
    let d_docs = lazy.docs_assisted_hits as i64 - off.docs_assisted_hits as i64;
    let d_cited = lazy.docs_cited_hits as i64 - off.docs_cited_hits as i64;

    eprintln!("── DELTA (WITH_DOCS − NO_DOCS) ─────────────────────────────");
    eprintln!(
        "  recall       : {:+.1} pp   ({:.1}% → {:.1}%)",
        d_recall,
        off.recall() * 100.0,
        lazy.recall() * 100.0
    );
    eprintln!(
        "  precision    : {:+.1} pp   ({:.1}% → {:.1}%)",
        d_precision,
        off.precision() * 100.0,
        lazy.precision() * 100.0
    );
    eprintln!(
        "  warn_emission: {:+.1} pp   ({:.1}% → {:.1}%)",
        d_emission,
        off.warning_emission_rate() * 100.0,
        lazy.warning_emission_rate() * 100.0
    );
    eprintln!(
        "  docs_assisted: {:+} samples  ({} → {})  [retrieval-path signal]",
        d_docs, off.docs_assisted_hits, lazy.docs_assisted_hits
    );
    eprintln!(
        "  docs_cited   : {:+} samples  ({} → {})  [L3 grounded in [DOC_N] chunks]",
        d_cited, off.docs_cited_hits, lazy.docs_cited_hits
    );
    eprintln!();
    eprintln!(
        "  interpretation: doc grounding is {} on this corpus",
        if d_recall > 1.0 {
            "HELPING (recall lifted)"
        } else if d_recall < -1.0 {
            "HURTING (recall dropped — investigate)"
        } else {
            "NEUTRAL (no measurable effect)"
        }
    );
    eprintln!();
}

// ─── Arm selection (env DOC_INJECTION_ARM) ───────────────────────────

fn should_run(arm: &str) -> bool {
    let v = std::env::var("DOC_INJECTION_ARM").unwrap_or_else(|_| "both".to_string());
    let v = v.trim().to_ascii_lowercase();
    // Accept both the legacy aliases (off|lazy) and the v2 names
    // (no_docs|with_docs) so existing scripts keep working.
    let aliased = match v.as_str() {
        "no_docs" => "off",
        "with_docs" => "lazy",
        other => other,
    };
    match aliased {
        "both" => true,
        _ => aliased == arm,
    }
}

// ─── Test entrypoint ─────────────────────────────────────────────────
//
// Single test, serial arms — env var swap is process-global so we cannot
// parallelize arms. Per-sample scans run sequentially within each arm.

#[tokio::test]
async fn doc_injection_bench_ab() {
    seed_bundle();
    let samples = load_samples();
    eprintln!();
    eprintln!(
        "==================================================================="
    );
    eprintln!(
        " doc-injection v2 benchmark — {} samples (py={}, ts={}, rs={})",
        samples.len(),
        samples.iter().filter(|s| s.language == "python").count(),
        samples
            .iter()
            .filter(|s| s.language == "typescript")
            .count(),
        samples.iter().filter(|s| s.language == "rust").count(),
    );
    eprintln!(
        " truth: TRUE={} FALSE={}",
        samples.iter().filter(|s| !s.is_false()).count(),
        samples.iter().filter(|s| s.is_false()).count()
    );
    eprintln!(
        " claim_type: api={} behav={}",
        samples
            .iter()
            .filter(|s| s.claim_type == "api_existence")
            .count(),
        samples
            .iter()
            .filter(|s| s.claim_type == "behavioral")
            .count()
    );
    eprintln!(
        "==================================================================="
    );

    let mut off_metrics: Option<ArmMetrics> = None;
    let mut lazy_metrics: Option<ArmMetrics> = None;

    if should_run("off") {
        off_metrics = Some(run_arm("NO_DOCS", "off", &samples).await);
        print_arm_report(off_metrics.as_ref().unwrap());
    }
    if should_run("lazy") {
        lazy_metrics = Some(run_arm("WITH_DOCS", "lazy", &samples).await);
        print_arm_report(lazy_metrics.as_ref().unwrap());
    }

    if let (Some(off), Some(lazy)) = (off_metrics.as_ref(), lazy_metrics.as_ref()) {
        print_delta_report(off, lazy);
    }

    // ── Hard sanity gates ────────────────────────────────────────────
    // Fail only when the scanner is provably broken. Soft targets are
    // reported above as WARN, not asserted.
    for (name, m) in [
        ("NO_DOCS", off_metrics.as_ref()),
        ("WITH_DOCS", lazy_metrics.as_ref()),
    ] {
        if let Some(m) = m {
            // Zero verdicts on FALSE samples → scanner is a no-op for this
            // corpus (v1 condition). Hard fail so it's impossible to miss.
            assert!(
                m.tp + m.fn_ > 0,
                "ARM {}: scanner produced 0 verdicts on {} FALSE samples — \
                 broken. Was the corpus loaded? Is L3 armed?",
                name,
                m.n_false
            );
            assert!(
                m.tp > 0,
                "ARM {}: scanner caught 0/{} FALSE samples — no-op recall. \
                 Same failure mode as v1 benchmark.",
                name,
                m.n_false
            );
        }
    }

    // ── Soft target check ────────────────────────────────────────────
    if let Some(lazy) = lazy_metrics.as_ref() {
        let recall = lazy.recall();
        let precision = lazy.precision();
        let emission = lazy.warning_emission_rate();
        if recall < 0.60 {
            eprintln!(
                "⚠ WARN: LAZY recall {:.1}% < 60% target. Phase 1 fix needed.",
                recall * 100.0
            );
        }
        if precision < 0.90 {
            eprintln!(
                "⚠ WARN: LAZY precision {:.1}% < 90% target. FP risk — \
                 check held_out_rescan before Phase 1 commit.",
                precision * 100.0
            );
        }
        if emission < 0.80 {
            eprintln!(
                "⚠ WARN: LAZY warning emission {:.1}% < 80% target. \
                 aggregate_claims may be suppressing L3 flags.",
                emission * 100.0
            );
        }
    }

    eprintln!("doc_injection_bench_ab: done.");
}
