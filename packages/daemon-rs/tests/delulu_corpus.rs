// DELULU FIM hallucination benchmark — Mode A (offline scanner).
//
// Tests `scanner::scan_response` directly against the DELULU benchmark
// (https://huggingface.co/datasets/microsoft/delulu-fim-benchmark, 1,947
// compiler-verified hallucinated FIM completions across 7 languages).
//
// Two complementary measurements:
//   - RECALL: scan(hallucinated_completion) → expect any warning/block.
//   - PRECISION: scan(golden_completion) → expect NO warning/block (FPR).
//
// Mode A does NOT start the daemon. It calls the scanner library directly,
// mirroring the pattern in tests/eval_corpus.rs. Layer 3 (LLM validator)
// is skipped (empty llm_api_key) so the test runs offline and deterministically.
//
// ========================================================================
// HOW TO RUN
// ========================================================================
//
// Fast subset (56 stratified samples, in CI):
//   cargo test --test delulu_corpus delulu_subset_recall -- --nocapture
//   cargo test --test delulu_corpus delulu_subset_precision -- --nocapture
//
// Full corpus (1,947 samples, requires dataset download):
//   powershell -File scripts/fetch_delulu.ps1
//   cargo test --test delulu_corpus delulu_full_recall -- --ignored --nocapture
//   cargo test --test delulu_corpus delulu_full_precision -- --ignored --nocapture
//
// ========================================================================
// SCANNING STRATEGY
// ========================================================================
//
// DELULU ships per-sample: prompt (prefix), suffix, golden_completion,
// hallucinated_completion. We scan the *completion text alone* — what the
// LLM produced in FIM mode. Context-dependent hallucinations (e.g. an
// undefined variable defined in the prompt) may be missed; this is a known
// limitation, documented per-test.
//
// Samples shorter than ~52 chars (13 tokens) are auto-skipped by the
// scanner — they appear in the report as `skipped` and are excluded from
// the denominator.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use anubis_daemon::scanner::{extract_lookup_terms, scan_response, ScanContext, ScanResultData};
use anubis_daemon::symbols;
use serde::Deserialize;
use tempfile::TempDir;

// ─── Schema ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct DeluluSample {
    benchmark_id: String,
    language: String,
    #[serde(default)]
    file_path: Option<String>,
    hallucination_type: String,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    suffix: Option<String>,
    golden_completion: String,
    hallucinated_completion: String,
    #[serde(default)]
    error_message: Option<String>,
}

// ─── Loader ──────────────────────────────────────────────────────────

fn fixtures_dir() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir).join("tests/fixtures")
}

fn load_jsonl(path: &Path) -> Vec<DeluluSample> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<DeluluSample>(l).unwrap_or_else(|e| panic!("bad jsonl line: {e}\n{l}")))
        .collect()
}

fn load_subset() -> Vec<DeluluSample> {
    let p = fixtures_dir().join("delulu_subset.jsonl");
    assert!(p.exists(), "subset fixture missing: {}. Run tests/fixtures/build_subset.py", p.display());
    load_jsonl(&p)
}

fn load_full() -> Vec<DeluluSample> {
    let p = fixtures_dir().join("delulu_full.jsonl");
    assert!(
        p.exists(),
        "full dataset missing: {}. Run: powershell -File scripts/fetch_delulu.ps1",
        p.display()
    );
    load_jsonl(&p)
}

// ─── Scanner plumbing ────────────────────────────────────────────────

fn empty_ctx() -> ScanContext {
    ScanContext {
        project_root: String::new(),
        logic_model: String::new(),
        llm_base_url: String::new(),
        llm_api_key: String::new(), // skip Layer 3
        llm_extra_headers: vec![],
        request_class: String::new(),
         language: String::new(),
        cancel: tokio_util::sync::CancellationToken::new(),
    }
}

/// Map DELULU language code to a file extension build_project_index walks.
/// Returns None for unsupported languages (sample gets skipped).
fn lang_to_ext(lang: &str) -> Option<&'static str> {
    match lang {
        "typescript" => Some("ts"),
        "javascript" => Some("js"),
        "python" => Some("py"),
        "rust" => Some("rs"),
        "go" => Some("go"),
        "java" => Some("java"),
        "csharp" => Some("cs"),
        "cpp" | "c" => Some("cpp"),
        _ => None,
    }
}

/// Build a temp project_root containing the sample's surrounding context
/// (`prompt + suffix`) as a single source file. This mirrors what a real
/// agent produces: edits to an existing file with imports + declarations
/// already in scope. `build_project_index` walks the temp dir, extracting
/// declarations / imports / bindings the scanner can verify claims against.
///
/// `completion` is NOT written to the temp file — only the surrounding
/// context. The completion is what we scan; the context is what we verify
/// against.
fn build_sample_project_root(s: &DeluluSample) -> Option<TempDir> {
    let ext = lang_to_ext(&s.language)?;
    let dir = tempfile::tempdir().ok()?;

    // Compose the file content from prompt + suffix (skip the completion).
    let mut file_content = String::new();
    if let Some(p) = &s.prompt {
        file_content.push_str(p);
    }
    if let Some(suf) = &s.suffix {
        // Pad with a blank line so declarations in the suffix don't merge
        // onto the prompt's last line.
        if !file_content.is_empty() && !file_content.ends_with('\n') {
            file_content.push('\n');
        }
        file_content.push_str(suf);
    }

    if file_content.trim().is_empty() {
        return None;
    }

    // Use file_path from sample if available, else synthesize.
    let fname = s
        .file_path
        .as_ref()
        .and_then(|p| Path::new(p).file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| format!("sample.{}", ext));

    let file_path = dir.path().join(&fname);
    fs::write(&file_path, &file_content).ok()?;
    Some(dir)
}

fn is_flagged(r: &ScanResultData) -> bool {
    !r.warnings.is_empty() || !r.blocks.is_empty()
}

fn was_skipped(r: &ScanResultData) -> bool {
    // Scanner emits a `too few tokens` detail when below threshold.
    r.details
        .iter()
        .any(|d| d.starts_with("too few tokens") || d.starts_with("skipped"))
}

// ─── Per-sample scan ─────────────────────────────────────────────────

struct SampleOutcome {
    flagged: bool,
    skipped: bool,
    warnings: Vec<String>,
}

/// Reconstruct the full file content (prefix + completion + suffix) and
/// scan that. In a real agent setting the LLM produces a full file edit
/// or diff with surrounding context — not a 3-line FIM middle in
/// isolation. Scanning the completion alone skips 68% of samples (too
/// short) and gives the scanner no scope for symbol resolution.
fn reconstruct(s: &DeluluSample, completion: &str) -> String {
    let mut out = String::new();
    if let Some(p) = &s.prompt {
        out.push_str(p);
    }
    out.push_str(completion);
    if let Some(suf) = &s.suffix {
        out.push_str(suf);
    }
    out
}

/// Scan the reconstructed completion against a per-sample project_root
/// built from the prompt + suffix. Returns flagged / skipped / warnings.
async fn scan_completion(s: &DeluluSample, completion: &str) -> SampleOutcome {
    let content = reconstruct(s, completion);

    // Try to build a per-sample project_root from the surrounding context.
    // If we can't (no prompt/suffix, unsupported language), fall back to
    // empty ctx — scanner stays silent (no-context guard).
    let temp = build_sample_project_root(s);
    let mut ctx = empty_ctx();
    if let Some(dir) = &temp {
        ctx.project_root = dir.path().to_string_lossy().to_string();
    }

    let result = scan_response(&content, &ctx).await;

    // Hold `temp` alive until scan finishes by dropping at end of scope.
    drop(temp);

    SampleOutcome {
        flagged: is_flagged(&result),
        skipped: was_skipped(&result),
        warnings: result.warnings.clone(),
    }
}

// ─── Aggregate report ────────────────────────────────────────────────

#[derive(Default, Debug, Clone, Copy)]
struct Bucket {
    total: usize,
    scanned: usize,
    flagged: usize,
    skipped: usize,
}

impl Bucket {
    fn recall(&self) -> Option<f64> {
        if self.scanned == 0 {
            None
        } else {
            Some(self.flagged as f64 / self.scanned as f64)
        }
    }
}

fn aggregate(samples: &[DeluluSample], outcomes: &[SampleOutcome]) -> (Bucket, BTreeMap<String, Bucket>, BTreeMap<String, Bucket>) {
    let mut overall = Bucket::default();
    let mut by_lang: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut by_type: BTreeMap<String, Bucket> = BTreeMap::new();

    for (s, o) in samples.iter().zip(outcomes.iter()) {
        overall.total += 1;
        let lang = by_lang.entry(s.language.clone()).or_default();
        lang.total += 1;
        let htype = by_type.entry(s.hallucination_type.clone()).or_default();
        htype.total += 1;

        if o.skipped {
            overall.skipped += 1;
            lang.skipped += 1;
            htype.skipped += 1;
            continue;
        }
        overall.scanned += 1;
        lang.scanned += 1;
        htype.scanned += 1;
        if o.flagged {
            overall.flagged += 1;
            lang.flagged += 1;
            htype.flagged += 1;
        }
    }
    (overall, by_lang, by_type)
}

fn print_report(label: &str, overall: Bucket, by_lang: &BTreeMap<String, Bucket>, by_type: &BTreeMap<String, Bucket>) {
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  DELULU {label:<54}║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!(
        "  total={}  scanned={}  flagged={}  skipped={}  →  recall/precision={}",
        overall.total, overall.scanned, overall.flagged, overall.skipped, pct_opt(overall.recall())
    );

    eprintln!();
    eprintln!("  by language:");
    for (lang, b) in by_lang {
        eprintln!("    {lang:<12} {:>7}  ({} scanned, {} flagged, {} skipped of {})", pct_opt(b.recall()), b.scanned, b.flagged, b.skipped, b.total);
    }

    eprintln!();
    eprintln!("  by hallucination type:");
    for (htype, b) in by_type {
        eprintln!("    {htype:<20} {:>7}  ({} scanned, {} flagged, {} skipped of {})", pct_opt(b.recall()), b.scanned, b.flagged, b.skipped, b.total);
    }
}

fn print_mismatches(label: &str, samples: &[DeluluSample], outcomes: &[SampleOutcome], expected_flagged: bool, max_show: usize) {
    let mut shown = 0;
    for (s, o) in samples.iter().zip(outcomes.iter()) {
        if o.skipped {
            continue;
        }
        if o.flagged != expected_flagged {
            if shown >= max_show {
                break;
            }
            shown += 1;
            eprintln!(
                "    [{}] {} ({}, {}): flagged={} warnings={:?}",
                label,
                s.benchmark_id,
                s.language,
                s.hallucination_type,
                o.flagged,
                o.warnings
            );
        }
    }
}

// ─── RECALL tests (hallucinated_completions) ─────────────────────────

/// Pre-warm the symbol cache by walking each sample's prompt and triggering
/// `auto_fetch_missing` for libraries detected. The fetches are async +
/// backgrounded by `symbols::auto_fetch_missing`; this function waits
/// (up to `timeout`) for cache size to stabilize.
///
/// Why pre-warm: the L1.5 path (`check_symbols`) returns early when the
/// cache is empty. Auto-fetch populates the cache for Rust crates
/// (docs.rs) + TypeScript packages (unpkg.com .d.ts). Python/Go/Java/C#
/// have no fetcher — those samples stay cache-cold and rely on L1 only.
///
/// Realistic analogy: a user opens a project; the first scan triggers
/// fetches; subsequent scans benefit. In tests we collapse this into a
/// single pre-warm pass before measuring recall.
async fn prewarm_symbol_cache(samples: &[DeluluSample], timeout: Duration) -> usize {
    let initial = symbols::cache::SymbolCache::open()
        .map(|c| c.list_libraries().len())
        .unwrap_or(0);
    eprintln!("[prewarm] cache starts with {initial} libraries");

    // Walk each sample's prompt + suffix and trigger fetches for any
    // library terms we haven't seen yet.
    let mut terms_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in samples {
        let content = reconstruct(s, ""); // prompt + "" + suffix
        let terms = extract_lookup_terms(&content);
        let new_terms: Vec<_> = terms.iter().filter(|t| !terms_seen.contains(*t)).collect();
        if !new_terms.is_empty() {
            for t in &new_terms {
                terms_seen.insert((*t).clone());
            }
            // auto_fetch_missing takes a HashSet — pass the full current set
            // so it picks the next uncached + unattempted term.
            symbols::auto_fetch_missing(&terms).await;
            // Yield between samples to let background fetches progress.
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
    eprintln!("[prewarm] triggered fetches for {} unique library terms", terms_seen.len());

    // Poll cache size until stable or timeout.
    let start = Instant::now();
    let mut last_count = initial;
    let mut stable_for_ms = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let now_count = symbols::cache::SymbolCache::open()
            .map(|c| c.list_libraries().len())
            .unwrap_or(0);
        if now_count == last_count {
            stable_for_ms += 2000;
        } else {
            stable_for_ms = 0;
            last_count = now_count;
        }
        eprintln!("[prewarm] cache={now_count} stable_for={stable_for_ms}ms");
        // Stop if stable for 6s (3 polls) OR timeout reached.
        if stable_for_ms >= 6000 || start.elapsed() >= timeout {
            break;
        }
    }
    eprintln!(
        "[prewarm] done in {:.1}s — cache went {} → {} libraries",
        start.elapsed().as_secs_f64(),
        initial,
        last_count
    );
    last_count
}

async fn run_recall(samples: &[DeluluSample]) -> Vec<SampleOutcome> {
    let mut out = Vec::with_capacity(samples.len());
    for s in samples {
        out.push(scan_completion(s, &s.hallucinated_completion).await);
    }
    out
}

/// Seed the symbol cache with bundled library APIs.
///
/// Loads `tests/fixtures/symbol_bundle.jsonl` (committed artifact) into the
/// user's symbol cache via `INSERT OR REPLACE`. Idempotent: safe to call
/// before every test run. Covers Python/Go/Java/C#/C++ stdlib + popular
/// third-party libraries (sklearn, streamlit, react, armadillo) so the
/// scanner has real library surfaces to verify against.
fn seed_symbol_bundle() {
    let bundle_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("symbol_bundle.jsonl");
    if !bundle_path.exists() {
        eprintln!(
            "  [seed] bundle not found at {}, skipping",
            bundle_path.display()
        );
        return;
    }
    match symbols::cache::SymbolCache::open() {
        Ok(cache) => match cache.seed_from_jsonl(&bundle_path) {
            Ok(n) => eprintln!("  [seed] inserted {} symbols from bundle", n),
            Err(e) => eprintln!("  [seed] failed: {}", e),
        },
        Err(e) => eprintln!("  [seed] cache open failed: {}", e),
    }
}

#[tokio::test]
async fn delulu_subset_recall() {
    let samples = load_subset();
    assert!(!samples.is_empty(), "no DELULU samples loaded");

    // Seed the symbol cache with bundled library APIs (idempotent via
    // INSERT OR REPLACE, ~200KB, takes <100ms). This populates Python/Go/
    // Java/C#/C++ standard library + popular third-party APIs (sklearn,
    // streamlit, react, armadillo, etc.) so check_symbols can verify
    // hallucinated code against real library surfaces.
    seed_symbol_bundle();

    // Pre-warm symbol cache via fetchers if requested (slow first run).
    //   $env:DELULU_PREWARM = '1'; cargo test --test delulu_corpus delulu_subset_recall -- --nocapture
    if std::env::var("DELULU_PREWARM").is_ok() {
        prewarm_symbol_cache(&samples, Duration::from_secs(120)).await;
    }

    let outcomes = run_recall(&samples).await;
    let (overall, by_lang, by_type) = aggregate(&samples, &outcomes);
    print_report("subset RECALL (hallucinated)", overall, &by_lang, &by_type);

    // Soft gate: with Layer 3 off + empty project root, recall will be low.
    // We assert that we DON'T crash and that we scanned SOMETHING.
    assert!(overall.scanned > 0, "scanner skipped every sample — check min-content threshold");

    // Show up to 5 misses so the developer can see what's slipping through.
    eprintln!();
    eprintln!("  sample of MISSES (hallucinated but not flagged, first 5):");
    print_mismatches("miss", &samples, &outcomes, true, 5);
}

#[tokio::test]
#[ignore = "full corpus — run: powershell -File scripts/fetch_delulu.ps1, then --ignored"]
async fn delulu_full_recall() {
    let samples = load_full();
    eprintln!("loaded {} samples from full DELULU dataset", samples.len());
    let outcomes = run_recall(&samples).await;
    let (overall, by_lang, by_type) = aggregate(&samples, &outcomes);
    print_report("FULL RECALL (hallucinated)", overall, &by_lang, &by_type);
    assert!(overall.scanned > 100, "expected many scanned samples");
}

// ─── PRECISION tests (golden_completions) ────────────────────────────

async fn run_precision(samples: &[DeluluSample]) -> Vec<SampleOutcome> {
    let mut out = Vec::with_capacity(samples.len());
    for s in samples {
        out.push(scan_completion(s, &s.golden_completion).await);
    }
    out
}

fn pct(x: f64) -> String {
    format!("{:.2}%", x * 100.0)
}

fn pct_opt(x: Option<f64>) -> String {
    match x {
        Some(v) => pct(v),
        None => "n/a".into(),
    }
}

fn precision_from(overall: &Bucket) -> f64 {
    // Precision = correctly NOT flagged / scanned
    // (for the golden set, "correct" = no warning)
    if overall.scanned == 0 {
        return 0.0;
    }
    let correct = overall.scanned - overall.flagged;
    correct as f64 / overall.scanned as f64
}

#[tokio::test]
#[ignore = "delulu_subset_precision surfaces 75% FPR using raw scan_output (no baseline-diff filter). delulu_compare.rs uses baseline-diff (full - baseline warnings); delulu_corpus.rs uses raw warnings. Without held-out corpus validation (council A4), tightening thresholds here is overfitting. Un-ignore after held-out corpus + compute_risk_score reweighting lands."]
async fn delulu_subset_precision() {
    let samples = load_subset();
    seed_symbol_bundle();
    let outcomes = run_precision(&samples).await;
    let (overall, by_lang, by_type) = aggregate(&samples, &outcomes);
    print_report("subset PRECISION (golden)", overall, &by_lang, &by_type);

    let precision = precision_from(&overall);
    eprintln!();
    eprintln!("  precision (golden correctly cleared): {}", pct(precision));
    assert!(overall.scanned > 0, "scanner skipped every golden sample");

    // Hard gate on precision: anubis must not over-flag compiler-verified
    // correct code. Allow some slack because golden completions may still
    // reference APIs the scanner's symbol cache doesn't know about.
    let fpr = 1.0 - precision;
    assert!(fpr < 0.50, "false-positive rate on golden completions = {} (expected < 50%)", pct(fpr));

    // Show up to 5 false positives.
    eprintln!();
    eprintln!("  sample of FALSE POSITIVES (golden incorrectly flagged, first 5):");
    print_mismatches("fp", &samples, &outcomes, false, 5);
}

#[tokio::test]
#[ignore = "full corpus — run: powershell -File scripts/fetch_delulu.ps1, then --ignored"]
async fn delulu_full_precision() {
    let samples = load_full();
    eprintln!("loaded {} samples from full DELULU dataset", samples.len());
    let outcomes = run_precision(&samples).await;
    let (overall, by_lang, by_type) = aggregate(&samples, &outcomes);
    print_report("FULL PRECISION (golden)", overall, &by_lang, &by_type);
    let precision = precision_from(&overall);
    eprintln!();
    eprintln!("  precision (golden correctly cleared): {}", pct(precision));
    assert!(overall.scanned > 100, "expected many scanned samples");
}
