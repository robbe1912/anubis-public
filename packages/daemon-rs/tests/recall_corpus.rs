// Synthetic injection recall corpus — non-circular DELULU recall validation.
//
// 30 self-contained snippets, each Docker-verified to break (ImportError,
// AttributeError, TypeError, E0599, panic, etc.). Every snippet is a
// DETERMINISTIC hallucination, so any scanner miss = provable recall gap,
// not measurement noise.
//
// Why this exists: DELULU was used to TUNE compute_risk_score, then used to
// MEASURE recall. Held-out corpus produced 0 natural hallucinations. Recall
// was unverifiable. This corpus breaks that circularity.
//
// Layout: tests/synthetic_corpus/{l1_5,l2,l3}_samples/<id>.<ext>
// Plan:   .omo/plans/synthetic-injection-corpus.md
//
// Ship gate (asserted at end):
//   - L1.5 caught >= 7 / 10
//   - L2   caught >= 8 / 12
//   - L3   caught >= 6 / 8   (only if DELULU_LLM_API_KEY present)
//   - Total caught >= 21/30  (only if DELULU_LLM_API_KEY present)
//
// Run:
//   cargo test --test recall_corpus -- --nocapture
//   $env:DELULU_LLM_API_KEY = "<key>"   # required for L3 minimum

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anubis_daemon::scanner::{scan_response, ScanContext, ScanResultData};

// ─── Sample spec ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Layer {
    L1_5,
    L2,
    L3,
}

impl Layer {
    fn as_str(&self) -> &'static str {
        match self {
            Layer::L1_5 => "L1.5",
            Layer::L2 => "L2",
            Layer::L3 => "L3",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SampleSpec {
    id: &'static str,
    rel_path: &'static str, // relative to tests/synthetic_corpus/
    language: &'static str, // python | rust | typescript | go
    expected_layer: Layer,
    mutation: &'static str, // M1..M5, L3-*
    /// Brief human-readable description of the injected hallucination.
    description: &'static str,
}

const SAMPLES: &[SampleSpec] = &[
    // ── L1.5 (10): symbol cache / scope / fuzzy ───────────────────────
    SampleSpec { id: "py_01_cross_lib_import", rel_path: "l1_5_samples/py_01_cross_lib_import.py", language: "python", expected_layer: Layer::L1_5, mutation: "M1", description: "fabricated symbol LoginMgr in flask_login" },
    SampleSpec { id: "py_02_invented_submodule", rel_path: "l1_5_samples/py_02_invented_submodule.py", language: "python", expected_layer: Layer::L1_5, mutation: "M2", description: "invented submodule pydantic.fields_extra" },
    SampleSpec { id: "py_03_typing_io_replacement", rel_path: "l1_5_samples/py_03_typing_io_replacement.py", language: "python", expected_layer: Layer::L1_5, mutation: "M3", description: "distutils.version.LooseVersion removed in py3.12" },
    SampleSpec { id: "py_04_dunder_method_wrong", rel_path: "l1_5_samples/py_04_dunder_method_wrong.py", language: "python", expected_layer: Layer::L1_5, mutation: "M3", description: "dict.fromkeys(fill=) hallucinated kwarg" },
    SampleSpec { id: "rs_01_wrong_crate_method", rel_path: "l1_5_samples/rs_01_wrong_crate_method.rs", language: "rust", expected_layer: Layer::L1_5, mutation: "M1", description: "tokio::sync::RwLock::read_unchecked does not exist" },
    SampleSpec { id: "rs_02_invented_trait", rel_path: "l1_5_samples/rs_02_invented_trait.rs", language: "rust", expected_layer: Layer::L1_5, mutation: "M2", description: "serde::de::VisitorExt invented trait" },
    SampleSpec { id: "ts_01_wrong_named_export", rel_path: "l1_5_samples/ts_01_wrong_named_export.ts", language: "typescript", expected_layer: Layer::L1_5, mutation: "M1", description: "useState imported from react-dom (wrong pkg)" },
    SampleSpec { id: "ts_02_invented_submodule", rel_path: "l1_5_samples/ts_02_invented_submodule.ts", language: "typescript", expected_layer: Layer::L1_5, mutation: "M2", description: "import from lodashfp (no such module)" },
    SampleSpec { id: "go_01_wrong_pkg_symbol", rel_path: "l1_5_samples/go_01_wrong_pkg_symbol.go", language: "go", expected_layer: Layer::L1_5, mutation: "M1", description: "http.Client.DoJSON invented method" },
    SampleSpec { id: "go_02_invented_subpkg", rel_path: "l1_5_samples/go_02_invented_subpkg.go", language: "go", expected_layer: Layer::L1_5, mutation: "M2", description: "context.WithTimeoutOrCancel invented" },

    // ── L2 (12): FORGE AST extractors ─────────────────────────────────
    SampleSpec { id: "py_05_pandas_merge_suffices", rel_path: "l2_samples/py_05_pandas_merge_suffices.py", language: "python", expected_layer: Layer::L2, mutation: "M4", description: "pd.merge(suffices=) wrong kwarg (real: suffixes=)" },
    SampleSpec { id: "py_06_str_to_uppercase", rel_path: "l2_samples/py_06_str_to_uppercase.py", language: "python", expected_layer: Layer::L2, mutation: "M5", description: "'str'.to_uppercase() (real: upper())" },
    SampleSpec { id: "py_07_requests_timeout", rel_path: "l2_samples/py_07_requests_timeout.py", language: "python", expected_layer: Layer::L2, mutation: "M4", description: "requests.get(timeout_mode=) wrong kwarg" },
    SampleSpec { id: "py_08_builtins_invented", rel_path: "l2_samples/py_08_builtins_invented.py", language: "python", expected_layer: Layer::L2, mutation: "M5", description: "list.flatten() invented method" },
    SampleSpec { id: "rs_03_wrong_arity", rel_path: "l2_samples/rs_03_wrong_arity.rs", language: "rust", expected_layer: Layer::L2, mutation: "M4", description: "tokio::spawn(fut, \"worker\") — wrong arity" },
    SampleSpec { id: "rs_04_method_on_wrong_type", rel_path: "l2_samples/rs_04_method_on_wrong_type.rs", language: "rust", expected_layer: Layer::L2, mutation: "M5", description: "usize::unwrap_or — wrong receiver type" },
    SampleSpec { id: "rs_05_iter_wrong_method", rel_path: "l2_samples/rs_05_iter_wrong_method.rs", language: "rust", expected_layer: Layer::L2, mutation: "M5", description: "iter().map_to_string() invented method" },
    SampleSpec { id: "ts_03_array_methods", rel_path: "l2_samples/ts_03_array_methods.ts", language: "typescript", expected_layer: Layer::L2, mutation: "M5", description: "[1,2,3].sum() (real: .reduce)" },
    SampleSpec { id: "ts_04_promise_methods", rel_path: "l2_samples/ts_04_promise_methods.ts", language: "typescript", expected_layer: Layer::L2, mutation: "M5", description: "Promise.resolve().retry(3) invented" },
    SampleSpec { id: "ts_05_object_keys", rel_path: "l2_samples/ts_05_object_keys.ts", language: "typescript", expected_layer: Layer::L2, mutation: "M5", description: "Object.values().unique() invented" },
    SampleSpec { id: "go_03_wrong_arity", rel_path: "l2_samples/go_03_wrong_arity.go", language: "go", expected_layer: Layer::L2, mutation: "M4", description: "http.Get(ctx, url) — too many args" },
    SampleSpec { id: "go_04_method_on_wrong_type", rel_path: "l2_samples/go_04_method_on_wrong_type.go", language: "go", expected_layer: Layer::L2, mutation: "M5", description: "len(s).String() — int has no String method" },

    // ── L3 (8): LLM semantic judge ────────────────────────────────────
    SampleSpec { id: "py_09_semantic_async_await", rel_path: "l3_samples/py_09_semantic_async_await.py", language: "python", expected_layer: Layer::L3, mutation: "L3-await-scope", description: "await outside async function" },
    SampleSpec { id: "py_10_off_by_one_pandas", rel_path: "l3_samples/py_10_off_by_one_pandas.py", language: "python", expected_layer: Layer::L3, mutation: "L3-off-by-one", description: "df.iloc[1:-1] drops both ends" },
    SampleSpec { id: "py_11_recursion_no_base", rel_path: "l3_samples/py_11_recursion_no_base.py", language: "python", expected_layer: Layer::L3, mutation: "L3-no-base-case", description: "factorial recursion with no base case" },
    SampleSpec { id: "rs_06_lifetime_subtle", rel_path: "l3_samples/rs_06_lifetime_subtle.rs", language: "rust", expected_layer: Layer::L3, mutation: "L3-runtime-panic", description: "RefCell nested borrow_mut panics at runtime" },
    SampleSpec { id: "rs_07_drop_order_bug", rel_path: "l3_samples/rs_07_drop_order_bug.rs", language: "rust", expected_layer: Layer::L3, mutation: "L3-use-after-free", description: "borrow outlives destructor (E0713)" },
    SampleSpec { id: "ts_06_event_loop_blocking", rel_path: "l3_samples/ts_06_event_loop_blocking.ts", language: "typescript", expected_layer: Layer::L3, mutation: "L3-event-loop", description: "sync fs.readFileSync inside async handler" },
    SampleSpec { id: "ts_07_promise_unhandled", rel_path: "l3_samples/ts_07_promise_unhandled.ts", language: "typescript", expected_layer: Layer::L3, mutation: "L3-unhandled-rej", description: "Promise chain missing .catch()" },
    SampleSpec { id: "go_05_concurrency_bug", rel_path: "l3_samples/go_05_concurrency_bug.go", language: "go", expected_layer: Layer::L3, mutation: "L3-data-race", description: "concurrent map writes without mutex" },
];

const TOTAL: usize = SAMPLES.len(); // 30

// ─── Layer categorization ────────────────────────────────────────────
//
// Warning prefix → layer (per forge_pipeline.rs::classify_warning and
// src/scanner/mod.rs L3 emission at line ~2760):
//   L1.5:  cached-hallucination: / scope-hallucination: / Hallucinated API:
//          / Unverified API: / hallucinated-import: / hallucinated-method:
//          (last two from local_introspect.rs Python dir() checks, emitted
//           directly to result.warnings without the forge: wrapper)
//   L2:    forge: hallucinated-{import,method,parameter,variable,...} /
//          forge: chain-{broken,phantom-member} / forge: bare-critical-call
//   L3:    claim-hallucinated (high-conf): ...

fn warning_layer(w: &str) -> Option<Layer> {
    let trimmed = w.trim_start();
    if trimmed.starts_with("forge:") {
        return Some(Layer::L2);
    }
    if trimmed.starts_with("claim-hallucinated") {
        return Some(Layer::L3);
    }
    if trimmed.starts_with("cached-hallucination:")
        || trimmed.starts_with("scope-hallucination:")
        || trimmed.starts_with("Hallucinated API:")
        || trimmed.starts_with("Unverified API:")
        || trimmed.starts_with("hallucinated-import:")
        || trimmed.starts_with("hallucinated-import-name:")
        || trimmed.starts_with("hallucinated-method:")
        || trimmed.starts_with("hallucinated-parameter:")
        || trimmed.starts_with("hallucinated-variable:")
        || trimmed.starts_with("hallucinated-function:")
        || trimmed.starts_with("hallucinated-call:")
    {
        return Some(Layer::L1_5);
    }
    None
}

/// Classify a sample's outcome by which layers fired.
struct LayerHits {
    l1_5: bool,
    l2: bool,
    l3: bool,
    any: bool,
    /// Warnings whose prefix matched no known layer (still count toward `any`
    /// but won't credit a specific layer). Useful for debugging misses.
    uncategorized: Vec<String>,
}

fn classify(result: &ScanResultData) -> LayerHits {
    let mut l1_5 = false;
    let mut l2 = false;
    let mut l3 = false;
    let mut uncategorized = Vec::new();
    for w in &result.warnings {
        match warning_layer(w) {
            Some(Layer::L1_5) => l1_5 = true,
            Some(Layer::L2) => l2 = true,
            Some(Layer::L3) => l3 = true,
            None => uncategorized.push(w.clone()),
        }
    }
    let any = l1_5 || l2 || l3 || !result.warnings.is_empty();
    LayerHits { l1_5, l2, l3, any, uncategorized }
}

// ─── Symbol cache seeding (mirrors delulu_compare::seed_bundle) ───────

fn seed_bundle() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures");
    if let Ok(c) = anubis_daemon::symbols::cache::SymbolCache::open() {
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_bulk.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_spring.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_rust_extended.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_npm.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_npm2.jsonl"));
    }
}

// ─── ScanContext construction (matches eval_corpus.rs env contract) ──

fn ext_for(language: &str) -> &'static str {
    match language {
        "python" => "py",
        "rust" => "rs",
        "typescript" => "ts",
        "go" => "go",
        _ => "txt",
    }
}

fn fence_for(language: &str) -> &'static str {
    match language {
        "python" => "python",
        "rust" => "rust",
        "typescript" => "typescript",
        "go" => "go",
        _ => "",
    }
}

fn build_ctx(project_root: &std::path::Path) -> ScanContext {
    ScanContext {
        project_root: project_root.to_string_lossy().to_string(),
        logic_model: std::env::var("DELULU_LLM_MODEL")
            .unwrap_or_else(|_| "glm-4.7-flash".to_string()),
        llm_base_url: std::env::var("DELULU_LLM_BASE_URL")
            .unwrap_or_else(|_| "https://api.z.ai/api/coding/paas/v4".to_string()),
        // Empty key short-circuits L3 in the cascade. DELULU_FORGE_OK forces
        // empty even if DELULU_LLM_API_KEY is set (forge-only smoke mode).
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

/// Wrap a raw snippet in a markdown code fence with language hint, so
/// `extract_api_blocks_only` isolates the code the way it would from real
/// LLM output. We also write the raw source to `src.<ext>` in the tempdir
/// so the project_index builder has declarations to seed from.
fn materialize(sample: &SampleSpec, root: &std::path::Path) -> String {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("synthetic_corpus");
    let raw = fs::read_to_string(corpus_root.join(sample.rel_path))
        .unwrap_or_else(|e| panic!("read {}: {}", sample.rel_path, e));

    // Write the bare source so build_project_index sees real declarations.
    let ext = ext_for(sample.language);
    let _ = fs::write(root.join(format!("src.{ext}")), &raw);

    // Present scanner with fenced block (mimics agent markdown output).
    let lang = fence_for(sample.language);
    format!("```{lang}\n{raw}\n```\n")
}

// ─── Per-sample scan ─────────────────────────────────────────────────

async fn scan_sample(sample: &SampleSpec) -> (ScanResultData, LayerHits) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let content = materialize(sample, tmp.path());
    let ctx = build_ctx(tmp.path());
    let started = std::time::Instant::now();
    let result = scan_response(&content, &ctx).await;
    let latency_ms = started.elapsed().as_millis();
    let hits = classify(&result);
    eprintln!(
        "  {:<32} lang={:<11} mut={:<18} layer(exp={}) caught={} l1_5={} l2={} l3={} latency_ms={} warns={}",
        sample.id,
        sample.language,
        sample.mutation,
        sample.expected_layer.as_str(),
        hits.any,
        hits.l1_5,
        hits.l2,
        hits.l3,
        latency_ms,
        result.warnings.len(),
    );
    if !hits.any {
        eprintln!("    MISS — no warnings fired");
        if !result.details.is_empty() {
            eprintln!("    details: {:?}", result.details);
        }
    } else if !hits.uncategorized.is_empty() {
        eprintln!("    uncategorized warnings (no layer credit):");
        for w in &hits.uncategorized {
            eprintln!("      {w}");
        }
    }
    (result, hits)
}

// ─── Test ────────────────────────────────────────────────────────────

#[tokio::test]
async fn recall_corpus_meets_ship_gate() {
    seed_bundle();
    let has_l3 = !std::env::var("DELULU_LLM_API_KEY").unwrap_or_default().is_empty()
        && std::env::var("DELULU_FORGE_ONLY").is_err();
    eprintln!(
        "=== recall_corpus: {} samples, L3 {} ===",
        TOTAL,
        if has_l3 { "ENABLED" } else { "SKIPPED (set DELULU_LLM_API_KEY to enable)" }
    );

    let mut counts: std::collections::HashMap<Layer, (usize, usize)> = Default::default();
    *counts.entry(Layer::L1_5).or_default() = (0, 10);
    *counts.entry(Layer::L2).or_default() = (0, 12);
    *counts.entry(Layer::L3).or_default() = (0, 8);

    let mut total_caught = 0usize;
    let mut misses: Vec<&SampleSpec> = Vec::new();
    let mut wrong_layer: Vec<(&SampleSpec, Vec<&'static str>)> = Vec::new();
    let mut seen_ids: HashSet<&str> = HashSet::new();

    for sample in SAMPLES {
        assert!(seen_ids.insert(sample.id), "duplicate sample id {}", sample.id);
        let (_, hits) = scan_sample(sample).await;

        if hits.any {
            total_caught += 1;
            let entry = counts.entry(sample.expected_layer).or_insert((0, 0));
            entry.0 += 1;
        } else {
            misses.push(sample);
        }

        // Track which layers fired (for cross-layer coverage report).
        let mut fired: Vec<&'static str> = Vec::new();
        if hits.l1_5 { fired.push("L1.5"); }
        if hits.l2 { fired.push("L2"); }
        if hits.l3 { fired.push("L3"); }
        if fired.iter().all(|l| *l != sample.expected_layer.as_str()) && hits.any {
            wrong_layer.push((sample, fired));
        }
    }

    let (l1_5_caught, l1_5_total) = counts[&Layer::L1_5];
    let (l2_caught, l2_total) = counts[&Layer::L2];
    let (l3_caught, l3_total) = counts[&Layer::L3];

    eprintln!();
    eprintln!("=== SHIP GATE ===");
    eprintln!("  total caught : {total_caught}/{TOTAL}");
    eprintln!("  L1.5 caught  : {l1_5_caught}/{l1_5_total}  (gate >= 7)");
    eprintln!("  L2 caught    : {l2_caught}/{l2_total}  (gate >= 8)");
    if has_l3 {
        eprintln!("  L3 caught    : {l3_caught}/{l3_total}   (gate >= 6)");
    } else {
        eprintln!("  L3 caught    : SKIPPED (no DELULU_LLM_API_KEY)");
    }

    if !misses.is_empty() {
        eprintln!();
        eprintln!("MISSES (no warning fired):");
        for m in &misses {
            eprintln!("  {} [{}] expected={} mut={}", m.id, m.language, m.expected_layer.as_str(), m.mutation);
        }
    }
    if !wrong_layer.is_empty() {
        eprintln!();
        eprintln!("CROSS-LAYER (caught at non-expected layer — counts toward total but flags coverage overlap):");
        for (s, fired) in &wrong_layer {
            eprintln!("  {} expected={} fired={:?}", s.id, s.expected_layer.as_str(), fired);
        }
    }

    // ── Assertions ───────────────────────────────────────────────────
    // These minimums come from the plan. FN cost >> FP cost (recall bias),
    // so falling below a minimum is a real regression — fail loudly.
    assert!(
        l1_5_caught >= 7,
        "L1.5 recall regression: {l1_5_caught}/{l1_5_total} < 7. Investigate check_symbols / check_instance_calls / cache seeding."
    );
    assert!(
        l2_caught >= 8,
        "L2 recall regression: {l2_caught}/{l2_total} < 8. Investigate FORGE language extractors (forge_python, forge_rust, forge_ts, forge_go)."
    );
    if has_l3 {
        assert!(
            l3_caught >= 6,
            "L3 recall regression: {l3_caught}/{l3_total} < 6. Investigate l3_per_claim.rs prompt — but DO NOT loosen it."
        );
        assert!(
            total_caught >= 21,
            "Total recall below ship gate: {total_caught}/{TOTAL} < 21."
        );
    } else {
        // No L3: minimum achievable is L1.5 + L2 = 7 + 8 = 15.
        assert!(
            total_caught >= 15,
            "Recall below L1.5+L2 minimum: {total_caught}/{TOTAL} < 15 (without L3)."
        );
    }
}
