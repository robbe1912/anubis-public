// DELULU diagnostic — direct warning-set comparison (no baseline needed).
//
// Strategy: compute full warning set for hallucinated vs golden. A sample
// is a TRUE positive iff hallucinated produces at least one warning that
// golden does NOT produce. This isolates the hallucination-specific signal
// — warnings that fire on both versions are shared-context noise.
//
// Logic:
//   h_set = warnings from scan(prompt + hallucinated + suffix)
//   g_set = warnings from scan(prompt + golden + suffix)
//   h_unique = h_set - g_set   (warnings only in hallucinated)
//   g_unique = g_set - h_set   (warnings only in golden)
//
//   TRUE positive:   h_unique non-empty (hallucinated caught, golden clean)
//   FP on golden:    g_unique non-empty (golden wrongly caught)
//   BOTH flagged:    h_unique and g_unique both non-empty
//   Neither:         h_set == g_set (or both empty)

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anubis_daemon::scanner::{scan_response, ScanContext};
use anubis_daemon::symbols;
use serde::Deserialize;
use tempfile::TempDir;

/// Shared language environment path — set once before sample loop.
/// For TS, points to a directory with node_modules/ installed.
static SHARED_ENV: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct S {
    benchmark_id: String,
    language: String,
    hallucination_type: String,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    suffix: Option<String>,
    hallucinated_completion: String,
    golden_completion: String,
}

fn seed_bundle() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    if let Ok(c) = symbols::cache::SymbolCache::open() {
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_bulk.jsonl"));
        let _ = c.seed_from_jsonl(&dir.join("symbol_bundle_spring.jsonl"));
    }
}

fn root(s: &S) -> Option<PathBuf> {
    let e = match s.language.as_str() {
        "typescript" => "ts",
        "python" => "py",
        "rust" => "rs",
        "go" => "go",
        "java" => "java",
        "csharp" => "cs",
        _ => "cpp",
    };

    // Build the full content for the sample file.
    let mut c = String::new();
    if let Some(p) = &s.prompt {
        c.push_str(p);
    }
    if let Some(suf) = &s.suffix {
        c.push_str(suf);
    }
    if c.trim().is_empty() {
        return None;
    }

    // Use shared env if available (packages installed), else fresh tempdir.
    if let Some(env_dir) = SHARED_ENV.get() {
        let sample_path = env_dir.join(format!("sample.{e}"));
        fs::write(&sample_path, &c).ok()?;
        Some(env_dir.clone())
    } else {
        let d = tempfile::tempdir().ok()?;
        fs::write(d.path().join(format!("sample.{e}")), &c).ok()?;
        // into_path() consumes TempDir WITHOUT deleting — sample file
        // is overwritten on each scan so no stale data accumulates.
        Some(d.into_path())
    }
}

/// Prepare a shared environment for TS samples with installed npm packages.
/// Creates a persistent directory in system temp (survives across test runs).
/// First run installs packages (~30s), subsequent runs skip (~0s).
fn prepare_language_env(samples: &[S]) {
    let has_ts = samples.iter().any(|s| s.language == "typescript");
    if !has_ts {
        return;
    }

    let env_dir = std::env::temp_dir().join("delulu-ts-env");
    let _ = fs::create_dir_all(&env_dir);

    let pkg_json_path = env_dir.join("package.json");
    let node_modules = env_dir.join("node_modules");
    let needs_install = !node_modules.exists() || !pkg_json_path.exists();

    // Write package.json with dependencies used in DELULU TS samples.
    // @apollo/client (gql), react-router-dom (routes), @testing-library/react,
    // vitest (test globals), zustand (state), react (hooks/components).
    const PKG_JSON: &str = r#"{"name":"delulu-env","version":"0.0.0","private":true,"dependencies":{"react":"^18.0.0","@apollo/client":"^3.0.0","react-router-dom":"^6.0.0","zustand":"^4.0.0"},"devDependencies":{"@types/react":"^18.0.0","@testing-library/react":"^14.0.0","vitest":"^1.0.0","typescript":"^5.0.0"}}"#;

    if needs_install {
        let _ = fs::write(&pkg_json_path, PKG_JSON);
        eprintln!("[delulu] Installing TS packages (first run, cached after)...");
        // Windows: npm is a .cmd batch file — must run via cmd /c.
        // Unix: npm is a regular executable.
        let output = if cfg!(windows) {
            std::process::Command::new("cmd")
                .arg("/c").arg("npm").arg("install")
                .arg("--silent").arg("--no-audit").arg("--no-fund")
                .arg("--legacy-peer-deps")
                .current_dir(&env_dir)
                .output()
        } else {
            std::process::Command::new("npm")
                .arg("install")
                .arg("--silent").arg("--no-audit").arg("--no-fund")
                .arg("--legacy-peer-deps")
                .current_dir(&env_dir)
                .output()
        };
        match &output {
            Ok(o) if o.status.success() => {
                eprintln!("[delulu] TS packages installed ✓");
            }
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                eprintln!("[delulu] npm install failed (exit {:?}):", o.status.code());
                eprintln!("  stdout[0..300]: {}", &stdout[..stdout.len().min(300)]);
                eprintln!("  stderr[0..300]: {}", &stderr[..stderr.len().min(300)]);
            }
            Err(e) => {
                eprintln!("[delulu] npm not found: {} (continuing without packages)", e);
            }
        }
    } else {
        eprintln!("[delulu] TS packages already installed (cache hit) ✓");
    }

    let _ = SHARED_ENV.set(env_dir);
}

fn empty_ctx(root: &str, language: &str) -> ScanContext {
    // DELULU_FORGE_ONLY=1 skips L3 entirely (empty key) instead of just
    // filtering output. L3 takes 10-20s/sample; FORGE-only mode should
    // be deterministic + fast (<1s/sample).
    let forge_only = std::env::var("DELULU_FORGE_ONLY").is_ok();
    let llm_api_key = if forge_only {
        String::new()
    } else {
        std::env::var("DELULU_LLM_API_KEY").unwrap_or_default()
    };
    ScanContext {
        project_root: root.to_string(),
        logic_model: std::env::var("DELULU_LLM_MODEL")
            .unwrap_or_else(|_| "glm-4.7-flash".to_string()),
        llm_base_url: std::env::var("DELULU_LLM_BASE_URL")
            .unwrap_or_else(|_| "https://api.z.ai/api/coding/paas/v4".to_string()),
        llm_api_key,
        llm_extra_headers: vec![],
        request_class: String::new(),
        language: language.to_string(),
        cancel: tokio_util::sync::CancellationToken::new(),
    }
}

async fn warning_set(s: &S, completion: &str) -> HashSet<String> {
    let prompt = s.prompt.clone().unwrap_or_default();
    let suffix = s.suffix.clone().unwrap_or_default();
    let r = root(s);
    let root_str = r.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let ctx = empty_ctx(&root_str, &s.language);
    let forge_only = std::env::var("DELULU_FORGE_ONLY").is_ok();

    let filter = |w: &String| if forge_only { w.starts_with("forge:") } else { true };

    // Completion-boundary-aware scope analysis via baseline-diff.
    //
    // Skipped when DELULU_NO_BASELINE_DIFF is set — used for combined
    // FORGE+L3 benchmarks where L3 is non-deterministic and baseline-diff
    // is unreliable (different L3 warnings on different runs).
    let no_baseline = std::env::var("DELULU_NO_BASELINE_DIFF").is_ok();

    if no_baseline {
        // Single scan mode — faster, used for L3 benchmarks.
        let full_content = format!("{}{}{}", prompt, completion, suffix);
        return scan_response(&full_content, &ctx)
            .await
            .warnings
            .into_iter()
            .filter(&filter)
            .collect();
    }

    let baseline_content = format!("{}{}", prompt, suffix);
    let baseline: HashSet<String> = if baseline_content.trim().is_empty() {
        HashSet::new()
    } else {
        scan_response(&baseline_content, &ctx).await
            .warnings
            .into_iter()
            .filter(&filter)
            .collect()
    };

    let full_content = format!("{}{}{}", prompt, completion, suffix);
    let full: HashSet<String> = scan_response(&full_content, &ctx)
        .await
        .warnings
        .into_iter()
        .filter(&filter)
        .collect();

    // Completion-specific = full - baseline.
    full.difference(&baseline).cloned().collect()
}

#[tokio::test]
async fn compare_flagged_sets() {
    seed_bundle();
    let has_l3 = std::env::var("DELULU_LLM_API_KEY").is_ok();
    let corpus_file = std::env::var("DELULU_CORPUS")
        .map(|c| format!("tests/fixtures/{}.jsonl", c))
        .unwrap_or_else(|_| "tests/fixtures/delulu_subset.jsonl".to_string());
    let txt = fs::read_to_string(&corpus_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", corpus_file, e));
    let mut samples: Vec<S> = txt.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();

    // Optional language filter — only test samples matching this language.
    // Applied BEFORE sample limit so DELULU_LANG_FILTER=python + LIMIT=3
    // gives first 3 Python samples, not first 3 of all (which would be cpp).
    // Useful for isolating FORGE results to Python (the only language FORGE
    // currently supports). Values: python, typescript, rust, go, java,
    // csharp, cpp.
    if let Ok(lang) = std::env::var("DELULU_LANG_FILTER") {
        let before = samples.len();
        samples.retain(|s| s.language == lang);
        eprintln!("[filter] DELULU_LANG_FILTER={lang}: {before} -> {} samples", samples.len());
    }

    // Allow limiting sample count via env var (L3 runs ~30s/sample × 2 scans).
    // Applied AFTER language filter so we limit on filtered set.
    if let Ok(n) = std::env::var("DELULU_SAMPLE_LIMIT") {
        if let Ok(n) = n.parse::<usize>() {
            samples.truncate(n);
        }
    }

    // Prepare shared package environment (npm install for TS, etc.)
    prepare_language_env(&samples);

    let (mut true_pos, mut fp_golden, mut both, mut neither) = (0, 0, 0, 0);
    // Strict FP-on-golden: any sample where golden completion produced
    // ANY warning — even if hallucinated completion produced the same
    // warning (which masks it in the g_unique metric above).
    // This is what users actually experience: correct code getting flagged.
    let mut strict_fp_count = 0usize;
    let mut strict_fp_ids: Vec<String> = vec![];
    let mut by_lang: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let mut by_type: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let mut true_pos_ids = vec![];

    let mut idx = 0usize;
    for s in &samples {
        idx += 1;
        let h_set = warning_set(s, &s.hallucinated_completion).await;
        let g_set = warning_set(s, &s.golden_completion).await;
        let h_unique: Vec<&String> = h_set.difference(&g_set).collect();
        let g_unique: Vec<&String> = g_set.difference(&h_set).collect();

        let is_true_pos = !h_unique.is_empty();
        let is_fp_golden = !g_unique.is_empty();
        // User-visible FP: golden completion produced any warning.
        // Includes cases where h_set and g_set have IDENTICAL warnings
        // (both flagged for same reason). The h_set "absorbs" the warning
        // in the difference metric, but the golden warning is still a real
        // false positive on correct code.
        if !g_set.is_empty() {
            strict_fp_count += 1;
            strict_fp_ids.push(s.benchmark_id.clone());
        }

        if is_true_pos && is_fp_golden {
            both += 1;
        } else if is_true_pos {
            true_pos += 1;
            true_pos_ids.push(s.benchmark_id.clone());
        } else if is_fp_golden {
            fp_golden += 1;
        } else {
            neither += 1;
        }

        let lang_entry = by_lang.entry(s.language.clone()).or_insert((0, 0));
        let type_entry = by_type.entry(s.hallucination_type.clone()).or_insert((0, 0));
        if is_true_pos {
            lang_entry.0 += 1;
            type_entry.0 += 1;
        }
        lang_entry.1 += 1;
        type_entry.1 += 1;

        // First 3 samples: dump warnings regardless. Also dump when DELULU_DEBUG set
        // AND there are any warnings at all.
        if idx <= 3 || (std::env::var("DELULU_DEBUG").is_ok() && (!h_set.is_empty() || !g_set.is_empty())) {
            eprintln!("\n[{}] {} ({}) h_completion={:?} g_completion={:?}",
                s.benchmark_id, s.language, s.hallucination_type,
                s.hallucinated_completion, s.golden_completion);
            eprintln!("  h_set ({}):", h_set.len());
            for w in &h_set { eprintln!("    {}", w); }
            eprintln!("  g_set ({}):", g_set.len());
            for w in &g_set { eprintln!("    {}", w); }
        }
    }

    let n = samples.len();
    eprintln!("\n═══ DELULU set-comparison results {} ═══",
        if has_l3 { "(L3 enabled)" } else { "(L3 off — local only)" });
    eprintln!("TRUE positive (h_unique non-empty):  {} ({:.2}%)", true_pos, true_pos as f64 / n as f64 * 100.0);
    eprintln!("FP on golden  (g_unique non-empty):  {} ({:.2}%)", fp_golden, fp_golden as f64 / n as f64 * 100.0);
    eprintln!("BOTH unique  (mixed signal):         {}", both);
    eprintln!("Neither (sets equal or empty):       {}", neither);
    eprintln!("\nTRUE recall: {:.2}%", true_pos as f64 / n as f64 * 100.0);
    eprintln!("TRUE FPR:   {:.2}%", (both + fp_golden) as f64 / n as f64 * 100.0);

    // Council A10: print Wilson 95% confidence intervals on recall and
    // FPR. With n=8 per language, "75% recall" is Wilson [35%, 96%] —
    // single-sample denominator swing of 12.5 percentage points. Printing
    // the interval makes the noise floor explicit so reviewers don't
    // over-index on small-n movements when comparing runs.
    let wilson = |successes: usize, total: usize| -> (f64, f64) {
        if total == 0 { return (0.0, 0.0); }
        let p = successes as f64 / total as f64;
        let n = total as f64;
        let z = 1.959963984540054; // 95% two-sided
        let denom = 1.0 + z * z / n;
        let center = (p + z * z / (2.0 * n)) / denom;
        let spread = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / denom;
        ((center - spread).max(0.0) * 100.0, (center + spread).min(1.0) * 100.0)
    };
    let (recall_lo, recall_hi) = wilson(true_pos, n);
    let (fpr_lo, fpr_hi) = wilson(both + fp_golden, n);
    eprintln!("  Wilson 95% recall CI: [{:.1}%, {:.1}%]", recall_lo, recall_hi);
    eprintln!("  Wilson 95% FPR CI:    [{:.1}%, {:.1}%]", fpr_lo, fpr_hi);

    // Strict FP-on-golden: user-visible false positives on correct code.
    // The "FP on golden" metric above UNDERCOUNTS because h_set masks g_set
    // when warnings are identical. Strict FP counts ANY golden warning as a
    // false positive, since users see warnings on correct code regardless
    // of whether hallucinated completions produced the same warning.
    eprintln!("Strict FP-on-golden (any g warning): {} ({:.2}%)", strict_fp_count, strict_fp_count as f64 / n as f64 * 100.0);
    if !strict_fp_ids.is_empty() {
        eprintln!("  Sample IDs with golden FPs:");
        for id in &strict_fp_ids { eprintln!("    {}", id); }
    }
    eprintln!("\nBy language (true_pos / total):");
    for (lang, (tp, tot)) in &by_lang {
        let (lo, hi) = wilson(*tp, *tot);
        eprintln!("  {:<12} {}/{} ({:.0}%)  Wilson 95%: [{:.0}%, {:.0}%]",
            lang, tp, tot, *tp as f64 / *tot as f64 * 100.0, lo, hi);
    }
    eprintln!("\nBy hallucination type (true_pos / total):");
    for (t, (tp, tot)) in &by_type {
        eprintln!("  {:<20} {}/{} ({:.0}%)", t, tp, tot, *tp as f64 / *tot as f64 * 100.0);
    }
    eprintln!("\nFirst 10 TRUE positive IDs:");
    for id in true_pos_ids.iter().take(10) {
        eprintln!("  {}", id);
    }
}

