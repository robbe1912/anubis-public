// DELULU custom benchmark — runs samples from the delulu fork
// (E:\GitRepos\delulu\data\custom) covering C, GDScript, GDShader, tscn.
//
// Same warning-set comparison logic as delulu_compare.rs (baseline-diff
// so shared-context warnings don't count). Extends language extension
// mapping for the custom languages.
//
// Reuses the same env vars:
//   DELULU_FORGE_ONLY=1         skip L3 entirely (recommended; fast)
//   DELULU_LANG_FILTER=c        only test samples matching this language
//   DELULU_SAMPLE_LIMIT=5       cap sample count
//   DELULU_DEBUG=1              verbose warning dump per sample
//   DELULU_NO_BASELINE_DIFF=1   skip baseline-diff (single scan per side)

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anubis_daemon::scanner::{scan_response, ScanContext};
use anubis_daemon::symbols;
use serde::Deserialize;
use tempfile::TempDir;

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
    }
}

/// Map language tag to file extension. Custom languages included.
fn ext_for(lang: &str) -> &'static str {
    match lang {
        "typescript" | "javascript" => "ts",
        "python" => "py",
        "rust" => "rs",
        "go" => "go",
        "java" => "java",
        "csharp" => "cs",
        "cpp" => "cpp",
        "c" => "c",
        "gdscript" => "gd",
        "gdshader" => "gdshader",
        "tscn" => "tscn",
        _ => "txt",
    }
}

fn root(s: &S) -> Option<TempDir> {
    let e = ext_for(&s.language);
    let d = tempfile::tempdir().ok()?;
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
    fs::write(d.path().join(format!("sample.{e}")), &c).ok()?;
    Some(d)
}

fn empty_ctx(root: &str, language: &str) -> ScanContext {
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
    let root_str = r
        .as_ref()
        .map(|d| d.path().to_string_lossy().to_string())
        .unwrap_or_default();
    let ctx = empty_ctx(&root_str, &s.language);
    let forge_only = std::env::var("DELULU_FORGE_ONLY").is_ok();

    // In FORGE-only mode, only count forge: warnings (the deterministic layer).
    // In L3 mode, count everything.
    let filter = |w: &String| if forge_only { w.starts_with("forge:") } else { true };

    let no_baseline = std::env::var("DELULU_NO_BASELINE_DIFF").is_ok();

    if no_baseline {
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
        scan_response(&baseline_content, &ctx)
            .await
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

    full.difference(&baseline).cloned().collect()
}

#[tokio::test]
async fn compare_custom_samples() {
    seed_bundle();
    let txt = fs::read_to_string("tests/fixtures/delulu_custom.jsonl")
        .expect("delulu_custom.jsonl missing — run tools/custom_to_jsonl.py in delulu repo");
    let mut samples: Vec<S> = txt
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    eprintln!("[loaded] {} custom samples", samples.len());

    if let Ok(lang) = std::env::var("DELULU_LANG_FILTER") {
        let before = samples.len();
        samples.retain(|s| s.language == lang);
        eprintln!("[filter] DELULU_LANG_FILTER={lang}: {before} -> {} samples", samples.len());
    }

    if let Ok(n) = std::env::var("DELULU_SAMPLE_LIMIT") {
        if let Ok(n) = n.parse::<usize>() {
            samples.truncate(n);
        }
    }

    let (mut true_pos, mut fp_golden, mut both, mut neither) = (0, 0, 0, 0);
    let mut strict_fp_count = 0usize;
    let mut strict_fp_ids: Vec<String> = vec![];
    let mut by_lang: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let mut by_type: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let mut tp_ids = vec![];
    let mut miss_ids: Vec<(String, String)> = vec![]; // (id, lang)

    let mut idx = 0usize;
    for s in &samples {
        idx += 1;
        let h_set = warning_set(s, &s.hallucinated_completion).await;
        let g_set = warning_set(s, &s.golden_completion).await;
        let h_unique: Vec<&String> = h_set.difference(&g_set).collect();
        let g_unique: Vec<&String> = g_set.difference(&h_set).collect();

        let is_true_pos = !h_unique.is_empty();
        let is_fp_golden = !g_unique.is_empty();
        if !g_set.is_empty() {
            strict_fp_count += 1;
            strict_fp_ids.push(s.benchmark_id.clone());
        }

        if is_true_pos && is_fp_golden {
            both += 1;
        } else if is_true_pos {
            true_pos += 1;
            tp_ids.push(s.benchmark_id.clone());
        } else if is_fp_golden {
            fp_golden += 1;
        } else {
            neither += 1;
            miss_ids.push((s.benchmark_id.clone(), s.language.clone()));
        }

        let lang_entry = by_lang.entry(s.language.clone()).or_insert((0, 0));
        let type_entry = by_type.entry(s.hallucination_type.clone()).or_insert((0, 0));
        if is_true_pos {
            lang_entry.0 += 1;
            type_entry.0 += 1;
        }
        lang_entry.1 += 1;
        type_entry.1 += 1;

        if idx <= 3
            || (std::env::var("DELULU_DEBUG").is_ok() && (!h_set.is_empty() || !g_set.is_empty()))
        {
            eprintln!(
                "\n[{}] {} ({}) h_completion={:?} g_completion={:?}",
                s.benchmark_id,
                s.language,
                s.hallucination_type,
                s.hallucinated_completion,
                s.golden_completion
            );
            eprintln!("  h_set ({}):", h_set.len());
            for w in &h_set {
                eprintln!("    {}", w);
            }
            eprintln!("  g_set ({}):", g_set.len());
            for w in &g_set {
                eprintln!("    {}", w);
            }
        }
    }

    let n = samples.len();
    eprintln!("\n═══ DELULU custom benchmark results ═══");
    eprintln!(
        "Samples: {} | Languages: {:?}",
        n,
        by_lang.keys().collect::<Vec<_>>()
    );
    eprintln!(
        "TRUE positive (h_unique non-empty):  {} ({:.2}%)",
        true_pos,
        true_pos as f64 / n as f64 * 100.0
    );
    eprintln!(
        "FP on golden  (g_unique non-empty):  {} ({:.2}%)",
        fp_golden,
        fp_golden as f64 / n as f64 * 100.0
    );
    eprintln!("BOTH unique  (mixed signal):         {}", both);
    eprintln!("Neither (sets equal or empty):       {}", neither);
    eprintln!(
        "\nTRUE recall: {:.2}%",
        true_pos as f64 / n as f64 * 100.0
    );
    eprintln!(
        "TRUE FPR:   {:.2}%",
        (both + fp_golden) as f64 / n as f64 * 100.0
    );
    eprintln!(
        "Strict FP-on-golden (any g warning): {} ({:.2}%)",
        strict_fp_count,
        strict_fp_count as f64 / n as f64 * 100.0
    );
    if !strict_fp_ids.is_empty() {
        eprintln!("  Sample IDs with golden FPs:");
        for id in &strict_fp_ids {
            eprintln!("    {}", id);
        }
    }
    eprintln!("\nBy language (true_pos / total):");
    for (lang, (tp, tot)) in &by_lang {
        eprintln!(
            "  {:<12} {}/{} ({:.0}%)",
            lang,
            tp,
            tot,
            *tp as f64 / *tot as f64 * 100.0
        );
    }
    eprintln!("\nBy hallucination type (true_pos / total):");
    for (t, (tp, tot)) in &by_type {
        eprintln!(
            "  {:<20} {}/{} ({:.0}%)",
            t,
            tp,
            tot,
            *tp as f64 / *tot as f64 * 100.0
        );
    }
    if !miss_ids.is_empty() {
        eprintln!("\nMISS samples (no detection):");
        for (id, lang) in &miss_ids {
            eprintln!("  [{}] {}", lang, id);
        }
    }
}
