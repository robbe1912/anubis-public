// Held-out corpus rescanner: walks result dirs from anubis-benchmark repo,
// extracts agent text events from agent_output.jsonl, runs them through
// the current scanner, and prints a comparison report.
//
// Usage:
//   $env:HELD_OUT_RESULTS_DIR='E:\GitRepos\anubis-benchmark\results'
//   cargo test --release --test held_out_rescan -- --nocapture
//
// Per HELD_OUT_README.md freeze policy: this is read-only measurement.
// Findings here MUST NOT drive changes to scanner weights, skip-lists,
// introspection rules, or any scanner parameter.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anubis_daemon::scanner::{scan_response, ScanContext};
use anubis_daemon::symbols;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct AgentEvent {
    #[serde(default)]
    part: serde_json::Value,
    #[serde(rename = "type", default)]
    event_type: String,
}

/// Reconstruct the LLM response content the daemon proxy would have seen.
///
/// Includes both `text` events (LLM prose/explanations) AND `tool_use` events
/// (write/edit/multiEdit content). The daemon proxy receives the LLM's full
/// response — tool_use blocks are LLM emissions serialized as JSON, with the
/// agent's actual code in `part.state.input`. Scanning only text events misses
/// the bulk of agent-written code.
///
/// For tool_use events, we extract the input fields that contain code:
///   - write: `input.content`
///   - edit: `input.oldString` + `input.newString`
///   - multiEdit: `input.edits[].oldString` + `input.newString`
///   - bash: `input.command` (sometimes contains inline scripts)
/// Other tools (read/glob/grep) are not code-emitting — skipped.
fn load_text_events(path: &Path) -> Vec<String> {
    let mut texts = Vec::new();
    let Ok(content) = fs::read_to_string(path) else {
        return texts;
    };
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<AgentEvent>(line) else {
            continue;
        };
        match ev.event_type.as_str() {
            "text" => {
                if let Some(text) = ev.part.get("text").and_then(|t| t.as_str()) {
                    if !text.trim().is_empty() {
                        texts.push(text.to_string());
                    }
                }
            }
            "tool_use" => {
                let tool = ev.part.get("tool").and_then(|t| t.as_str()).unwrap_or("");
                let state = match ev.part.get("state") {
                    Some(s) => s,
                    None => continue,
                };
                let input = state.get("input").unwrap_or(state);
                let chunks = extract_tool_code(tool, input);
                for chunk in chunks {
                    if !chunk.trim().is_empty() {
                        texts.push(chunk);
                    }
                }
            }
            _ => {}
        }
    }
    texts
}

/// Pull code-bearing strings out of a tool_use input payload.
fn extract_tool_code(tool: &str, input: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    match tool {
        "write" => {
            if let Some(c) = input.get("content").and_then(|v| v.as_str()) {
                out.push(c.to_string());
            }
        }
        "edit" => {
            for k in ["oldString", "newString"] {
                if let Some(s) = input.get(k).and_then(|v| v.as_str()) {
                    out.push(format!("--- {k} ---\n{}", s));
                }
            }
        }
        "multiEdit" => {
            if let Some(edits) = input.get("edits").and_then(|v| v.as_array()) {
                for (i, e) in edits.iter().enumerate() {
                    for k in ["oldString", "newString"] {
                        if let Some(s) = e.get(k).and_then(|v| v.as_str()) {
                            out.push(format!("--- edit[{i}].{k} ---\n{}", s));
                        }
                    }
                }
            }
        }
        "bash" => {
            if let Some(cmd) = input.get("command").and_then(|v| v.as_str()) {
                // Inline scripts are common in bash tool calls (heredocs etc).
                if cmd.contains('\n') {
                    out.push(format!("--- bash command ---\n{}", cmd));
                }
            }
        }
        _ => {}
    }
    out
}

#[derive(Default)]
struct RunSummary {
    dir_name: String,
    bypass_anubis: bool,
    text_event_count: usize,
    warning_count: usize,
    warnings: Vec<String>,
    latency_ms: u128,
}

/// Build a ScanContext that honours Layer-3 enable/disable via env vars.
///
/// Mirrors `delulu_compare.rs::empty_ctx`: when `DELULU_FORGE_ONLY` is set OR
/// `DELULU_LLM_API_KEY` is unset/empty, L3 is skipped (empty key). Otherwise
/// L3 runs against the configured scanner-judge model.
fn build_ctx() -> ScanContext {
    let forge_only = std::env::var("DELULU_FORGE_ONLY").is_ok();
    let llm_api_key = if forge_only {
        String::new()
    } else {
        std::env::var("DELULU_LLM_API_KEY").unwrap_or_default()
    };
    ScanContext {
        project_root: String::new(),
        logic_model: std::env::var("DELULU_LLM_MODEL")
            .unwrap_or_else(|_| "glm-4.7-flash".to_string()),
        llm_base_url: std::env::var("DELULU_LLM_BASE_URL")
            .unwrap_or_else(|_| "https://api.z.ai/api/coding/paas/v4".to_string()),
        llm_api_key,
        llm_extra_headers: Vec::new(),
        request_class: String::new(),
        language: String::new(),
        cancel: tokio_util::sync::CancellationToken::new(),
    }
}

async fn scan_run(dir: &Path) -> RunSummary {
    let mut summary = RunSummary::default();
    summary.dir_name = dir.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    summary.bypass_anubis = summary.dir_name.starts_with("no-anubis-");

    let agent_path = dir.join("agent_output.jsonl");
    let texts = load_text_events(&agent_path);
    summary.text_event_count = texts.len();

    // Treat the concatenation of all text events as a single agent response.
    // This mirrors how the daemon scans a multi-event opencode stream: each
    // text chunk contributes to the cumulative response that hits the scanner.
    let combined = texts.join("\n\n");
    if combined.trim().is_empty() {
        return summary;
    }

    let ctx = build_ctx();

    let started = Instant::now();
    let result = scan_response(&combined, &ctx).await;
    summary.latency_ms = started.elapsed().as_millis();
    summary.warnings = result.warnings.clone();
    summary.warning_count = result.warnings.len();

    // Persist warnings alongside the source transcript so downstream tools
    // (llm_evaluator.py) can read them without re-running the scanner.
    // Writes to `<result_dir>/rescan-warnings.txt`, one warning per line,
    // only when at least one warning fired (empty file = clean scan).
    let warn_path = dir.join("rescan-warnings.txt");
    let body = summary.warnings.join("\n");
    let _ = fs::write(&warn_path, body);
    summary
}

fn discover_run_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        eprintln!("could not read {}", root.display());
        return dirs;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        // Match held-out-* (with or without no-anubis- prefix) OR task-* (prior
        // benchmark runs re-scanned through current scanner for FP/regression
        // measurement). Optional RESULT_PATTERN env narrows when set.
        let is_held_out = name.starts_with("held-out-multipl-")
            || name.starts_with("no-anubis-held-out-multipl-");
        let is_task = name.starts_with("task-");
        if !is_held_out && !is_task {
            continue;
        }
        if let Ok(pat) = std::env::var("RESULT_PATTERN") {
            // Support pipe-separated alternation: 'task-001|task-005' matches
            // any dir name containing one of the alternatives. Plain substring
            // when no pipe present.
            let matched = if pat.contains('|') {
                pat.split('|').any(|alt| !alt.is_empty() && name.contains(alt))
            } else {
                name.contains(&pat)
            };
            if !matched {
                continue;
            }
        }
        // Skip dirs without agent_output.jsonl (incomplete runs)
        if !path.join("agent_output.jsonl").exists() {
            continue;
        }
        dirs.push(path);
    }
    dirs
}

#[tokio::test]
async fn rescan_held_out_corpus() {
    let results_root = std::env::var("HELD_OUT_RESULTS_DIR")
        .unwrap_or_else(|_| {
            eprintln!("HELD_OUT_RESULTS_DIR not set, skipping");
            String::new()
        });
    if results_root.is_empty() {
        return;
    }

    // Seed symbol cache from daemon's standard bundle location so that
    // library lookups behave the same as production scans.
    if let Ok(cache) = symbols::cache::SymbolCache::open() {
        let home = std::env::var("USERPROFILE").unwrap_or_else(|_| String::new());
        if !home.is_empty() {
            let primary = PathBuf::from(&home).join(".anubis").join("symbol_bundle.jsonl");
            if primary.exists() {
                let _ = cache.seed_from_jsonl(&primary);
            }
            // Pick up auxiliary bundles (spring, npm, rust_extended, etc).
            if let Ok(entries) = fs::read_dir(PathBuf::from(&home).join(".anubis")) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.starts_with("symbol_bundle_") && s.ends_with(".jsonl"))
                        .unwrap_or(false)
                    {
                        let _ = cache.seed_from_jsonl(&p);
                    }
                }
            }
        }
    }

    let dirs = discover_run_dirs(Path::new(&results_root));
    if dirs.is_empty() {
        eprintln!("no held-out run dirs found under {}", results_root);
        return;
    }

    eprintln!("discovered {} run dirs", dirs.len());

    // Group by task_id + bypass flag, picking most recent run per group.
    let mut by_group: std::collections::HashMap<(String, bool), RunSummary> = Default::default();
    for dir in &dirs {
        let summary = scan_run(dir).await;
        let name = &summary.dir_name;
        let task_id = if let Some(stripped) = name.strip_prefix("no-anubis-") {
            stripped.rsplit_once('-').map(|(t, _)| t.to_string()).unwrap_or_default()
        } else {
            name.rsplit_once('-').map(|(t, _)| t.to_string()).unwrap_or_default()
        };
        let key = (task_id, summary.bypass_anubis);
        by_group.entry(key)
            .and_modify(|existing| {
                // Keep newer (lexicographically larger timestamp suffix wins).
                if summary.dir_name > existing.dir_name {
                    *existing = RunSummary { dir_name: summary.dir_name.clone(), ..Default::default() };
                }
            })
            .or_insert_with(|| RunSummary { dir_name: summary.dir_name.clone(), ..Default::default() });
    }

    // Re-scan the selected dirs.
    let mut selected: Vec<RunSummary> = Vec::new();
    for ((_, _), picked) in &by_group {
        let path = Path::new(&results_root).join(&picked.dir_name);
        let s = scan_run(&path).await;
        selected.push(s);
    }
    selected.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));

    eprintln!();
    eprintln!("=== HELD-OUT RESCAN REPORT (read-only, do not tune against) ===");
    eprintln!();
    let l3_enabled = std::env::var("DELULU_LLM_API_KEY").map(|k| !k.is_empty()).unwrap_or(false)
        && !std::env::var("DELULU_FORGE_ONLY").is_ok();
    eprintln!(
        "Layer 3: {}",
        if l3_enabled { "ENABLED (LLM judge runs)" } else { "DISABLED (forge-only)" }
    );
    eprintln!();
    eprintln!("{:<70} {:>5} {:>8} {:>10}", "DIR", "TEXT", "WARNS", "LAT_MS");
    eprintln!("{}", "-".repeat(101));
    let mut bypass_flagged = 0usize;
    let mut bypass_total = 0usize;
    let mut bypass_warnings = 0usize;
    let mut withanubis_flagged = 0usize;
    let mut withanubis_total = 0usize;
    let mut withanubis_warnings = 0usize;
    let mut all_warnings: HashSet<String> = HashSet::new();
    let mut all_latencies: Vec<u128> = Vec::new();
    for s in &selected {
        eprintln!(
            "{:<70} {:>5} {:>8} {:>10}",
            s.dir_name, s.text_event_count, s.warning_count, s.latency_ms
        );
        all_latencies.push(s.latency_ms);
        for w in &s.warnings {
            eprintln!("    - {}", w);
            all_warnings.insert(w.clone());
        }
        if s.bypass_anubis {
            bypass_total += 1;
            bypass_warnings += s.warning_count;
            if s.warning_count > 0 {
                bypass_flagged += 1;
            }
        } else {
            withanubis_total += 1;
            withanubis_warnings += s.warning_count;
            if s.warning_count > 0 {
                withanubis_flagged += 1;
            }
        }
    }
    eprintln!();
    eprintln!("=== SUMMARY ===");
    eprintln!("WITH anubis feedback (original runs): {} tasks, {} flagged, {} total warnings",
              withanubis_total, withanubis_flagged, withanubis_warnings);
    eprintln!("WITHOUT anubis feedback (bypass runs): {} tasks, {} flagged, {} total warnings",
              bypass_total, bypass_flagged, bypass_warnings);
    eprintln!();
    eprintln!("Unique warning shapes across all runs: {}", all_warnings.len());

    // Latency percentiles (p50 / p95 / p99).
    if !all_latencies.is_empty() {
        all_latencies.sort_unstable();
        let n = all_latencies.len();
        let pct = |p: f64| -> u128 {
            if n == 0 { return 0; }
            let idx = ((p * n as f64).ceil() as usize).saturating_sub(1).min(n - 1);
            all_latencies[idx]
        };
        eprintln!();
        eprintln!("Latency (ms) across {} runs: p50={} p95={} p99={} min={} max={}",
                  n, pct(0.50), pct(0.95), pct(0.99),
                  all_latencies[0], all_latencies[n - 1]);
    }
}
