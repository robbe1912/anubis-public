// scan_transcript — offline post-hoc hallucination scanner.
//
// Reads a JSONL file of OpenAI chat-completion responses (one per line),
// extracts `choices[0].message.content`, and runs the Anubis scanner on
// each. No daemon required. Used by the hard E2E benchmark harness.
//
// USAGE:
//   scan_transcript <input.jsonl> [--lang <language>] [--project-root <path>]
//                   [--context-dir <dir>]
//
// OUTPUT (stdout, one JSON object per response):
//   {"index":0,"chars":1234,"warnings":[...],"risk_score":0.12,
//    "confidence":0.95,"clean":true,"details":[...]}
//
// EXIT CODE:
//   0 = scanned successfully (regardless of warnings)
//   1 = could not read input / invalid usage

use anubis_daemon::scanner::{scan_response, ScanContext};
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

/// Minimal OpenAI chat-completion response shape — only what we need to
/// extract the assistant message content.
#[derive(Deserialize)]
struct ChatCompletion {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: Value,
}

fn print_usage() {
    eprintln!(
        "scan_transcript — offline hallucination scanner for LLM transcripts\n\n\
         USAGE:\n    \
         scan_transcript <input.jsonl> [--lang <language>] [--project-root <path>]\n\n\
          ARGS:\n    \
           input.jsonl        Path to JSONL file (one OpenAI chat-completion per line)\n    \
           --lang <lang>      Optional language hint (rust, python, typescript, go, gdscript)\n    \
           --project-root     Optional project root path for symbol resolution\n    \
           --context-dir      Optional dir of tool-result text files (agent-read file\n    \
                              contents) accumulated as session symbols before scanning —\n    \
                              reproduces the live proxy's fragment-visibility suppression\n    \
           --enable-llm       Force-enable L3 (otherwise auto-enabled when config.yaml has api_key)\n\n\
         OUTPUT:\n    \
         One JSON object per response line on stdout.\n    \
         Human-readable summary on stderr at the end."
    );
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter().enumerate();
    while let Some((i, arg)) = iter.next() {
        if arg == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        std::process::exit(if args.is_empty() { 1 } else { 0 });
    }

    let input_path = PathBuf::from(&args[0]);
    let language = parse_flag(&args, "--lang").unwrap_or_default();
    let project_root = parse_flag(&args, "--project-root")
        .unwrap_or_else(|| env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());

    let contents = match fs::read_to_string(&input_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot read {}: {}", input_path.display(), e);
            std::process::exit(1);
        }
    };

    // Silence file-logging side effects from init_logging — we don't want
    // scan_transcript runs to spam ~/.anubis/anubis.log.
    // Set RUST_LOG to suppress scanner traces by default unless user overrides.
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "warn");
    }
    anubis_daemon::init_logging();

    // Read LLM config for behavioral verification (L2.5 + L3).
    // Priority: --enable-llm flag > env vars > ~/.anubis/config.yaml > empty (deterministic only).
    //
    // Auto-enable when config.yaml has scanner.api_key — reasoning-claim L3
    // bypass (Task 4) needs L3 to run for reasoning claim verification.
    // Without this auto-detection, users would have to remember `--enable-llm`
    // even with a configured API key.
    let enable_llm_flag = args.iter().any(|a| a == "--enable-llm");
    let cfg = anubis_daemon::config::load_config();
    let config_has_api_key = !cfg.scanner.api_key.is_empty();
    let mut enable_llm = enable_llm_flag || config_has_api_key;
    // Kill switch for benchmark/offline runs: deterministic layers only.
    // Empty-string env vars can't disable L3 (they fall back to config.yaml),
    // so presence of this var (any value) is the only reliable off switch.
    if env::var("ANUBIS_DISABLE_L3").is_ok() {
        enable_llm = false;
        eprintln!("[scan_transcript] L3 + behavioral verification DISABLED via ANUBIS_DISABLE_L3 (deterministic layers only)");
    }

    let (llm_api_key, mut llm_base_url, mut logic_model) = if enable_llm {
        let key = env::var("ANUBIS_LLM_API_KEY")
            .or_else(|_| env::var("DELULU_LLM_API_KEY"))
            .unwrap_or_default();
        let base = env::var("ANUBIS_LLM_BASE_URL").unwrap_or_default();
        let model = env::var("ANUBIS_LLM_MODEL").unwrap_or_default();
        if key.is_empty() {
            // Fall back to config.yaml (already loaded above).
            (cfg.scanner.api_key, cfg.scanner.base_url, cfg.scanner.model)
        } else {
            (key, base, model)
        }
    } else {
        (String::new(), String::new(), String::new())
    };

    // Config defaults: if config.yaml had api_key but base_url/model were
    // missing, fall back to scanner defaults so L3 actually runs.
    if enable_llm && !llm_api_key.is_empty() {
        if llm_base_url.is_empty() {
            llm_base_url = "https://api.z.ai/api/coding/paas/v4".to_string();
        }
        if logic_model.is_empty() {
            logic_model = "glm-4.7-flash".to_string();
        }
    }

    if enable_llm && !llm_api_key.is_empty() {
        let src = if enable_llm_flag { "--enable-llm flag" }
                  else if config_has_api_key { "config.yaml api_key" }
                  else { "env vars" };
        eprintln!(
            "[scan_transcript] LLM behavioral verification ENABLED via {} (model: {}, reasoning claims will be routed to L3)",
            src, logic_model
        );
    } else if enable_llm && llm_api_key.is_empty() {
        eprintln!(
            "[scan_transcript] L3 requested but no api_key found in env / config.yaml — reasoning claims will NOT be verified"
        );
    }

    let ctx = ScanContext {
        project_root: project_root.clone(),
        logic_model,
        llm_base_url,
        llm_api_key,
        llm_extra_headers: vec![],
        request_class: "user".to_string(),
        language: language.clone(),
        cancel: CancellationToken::new(),
    };

    // ── Context accumulation (fragment-visibility FP replay) ────────────
    // In live proxy operation, request tool results (file contents the agent
    // read) are accumulated as session symbols BEFORE response scans, so
    // symbols quoted from real project code are never flagged. Offline
    // replay must reproduce that: --context-dir holds one tool-result text
    // file per agent file-read; accumulate each into the session store
    // keyed at ctx.project_root (empty language tag = universal, matching
    // the proxy's accumulate_request_tool_symbols).
    let context_dir = parse_flag(&args, "--context-dir");
    if let Some(dir) = &context_dir {
        let dir_path = PathBuf::from(dir);
        let entries = match fs::read_dir(&dir_path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: cannot read context dir {}: {}", dir, e);
                std::process::exit(1);
            }
        };
        let mut count = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            if text.trim().is_empty() {
                continue;
            }
            anubis_daemon::scanner::project_index::accumulate_session_symbols(
                &project_root,
                &text,
                "",
            );
            count += 1;
        }
        eprintln!(
            "[scan_transcript] accumulated {} context file(s) from {} as session symbols",
            count, dir
        );
    }

    let mut total = 0usize;
    let mut with_warnings = 0usize;
    let mut total_warnings = 0usize;
    let mut idx = 0usize;

    // Collect all valid responses first so we can do two passes.
    // First pass triggers auto_fetch_missing (fire-and-forget tokio::spawn).
    // Second pass benefits from populated cache.
    let mut responses: Vec<(usize, String)> = Vec::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() { idx += 1; continue; }
        let parsed: ChatCompletion = match serde_json::from_str(line) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{}] skip (invalid JSON: {})", idx, e);
                idx += 1;
                continue;
            }
        };
        let content_str = match parsed.choices.first() {
            Some(c) => match &c.message.content {
                Value::String(s) => s.clone(),
                Value::Null => String::new(),
                other => other.to_string(),
            },
            None => String::new(),
        };
        if content_str.is_empty() { idx += 1; continue; }
        responses.push((idx, content_str));
        idx += 1;
    }

    eprintln!("Pass 1/2: warming cache ({} responses)...", responses.len());
    for (_, content) in &responses {
        let _ = scan_response(content, &ctx).await; // triggers fire-and-forget fetches
    }

    eprintln!("Waiting 15s for live API fetchers (docs.rs/pkg.go.dev/javadoc.io) to complete...");
    let warmup_secs = std::env::var("SCAN_WARMUP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    eprintln!("Waiting {}s for cache warming...", warmup_secs);
    tokio::time::sleep(std::time::Duration::from_secs(warmup_secs)).await;

    eprintln!("Pass 2/2: scanning with warmed cache...\n");

    for (idx, content) in &responses {
        let result = scan_response(content, &ctx).await;
        let chars = content.chars().count();
        let warnings_count = result.warnings.len();
        total += 1;
        total_warnings += warnings_count;
        if warnings_count > 0 {
            with_warnings += 1;
        }

        // Surface reasoning claims separately so the harness can measure
        // reasoning-claim L3 recall / FPR independently from code-claim
        // metrics. Cheap: pure text scan over the response content.
        //
        // JSON field names use `reasoning_claims` (user-facing label);
        // internally calls `extract_prose_claims` (canonical implementation
        // name retained per l3_per_claim.rs).
        let reasoning_claims = anubis_daemon::scanner::l3_per_claim::extract_prose_claims(content);
        let reasoning_count = reasoning_claims.len();

        // One JSON line per response — easy to parse from Python.
        let summary = serde_json::json!({
            "index": idx,
            "chars": chars,
            "warnings": result.warnings,
            "blocks": result.blocks,
            "details": result.details,
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "clean": result.clean,
            "scan_failed": result.scan_failed,
            "reasoning_claims_count": reasoning_count,
            "reasoning_claims": reasoning_claims,
        });
        println!("{}", summary);

        // Human-readable trace on stderr so callers can watch progress.
        if reasoning_count > 0 {
            eprintln!(
                "[{}] chars={} warnings={} risk={:.3} conf={:.3} clean={} reasoning={}",
                idx, chars, warnings_count, result.risk_score, result.confidence, result.clean, reasoning_count
            );
        } else {
            eprintln!(
                "[{}] chars={} warnings={} risk={:.3} conf={:.3} clean={}",
                idx, chars, warnings_count, result.risk_score, result.confidence, result.clean
            );
        }
        for w in &result.warnings {
            eprintln!("    - {}", w);
        }
    }

    eprintln!(
        "\nSUMMARY: scanned {} responses, {} had warnings ({} total warnings)",
        total, with_warnings, total_warnings
    );
}
