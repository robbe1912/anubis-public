//! Stress / robustness matrix for `scan_response` + read-only HTTP probes
//! against the live daemon on :7878.
//!
//! Goal: prove the scanner does NOT crash (panic) or hang (>30s) on hostile
//! input. Every scan case is wrapped in a 30s `tokio::time::timeout`; a
//! timeout or an in-band panic fails the test loudly so the failure (with
//! stack trace, run with RUST_BACKTRACE=1) lands in the report.
//!
//! Run modes (mirrors `held_out_rescan.rs::build_ctx` env contract):
//!
//!   # Full matrix, L3 off (deterministic layers only):
//!   $env:DELULU_FORGE_ONLY="1"
//!   $env:RUST_BACKTRACE="1"
//!   cargo test --release --test stress_robustness -- --nocapture
//!
//!   # 3 longest cases re-run with live L3 against local Ollama:
//!   # (DELULU_FORGE_ONLY must be UNSET)
//!   $env:DELULU_LLM_MODEL="gemma4:e4b"
//!   $env:DELULU_LLM_BASE_URL="http://localhost:11434/v1"
//!   $env:DELULU_LLM_API_KEY="ollama"
//!   cargo test --release --test stress_robustness big_input_ -- --nocapture
//!
//! The `big_input_` name prefix selects the three heaviest inputs:
//! 500KB single line, 500KB of 1-char lines, 10k distinct method calls.
//!
//! The final test probes the LIVE daemon (127.0.0.1:7878) with malformed
//! JSON, an empty POST, and a 5MB body — expecting an HTTP error status
//! (NOT connection death) — then confirms liveness via /__anubis/ping.
//! Probes are read-only requests; the daemon is never restarted or killed.

use anubis_daemon::scanner::{scan_response, ScanContext};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

const CASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a ScanContext honouring the DELULU_* env contract.
///
/// `project_root` points at a fresh empty tempdir (kept alive by the
/// returned guard) so `build_project_index` walks nothing and tests stay
/// hermetic. `request_class: "agent"` matches the real agent traffic path
/// (see pipeline_e2e_integration.rs lines 50-61).
fn make_ctx(language: &str) -> (ScanContext, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create tempdir for project_root");
    let forge_only = std::env::var("DELULU_FORGE_ONLY").is_ok();
    let llm_api_key = if forge_only {
        String::new()
    } else {
        std::env::var("DELULU_LLM_API_KEY").unwrap_or_default()
    };
    let ctx = ScanContext {
        project_root: dir.path().to_string_lossy().to_string(),
        logic_model: std::env::var("DELULU_LLM_MODEL")
            .unwrap_or_else(|_| "glm-4.7-flash".to_string()),
        llm_base_url: std::env::var("DELULU_LLM_BASE_URL")
            .unwrap_or_else(|_| "https://api.z.ai/api/coding/paas/v4".to_string()),
        llm_api_key,
        llm_extra_headers: vec![],
        request_class: "agent".to_string(),
        language: language.to_string(),
        cancel: CancellationToken::new(),
    };
    (ctx, dir)
}

/// Run one hostile input through `scan_response` under the 30s timeout and
/// print a one-line report row. Panics from inside the scanner propagate
/// (test failure = finding); a timeout panics with a HANG marker.
async fn run_case(name: &str, language: &str, input: String) {
    let (ctx, _dir_guard) = make_ctx(language);
    let started = Instant::now();
    let result = tokio::time::timeout(CASE_TIMEOUT, scan_response(&input, &ctx))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "[{name}] TIMEOUT: scan_response did not return within 30s (HANG) input_len={}",
                input.len()
            )
        });
    println!(
        "[stress] {name}: input_len={} -> RETURNED in {}ms | warnings={} scan_failed={} details={}",
        input.len(),
        started.elapsed().as_millis(),
        result.warnings.len(),
        result.scan_failed,
        result.details.len()
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Scan matrix — 14 hostile inputs
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_empty_string() {
    run_case("empty_string", "python", String::new()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_whitespace_only() {
    // Mixed ASCII + tab + full-width (U+3000) whitespace, ~60KB.
    let unit = " \t\r\n\u{3000}\u{00A0}";
    run_case("whitespace_only", "python", unit.repeat(10_000)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn big_input_single_line_500kb() {
    // One 512KB line inside a string literal — single-line regex/AST stress.
    let payload = "A".repeat(512 * 1024 - 12);
    let input = format!("value = \"{payload}\"");
    run_case("single_line_500kb", "python", input).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn big_input_one_char_lines_500kb() {
    // 262,144 lines, each exactly one char.
    let mut s = String::with_capacity(512 * 1024 + 1);
    for i in 0..(512 * 1024 / 2) {
        s.push((b'a' + (i % 26) as u8) as char);
        s.push('\n');
    }
    run_case("one_char_lines_500kb", "python", s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_unbalanced_braces() {
    // 200k unclosed opens — tree-sitter Rust parser recovery stress.
    let input = format!("fn broken() {{}}\n{}", "{".repeat(200_000));
    run_case("unbalanced_braces", "rust", input).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_unterminated_code_fences() {
    // Opened ```typescript fence, never closed — fence extractor stress.
    let mut s = String::from("Here is the code:\n```typescript\n");
    for i in 0..5_000 {
        s.push_str(&format!("const v{i} = obj{i}.method_{i}();\n"));
    }
    run_case("unterminated_code_fences", "typescript", s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_garbage_bytes_utf8_lossy() {
    // Every byte value (incl. 0x00, 0x80-0xFF) via lossy conversion ->
    // U+FFFD replacement chars scattered through ~200KB.
    let mut bytes: Vec<u8> = Vec::with_capacity(200_000);
    let mut b: u8 = 0;
    while bytes.len() < 200_000 {
        bytes.push(b);
        b = b.wrapping_add(7); // 7 coprime with 256 -> full coverage
    }
    let input = String::from_utf8_lossy(&bytes).into_owned();
    run_case("garbage_bytes_utf8_lossy", "python", input).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_nul_bytes() {
    // 100KB of NUL inside a code-ish line + NUL-terminated identifiers.
    let input = format!("data = \"{}\"\nlabel\0 = value\0()\n", "\0".repeat(100_000));
    run_case("nul_bytes", "python", input).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_rtl_unicode_emoji_identifiers() {
    // RTL override + Hebrew/Arabic + emoji in identifiers.
    let mut s = String::from("Explanation \u{202E}dlrow olleh\u{202C}:\n```python\n");
    for i in 0..2_000 {
        s.push_str(&format!(
            "\u{05D0}\u{0631}.method_\u{1F600}_{i}(); let \u{1F680}var{i} = 1\n"
        ));
    }
    s.push_str("```\n");
    run_case("rtl_unicode_emoji_identifiers", "python", s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_deep_nested_json_tool_args_500_levels() {
    // {"args":{"args":...}} nested 500 deep, then the whole thing embedded as
    // an ESCAPED JSON string (backslash-escaped quotes) — unescape stress.
    let mut node = serde_json::json!({ "leaf": 1 });
    for _ in 0..500 {
        node = serde_json::json!({ "args": node });
    }
    let nested = node.to_string();
    let escaped = serde_json::to_string(&serde_json::Value::String(nested)).expect("escape json");
    let input = format!("Tool call arguments: {escaped}");
    run_case("deep_nested_json_tool_args_500_levels", "python", input).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_single_64kb_identifier() {
    // One 65,536-char identifier used twice — tokenizer/regex boundary stress.
    let ident = "a".repeat(65_536);
    let input = format!("let {ident} = 1;\n{ident}.method();\n");
    run_case("single_64kb_identifier", "rust", input).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn big_input_ten_thousand_method_calls() {
    // 10k DISTINCT obj.method pairs — claim extraction + cache flood.
    let mut s = String::from("```python\n");
    for i in 0..10_000 {
        s.push_str(&format!("obj_{}.method_{}()\n", i, i));
    }
    s.push_str("```\n");
    run_case("ten_thousand_method_calls", "python", s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_zero_width_chars() {
    // ZWSP/ZWNJ/ZWJ/BOM inside identifiers and member chains.
    let mut s = String::new();
    for i in 0..5_000 {
        s.push_str(&format!("v\u{200B}{i} = obj\u{200C}.m\u{200D}ethod_{i}()\u{FEFF}\n"));
    }
    run_case("zero_width_chars", "typescript", s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_cr_only_line_endings() {
    // CR-only separators: Rust .lines() sees ONE ~130KB line — huge-line stress.
    let mut s = String::new();
    for i in 0..5_000 {
        s.push_str(&format!("x{i} = data_{i}.fetch_{i}()\r"));
    }
    run_case("cr_only_line_endings", "python", s).await;
}

// ─── Scaling characterization for the unbalanced-braces hang ────────────────
// 200k braces hangs >30s (see stress_unbalanced_braces). These bisect the
// growth curve so the report can state whether cost is linear or quadratic.
// 100k+ intentionally NOT tested: extrapolation says it would pin a worker
// thread for minutes.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn braces_scaling_25k() {
    let input = format!("fn broken() {{}}\n{}", "{".repeat(25_000));
    run_case("braces_scaling_25k", "rust", input).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn braces_scaling_50k() {
    let input = format!("fn broken() {{}}\n{}", "{".repeat(50_000));
    run_case("braces_scaling_50k", "rust", input).await;
}

// ────────────────────────────────────────────────────────────────────────────
// Live daemon HTTP probes (:7878, sleev-auth mode) — read-only
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_http_probes_then_liveness() {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("build reqwest client");
    let base = "http://127.0.0.1:7878";
    let completions = format!("{base}/v1/chat/completions");

    // Pre-probe liveness: daemon must be up before we can probe it.
    let ping = client
        .get(format!("{base}/__anubis/ping"))
        .send()
        .await
        .expect("pre-probe ping: daemon at 127.0.0.1:7878 not reachable");
    println!("[probe] pre-ping -> HTTP {}", ping.status());
    assert!(
        ping.status().is_success(),
        "[probe] pre-probe ping not 2xx: {}",
        ping.status()
    );

    // Probe 1: malformed JSON body. Must yield an HTTP status, not a dead
    // connection.
    match client
        .post(&completions)
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
    {
        Ok(resp) => println!("[probe] malformed-json -> HTTP {}", resp.status()),
        Err(e) => panic!("[probe] malformed-json: CONNECTION DEATH (no HTTP response): {e}"),
    }

    // Probe 2: empty POST body.
    match client
        .post(&completions)
        .header("content-type", "application/json")
        .body("")
        .send()
        .await
    {
        Ok(resp) => println!("[probe] empty-post -> HTTP {}", resp.status()),
        Err(e) => panic!("[probe] empty-post: CONNECTION DEATH (no HTTP response): {e}"),
    }

    // Probe 3: oversized 5MB body. Record transport errors rather than
    // hard-failing — servers that reject early may close mid-upload; the
    // post-probe liveness assert below is the real verdict on daemon death.
    let body = "A".repeat(5 * 1024 * 1024);
    match client
        .post(&completions)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(resp) => println!("[probe] oversized-5MB -> HTTP {}", resp.status()),
        Err(e) => println!(
            "[probe] oversized-5MB: TRANSPORT ERROR (recorded; liveness checked next): {e}"
        ),
    }

    // Post-probe liveness — the hard assert. Any HTTP response to ping
    // (including 5xx) proves the process is alive; transport error = death.
    match client.get(format!("{base}/__anubis/ping")).send().await {
        Ok(resp) => {
            let st = resp.status();
            println!("[probe] post-ping -> HTTP {st}");
            assert!(
                st.is_success(),
                "[probe] DAEMON UNHEALTHY after probes: ping = {st}"
            );
        }
        Err(e) => panic!("[probe] DAEMON DIED after probes: ping transport error: {e}"),
    }
    println!("[probe] daemon liveness VERIFIED after all probes");
}
