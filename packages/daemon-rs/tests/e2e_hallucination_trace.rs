//! End-to-end trace test for parameter-receiver hallucinations.
//!
//! Puts a known hallucination (`text.to_camel()` — method does not exist on
//! Python `str`) through `scan_response` with each layer individually gated,
//! so the test FAILS at the FIRST broken layer instead of silently passing.
//!
//! Run with:
//!   cargo test --test e2e_hallucination_trace -- --nocapture
//!
//! Layer chain:
//!   L0: detect_language → must return "python"
//!   L1: extract_python_apis → must extract `text.to_camel` as Method call
//!   L1.5: verify_against_introspection → silent skip OK (by design)
//!   L2: run_forge_python → must emit `chain-broken` warning
//!   L2.5: cascade filter in scan_response → must NOT drop chain-broken
//!   L3: validator (optional, requires API key) → can confirm or deny
//!   Final: ScanResultData.warnings must contain chain-broken

use anubis_daemon::scanner::{
    self,
    ast_extractor::{extract_python_apis, extract_python_assignments},
    local_introspect::{detect_unresolved_receivers, verify_against_introspection},
    language_detection::detect_language,
    forge_pipeline::run_forge_pipeline,
    ScanContext,
};
use tokio_util::sync::CancellationToken;

/// Source containing three parameter-receiver hallucinations.
/// Each function takes a parameter and calls a nonexistent method on it.
const HALLUCINATED_SRC: &str = r#"
def to_snake_case(text):
    """Convert text to snake_case."""
    return text.to_snake()   # str has no to_snake() method


def to_camel_case(text):
    """Convert text to camelCase."""
    return text.to_camel()   # str has no to_camel() method


def to_kebab_case(text):
    """Convert text to kebab-case."""
    return text.to_kebab()   # str has no to_kebab() method
"#;

/// Same code but wrapped in markdown code fence — this is what Claude Code
/// actually returns. Tests that language detection + code extraction work
/// on real agent output, not just bare source.
const MARKDOWN_WRAPPED_SRC: &str = r#"I'll add another hallucinated function. The method `to_camel()` does not exist on Python `str`.

```python
def to_camel_case(text):
    """Convert text to camelCase (e.g. 'hello world' -> 'helloWorld')."""
    return text.to_camel()   # str has no to_camel() method
```

The hallucination: `text.to_camel()` — Python's `str` has no such method."#;

/// Production-shape content: Anthropic streaming response concatenates
/// text blocks AND tool_use input JSON. The hallucinated code lives
/// INSIDE a tool_use Update command's diff field, escaped as JSON
/// strings. This is what the daemon actually sees after SSE reassembly.
/// If FORGE works on MARKDOWN_WRAPPED_SRC but fails here, the bug is
/// that diff content embedded in tool_use JSON isn't reaching FORGE.
const PRODUCTION_SHAPE_SRC: &str = r#"I'll add another hallucinated case-conversion function to kebab_trigger.py. Let me add to_camel_case that calls str.to_camel() — a nonexistent method.

[TOOL_USE: Update]
{
  "filePath": "C:\\Users\\robin\\kebab_trigger.py",
  "oldString": "    return text.to_snake()   # str has no to_snake() method\n\n\nif __name__",
  "newString": "    return text.to_snake()   # str has no to_snake() method\n\n\ndef to_camel_case(text):\n    \"\"\"Convert text to camelCase (e.g. 'hello world' -> 'helloWorld').\"\"\"\n    return text.to_camel()   # str has no to_camel() method\n\n\nif __name__"
}
[END TOOL_USE]

Added to_camel_case(). The hallucination: text.to_camel() — Python's str has no such method, so it raises AttributeError. (Manual camelCase conversion would require splitting, capitalizing each part after the first, and joining.)"#;

fn make_ctx() -> ScanContext {
    ScanContext {
        project_root: std::env::temp_dir().to_string_lossy().to_string(),
        logic_model: "glm-4.7-flash".to_string(),
        llm_base_url: String::new(),
        llm_api_key: String::new(), // no L3 — deterministic layers only
        llm_extra_headers: vec![],
        request_class: "agent".to_string(),
        language: String::new(), // force auto-detection
        cancel: CancellationToken::new(),
    }
}

#[tokio::test]
async fn l0_language_detection_python() {
    let lang = detect_language(HALLUCINATED_SRC, "");
    println!("L0 detect_language(bare_src) = {:?}", lang);
    assert_eq!(lang, "python", "bare Python source must detect as python");

    let lang_md = detect_language(MARKDOWN_WRAPPED_SRC, "");
    println!("L0 detect_language(markdown_wrapped) = {:?}", lang_md);
    // Markdown-wrapped case: language detection runs on raw content.
    // If detect_language fails here, FORGE never runs in production.
    assert_eq!(
        lang_md, "python",
        "markdown-wrapped Python must detect as python — if this fails, \
         FORGE never runs and no hallucination can be caught"
    );
}

#[tokio::test]
async fn l1_extract_python_apis_captures_method_calls() {
    let calls = extract_python_apis(HALLUCINATED_SRC)
        .await
        .expect("extract_python_apis must succeed on valid Python");
    println!("L1 extracted {} calls:", calls.len());
    for c in &calls {
        println!("  kind={:?} name={} receiver={}", c.kind, c.name, c.receiver);
    }
    let has_to_snake = calls
        .iter()
        .any(|c| c.name == "to_snake" && c.receiver == "text");
    let has_to_camel = calls
        .iter()
        .any(|c| c.name == "to_camel" && c.receiver == "text");
    let has_to_kebab = calls
        .iter()
        .any(|c| c.name == "to_kebab" && c.receiver == "text");
    assert!(has_to_snake, "must extract text.to_snake method call");
    assert!(has_to_camel, "must extract text.to_camel method call");
    assert!(has_to_kebab, "must extract text.to_kebab method call");
}

#[tokio::test]
async fn l1_assignments_captures_parameters() {
    let assignments = extract_python_assignments(HALLUCINATED_SRC)
        .await
        .expect("extract_python_assignments must succeed");
    println!("L1 assignments:");
    for (k, v) in &assignments {
        println!("  {} = {}", k, v);
    }
    assert!(
        assignments.contains_key("text"),
        "parameter `text` must appear in assignments map (as <parameter>)"
    );
    assert_eq!(
        assignments.get("text"),
        Some(&"<parameter>".to_string()),
        "parameter marker must be <parameter>"
    );
}

#[tokio::test]
async fn l2_detect_unresolved_receivers_fires_on_parameters() {
    let calls = extract_python_apis(HALLUCINATED_SRC)
        .await
        .expect("extract_python_apis");
    let assignments = extract_python_assignments(HALLUCINATED_SRC)
        .await
        .expect("extract_python_assignments");
    let scope_vars: Vec<(String, String)> = Vec::new();
    // No content / no session symbols: ctor suppression (R1/R2) inactive —
    // this test asserts the parameter-receiver chain-broken path still fires.
    let warnings = detect_unresolved_receivers(
        &calls,
        &scope_vars,
        &assignments,
        "",
        &std::collections::HashSet::new(),
    );
    println!("L2 detect_unresolved_receivers emitted {} warnings:", warnings.len());
    for w in &warnings {
        println!("  {}", w);
    }
    let has_to_camel = warnings
        .iter()
        .any(|w| w.contains("text.to_camel") && w.starts_with("chain-broken"));
    assert!(
        has_to_camel,
        "must emit chain-broken for text.to_camel — if this fails, \
         detect_unresolved_receivers has a receiver-extraction regression"
    );
}

#[tokio::test]
async fn l2_run_forge_python_emits_chain_broken() {
    let scope_vars: Vec<(String, String)> = Vec::new();
    let result = run_forge_pipeline(HALLUCINATED_SRC, "python", &scope_vars, "", "")
        .await;
    println!(
        "L2 run_forge_pipeline: extracted={} hallucinated={} unknown={} warnings={}",
        result.claims_extracted,
        result.claims_hallucinated,
        result.claims_unknown,
        result.warnings.len()
    );
    for w in &result.warnings {
        println!("  warning: {}", w);
    }
    let has_chain_broken = result
        .warnings
        .iter()
        .any(|w| w.contains("chain-broken") && w.contains("to_camel"));
    assert!(
        has_chain_broken,
        "FORGE pipeline must emit chain-broken for text.to_camel — \
         if this fails, run_forge_python wiring (Step 2a) is broken"
    );
    assert!(
        result.claims_hallucinated >= 1,
        "claims_hallucinated must be >= 1 (was {})",
        result.claims_hallucinated
    );
}

#[tokio::test]
async fn l3_scan_response_end_to_end_catches_hallucination_bare() {
    let ctx = make_ctx();
    let result = scanner::scan_response(HALLUCINATED_SRC, &ctx).await;
    println!("L3 scan_response (bare):");
    println!("  clean={} risk={} confidence={}", result.clean, result.risk_score, result.confidence);
    println!("  warnings: {}", result.warnings.len());
    for w in &result.warnings {
        println!("    {}", w);
    }
    println!("  details: {}", result.details.len());
    for d in &result.details {
        println!("    {}", d);
    }
    let has_chain_broken = result
        .warnings
        .iter()
        .chain(result.details.iter())
        .any(|s| s.contains("chain-broken") && s.contains("to_camel"));
    assert!(
        has_chain_broken,
        "scan_response must surface chain-broken for text.to_camel \
         — if L2 emitted it but scan_response dropped it, the cascade \
         filter or session_defined filter is the culprit"
    );
    assert!(
        result.risk_score > 0.0,
        "risk_score must be > 0 when chain-broken fires (was {})",
        result.risk_score
    );
    assert!(
        !result.clean,
        "scan_result must not be clean when chain-broken fires"
    );
}

#[tokio::test]
async fn l3_scan_response_end_to_end_catches_hallucination_markdown() {
    // This is the CRITICAL production test — Claude Code's actual output is
    // markdown-wrapped prose + code. If scan_response catches hallucinations
    // in bare source but NOT in markdown, that's the production bug.
    let ctx = make_ctx();
    let result = scanner::scan_response(MARKDOWN_WRAPPED_SRC, &ctx).await;
    println!("L3 scan_response (markdown-wrapped):");
    println!("  clean={} risk={} confidence={}", result.clean, result.risk_score, result.confidence);
    println!("  warnings: {}", result.warnings.len());
    for w in &result.warnings {
        println!("    {}", w);
    }
    println!("  details: {}", result.details.len());
    for d in &result.details {
        println!("    {}", d);
    }
    let has_chain_broken = result
        .warnings
        .iter()
        .chain(result.details.iter())
        .any(|s| s.contains("chain-broken"));
    assert!(
        has_chain_broken,
        "scan_response must catch hallucination in markdown-wrapped Python — \
         THIS IS THE PRODUCTION BUG. If L3 (bare) passes but this fails, \
         the failure is in: detect_language, extract_code_blocks_only, \
         or the forge_content selection logic in scan_response"
    );
    assert!(
        result.risk_score > 0.0,
        "risk_score must be > 0 for markdown-wrapped hallucination (was {})",
        result.risk_score
    );
}

#[tokio::test]
async fn l0_regex_sanity_check() {
    use regex::Regex;
    let re = Regex::new(r#""(?:content|command|input|code|source|body|file_content|new_content|newString|oldString|text|args)"\s*:\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    let simple = r#"{"oldString": "hello world"}"#;
    println!("simple matches: {}", re.find_iter(simple).count());
    for cap in re.captures_iter(simple) {
        println!("  cap[1]={}", &cap[1]);
    }
    let production_like = r#"[TOOL_USE]
{
  "oldString": "line1\nline2",
  "newString": "line1\nline2\nline3"
}
[END]"#;
    println!("production_like matches: {}", re.find_iter(production_like).count());
    for cap in re.captures_iter(production_like) {
        println!("  cap[1] first 50: {:?}", &cap[1][..cap[1].len().min(50)]);
    }
    // Test against the EXACT production_shape content to find the failure case
    let prod_matches = re.find_iter(PRODUCTION_SHAPE_SRC).count();
    println!("PRODUCTION_SHAPE_SRC matches: {}", prod_matches);
    for cap in re.captures_iter(PRODUCTION_SHAPE_SRC).take(5) {
        println!("  cap[1] first 80: {:?}", &cap[1][..cap[1].len().min(80)]);
    }
    assert!(re.is_match(simple), "regex must match simple JSON");
    assert!(re.is_match(production_like), "regex must match production-like JSON");
}

#[tokio::test]
async fn l3_scan_response_end_to_end_catches_hallucination_production_shape() {
    let ctx = make_ctx();
    // Direct diagnostic: invoke extract_tool_call_code on the production shape
    // to see what it actually returns. This isolates the regex/extraction
    // behavior from the full scan_response pipeline.
    let tool_code_direct = anubis_daemon::scanner::extract_tool_call_code(PRODUCTION_SHAPE_SRC);
    println!("L3 extract_tool_call_code direct: len={}", tool_code_direct.len());
    if !tool_code_direct.is_empty() {
        for (i, line) in tool_code_direct.lines().take(10).enumerate() {
            println!("  [{}] {}", i, line);
        }
    }
    let result = scanner::scan_response(PRODUCTION_SHAPE_SRC, &ctx).await;
    println!("L3 scan_response (production-shape with tool_use JSON):");
    println!("  clean={} risk={} confidence={}", result.clean, result.risk_score, result.confidence);
    println!("  warnings: {}", result.warnings.len());
    for w in &result.warnings {
        println!("    {}", w);
    }
    println!("  details: {}", result.details.len());
    for d in &result.details {
        println!("    {}", d);
    }
    let has_chain_broken = result
        .warnings
        .iter()
        .chain(result.details.iter())
        .any(|s| s.contains("chain-broken"));
    if !has_chain_broken {
        // Diagnostics: did language detection fire? did FORGE run at all?
        let lang = detect_language(PRODUCTION_SHAPE_SRC, "");
        println!("  detect_language(production_shape) = {:?}", lang);
        println!(
            "  FAILURE INDICATOR: scan_response caught hallucination in markdown \
             but NOT in production-shape content. Root cause is in code extraction: \
             tool_use JSON content isn't being unwrapped before FORGE runs."
        );
    }
    assert!(
        has_chain_broken,
        "scan_response must catch hallucination embedded in tool_use JSON — \
         THIS IS THE PRODUCTION BUG. The hallucinated code lives inside the \
         Update command's newString field as escaped JSON, and the scanner \
         is not extracting it before running FORGE."
    );
    assert!(
        result.risk_score > 0.0,
        "risk_score must be > 0 for production-shape hallucination (was {})",
        result.risk_score
    );
}

/// Realistic Anthropic SSE event sequence for a tool_use Update command.
/// Each event is a single SSE `data: {...}` line as Anthropic actually emits.
/// When fed through `process_sse_line`, this builds a `full_content` string
/// byte-identical to what the proxy assembles in production. If the hallucination
/// is caught on this content but not in production, the bug is elsewhere. If it
/// is NOT caught here, the bug is in extract_tool_call_code or downstream FORGE.
fn build_realistic_anthropic_stream() -> String {
    use anubis_daemon::proxy::process_sse_line;
    let events: &[&str] = &[
        // text block start
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
        // text deltas — Claude's prose preamble
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I'll add another hallucinated function. "}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"The method to_camel() does not exist on str."}}"#,
        r#"data: {"type":"content_block_stop","index":0}"#,
        // tool_use block — Anthropic streams partial_json fragments
        r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01ABC","name":"Update","input":{}}}"#,
        // The partial_json fragments, concatenated, must form a valid JSON object.
        // Anthropic typically streams in 3-10 fragments depending on size.
        // Each fragment's value is a JSON-encoded string fragment.
        // NOTE: in the SSE wire format, backslashes are DOUBLY escaped
        // (once for SSE JSON, once for the inner JSON string value).
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"filePath\": \"C:\\\\Users\\\\robin\\\\test.py\", "}}"#,
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"oldString\": \"    return text.to_snake()   # str has no to_snake() method\\n\\n\\nif __name__\", "}}"#,
        r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"newString\": \"    return text.to_snake()   # str has no to_snake() method\\n\\n\\ndef to_camel_case(text):\\n    \\\"\\\"\\\"Convert text to camelCase.\\\"\\\"\\\"\\n    return text.to_camel()   # str has no to_camel() method\\n\\n\\nif __name__\"}"}}"#,
        r#"data: {"type":"content_block_stop","index":1}"#,
        r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":150}}"#,
        r#"data: {"type":"message_stop"}"#,
    ];

    let mut full_content = String::new();
    let mut usage: Option<serde_json::Value> = None;
    let mut has_text_content = false;
    for ev in events {
        process_sse_line(ev, &mut full_content, &mut usage, &mut has_text_content);
    }
    full_content
}

#[tokio::test]
async fn l4_anthropic_sse_assembly_catches_hallucination() {
    let full_content = build_realistic_anthropic_stream();

    println!("=== ASSEMBLED full_content ({} bytes) ===", full_content.len());
    for (i, line) in full_content.lines().enumerate() {
        println!("{:3}: {}", i + 1, line);
    }
    println!("=== END full_content ===\n");

    // First verify the assembled content actually contains the hallucinated code.
    // The newString field's value, after JSON-unescaping during SSE parsing,
    // should contain `return text.to_camel()` as readable text.
    assert!(
        full_content.contains("to_camel"),
        "assembled content must mention to_camel; got:\n{}",
        full_content
    );

    // Now run scan_response on the assembled content — same path the proxy uses.
    let ctx = make_ctx();
    let result = scanner::scan_response(&full_content, &ctx).await;

    println!("=== scan_response result ===");
    println!("  clean={} risk={} confidence={}", result.clean, result.risk_score, result.confidence);
    println!("  warnings: {}", result.warnings.len());
    for w in &result.warnings {
        println!("    {}", w);
    }
    println!("  details: {}", result.details.len());
    for d in &result.details {
        println!("    {}", d);
    }

    let has_chain_broken = result
        .warnings
        .iter()
        .chain(result.details.iter())
        .any(|s| s.contains("chain-broken") || s.contains("to_camel"));

    assert!(
        has_chain_broken,
        "scan_response must catch hallucination in realistically-assembled Anthropic stream — \
         this test mirrors production byte-for-byte. Failure here means extract_tool_call_code \
         or FORGE cannot handle real-world Anthropic partial_json concatenation."
    );
    assert!(
        result.risk_score > 0.0,
        "risk_score must be > 0 for assembled stream (was {})",
        result.risk_score
    );
}

/// Production stress test: Claude's prose naturally contains em-dashes (—),
/// smart quotes (" "), and other Unicode. Past failure mode: py_compile ran
/// on prose mixed with code and raised "invalid character '—' (U+2014)",
/// producing noise warnings but no chain-broken for the actual hallucination.
/// This test verifies chain-broken still fires for the hallucination despite
/// em-dashes in surrounding prose.
#[tokio::test]
async fn l5_prose_with_em_dash_does_not_mask_hallucination() {
    let full_content = build_realistic_anthropic_stream()
        // Inject em-dashes and smart quotes into the prose — exactly what
        // Claude's natural writing style produces.
        + " Added as_camel_case() — another hallucinated function — "
        + "calls text.to_camel() which doesn’t exist on str.";

    println!("=== EM-DASH STRESS content ({} bytes) ===", full_content.len());
    println!("{}", full_content);
    println!("=== END ===\n");

    let ctx = make_ctx();
    let result = scanner::scan_response(&full_content, &ctx).await;

    println!("=== scan_response result ===");
    println!("  clean={} risk={} confidence={}", result.clean, result.risk_score, result.confidence);
    println!("  warnings: {}", result.warnings.len());
    for w in &result.warnings {
        println!("    {}", w);
    }

    let has_chain_broken = result
        .warnings
        .iter()
        .chain(result.details.iter())
        .any(|s| s.contains("chain-broken") && s.contains("to_camel"));

    assert!(
        has_chain_broken,
        "chain-broken for text.to_camel must survive em-dash contamination in prose"
    );
    assert!(
        result.risk_score > 0.0,
        "risk_score must be > 0 even with prose em-dashes (was {})",
        result.risk_score
    );
}

/// Production-shape regression test: real Claude Code traffic uses OpenAI
/// str_replace_editor format with snake_case field names (new_string,
/// old_string), NOT Anthropic camelCase (newString, oldString). Caught
/// after production failure 2026-08-07 — earlier extractor missed the
/// hallucination because target_fields list only had camelCase variants.
#[tokio::test]
async fn l6_openai_snake_case_tool_call_catches_hallucination() {
    // Real bytes from ~/.anubis diagnostic dump (verbatim, after JSON parse):
    // - literal `\n` (backslash + n) wire-format escape inside string values
    // - literal `\"` wire-format escape for inner quotes
    // - field names snake_case: new_string, old_string, file_path, replace_all
    let src = r#"I'll add to_pascal_case that calls text.to_pascal() - a nonexistent method.{"replace_all":false,"file_path":"C:\\Users\\robin\\test.py","old_string":"    return text.to_slug()   # str has no to_slug() method\n\n\nif __name__ == \"__main__\":","new_string":"    return text.to_slug()   # str has no to_slug() method\n\n\ndef to_pascal_case(text):\n    \"\"\"Convert text to PascalCase.\"\"\"\n    return text.to_pascal()   # str has no to_pascal() method\n\n\nif __name__ == \"__main__\":"}"#;

    let ctx = make_ctx();
    let result = scanner::scan_response(src, &ctx).await;

    println!("warnings: {}", result.warnings.len());
    for w in &result.warnings {
        println!("    {}", w);
    }

    let has_chain_broken = result
        .warnings
        .iter()
        .chain(result.details.iter())
        .any(|s| s.contains("chain-broken") && s.contains("to_pascal"));

    assert!(
        has_chain_broken,
        "chain-broken for text.to_pascal must fire on OpenAI snake_case tool_call format"
    );
    assert!(
        result.risk_score > 0.0,
        "risk_score must be > 0 for snake_case tool_call hallucination (was {})",
        result.risk_score
    );
}
