//! End-to-end pipeline integration test.
//!
//! Verifies the ENTIRE chain works in one shot:
//!   content in → docs injected → L3 fires → verdict returned → warning emitted.
//!
//! Uses a `wiremock` mock LLM server so the test is fully deterministic — no
//! real API key, no network dependency on the docs Worker. The mock plays the
//! role of the LLM judge: it captures the request (proving L3 fired + the
//! docs-injection section reached the prompt) and returns a fixed
//! `hallucinated` verdict (proving the verdict→warning merge works).
//!
//! Each assertion maps to one link in the chain, so the FIRST broken link
//! fails loudly with a message naming the culprit:
//!
//!   Link 1 (content in)        → scan produced detail lines
//!   Link 2 (docs injected)     → L3 system prompt contains DOCUMENT EVIDENCE
//!   Link 3 (L3 fires)          → mock received >=1 POST /chat/completions
//!   Link 4 (verdict returned)  → validator_response records claims_hallucinated>0
//!   Link 5 (warning emitted)   → warnings contains "claim-hallucinated"
//!
//! Run:
//!   cargo test --test pipeline_e2e_integration -- --nocapture

use anubis_daemon::scanner::{scan_response, ScanContext};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Realistic LLM-shaped response: a markdown code fence with a hallucinated
/// API (`nested.flatten()` — Python `list` has no `flatten`) plus prose that
/// makes two behavioral claims about it using trigger words (`O(n)`,
/// `thread-safe`). The trigger words force `extract_prose_claims` to surface
/// the claim and `compute_cascade_decision` to NOT skip L3. No `Capital.method(`
/// pattern and no import statements → `extract_lookup_terms` / `detect_libraries`
/// return empty → `search_docs` / `build_library_docs_fallback` short-circuit
/// without any network call, keeping the test hermetic.
const HALLUCINATED_CONTENT: &str = "\
Here's how to flatten a list:

```python
nested = [[1, 2], [3, 4]]
flat = nested.flatten()
```

The `list.flatten()` method runs in O(n) time and is thread-safe, returning a \
flat copy of the nested elements.
";

/// Build a `ScanContext` wired to the mock LLM server.
fn make_ctx(base_url: String, api_key: &str) -> ScanContext {
    ScanContext {
        project_root: std::env::temp_dir().to_string_lossy().to_string(),
        logic_model: "test-mock-model".to_string(),
        llm_base_url: base_url,
        llm_api_key: api_key.to_string(),
        llm_extra_headers: vec![],
        request_class: "agent".to_string(),
        language: "python".to_string(),
        cancel: CancellationToken::new(),
    }
}

/// Mock LLM response body: OpenAI chat-completion shape carrying ONE
/// `hallucinated` verdict for the ONE claim each judge call verifies (§1/§2
/// of the l3-prompt-redesign spec: one claim per call, single JSON object
/// with a `quote` field). The quote below is a verbatim substring of the
/// scanned code, so it passes the mechanical `quote_found` check. If the
/// scan extracts more than one prose claim, each gets its own call and its
/// own (identical) hallucinated verdict.
fn mock_l3_hallucinated_body() -> serde_json::Value {
    let content = concat!(
        "<reasoning>The claim about list.flatten is wrong — Python lists have no ",
        "flatten method; flattening uses itertools.chain.from_iterable or a ",
        "comprehension.</reasoning>\n",
        "{\"quote\":\"nested.flatten()\",\"verdict\":\"hallucinated\",",
        "\"confidence\":0.95,",
        "\"reason\":\"Python list has no flatten method\"}",
    );
    serde_json::json!({
        "choices": [{ "message": { "content": content }, "finish_reason": "stop" }]
    })
}

/// Extract the system prompt from a captured wiremock request body.
fn system_prompt_from_request(body: &[u8]) -> String {
    let v: serde_json::Value =
        serde_json::from_slice(body).expect("L3 request body must be valid JSON");
    v.get("messages")
        .and_then(|m| m.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
        })
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

// ────────────────────────────────────────────────────────────────────────────
// PRIMARY: full chain — content in → docs injected → L3 → verdict → warning
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn full_pipeline_l3_fires_and_emits_warning() {
    // L3 gate short-circuits when DELULU_FORGE_ONLY is set. This test binary
    // owns the env var (single binary, no cross-file races), so remove it to
    // guarantee the L3 path is reachable.
    std::env::remove_var("DELULU_FORGE_ONLY");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_l3_hallucinated_body()))
        .mount(&server)
        .await;

    let ctx = make_ctx(server.uri(), "test-key-nonempty");
    let result = scan_response(HALLUCINATED_CONTENT, &ctx).await;

    println!(
        "scan_response: clean={} risk={} confidence={}\nwarnings ({}):",
        result.clean, result.risk_score, result.confidence, result.warnings.len()
    );
    for w in &result.warnings {
        println!("  - {}", w);
    }
    println!("details ({}):", result.details.len());
    for d in &result.details {
        println!("  - {}", d);
    }
    println!("validator_response: {}", result.validator_response);

    // ── Link 1: content reached scan_response ────────────────────────────
    // A short-circuited scan (compaction class, <3 tokens) returns near-empty
    // details. Real content with prose + code must produce detail lines.
    assert!(
        !result.details.is_empty(),
        "Link 1 broken (content in): scan produced no detail lines — \
         scan_response short-circuited before running the pipeline."
    );

    // ── Link 3: L3 fired (mock received the POST) ───────────────────────
    // Asserted before Link 2 because if L3 never fired there is no request
    // body to inspect for the docs section.
    let received = server
        .received_requests()
        .await
        .expect("wiremock request recording must be enabled");
    assert!(
        !received.is_empty(),
        "Link 3 broken (L3 fires): mock LLM received ZERO requests. \
         The cascade skipped L3 or the api_key/min_len/prose-claim gate is broken."
    );
    let l3_request = &received[0];
    let system_prompt = system_prompt_from_request(&l3_request.body);

    // ── Link 2: the falsification-judge prompt is on the wire ──────────
    // `build_judge_system_prompt` ALWAYS carries the falsification
    // contract. Its absence means the prompt-builder wiring is broken.
    assert!(
        system_prompt.contains("prove the claim WRONG"),
        "Link 2 broken (judge prompt): L3 system prompt is missing the \
         falsification framing that build_judge_system_prompt must emit. \
         Prompt head: {:?}",
        &system_prompt[..system_prompt.len().min(400)]
    );
    assert!(
        system_prompt.contains("QUOTE RULE"),
        "Link 2 broken (judge prompt): mechanical quote rule missing."
    );

    // The user prompt must position the CODE first and the CLAIM last (§2),
    // and carry the scanned code block (nested.flatten()).
    let v: serde_json::Value = serde_json::from_slice(&l3_request.body)
        .expect("L3 request body must be valid JSON");
    let user_prompt = v
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        })
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or_default();
    assert!(
        user_prompt.contains("CODE (python):"),
        "Link 2 broken (judge prompt): user prompt must lead with the code block"
    );
    assert!(
        user_prompt.contains("nested.flatten()"),
        "Link 2 broken (judge prompt): scanned code must reach the judge"
    );
    assert!(
        user_prompt.contains("Find evidence that this claim is wrong"),
        "Link 2 broken (judge prompt): falsification instruction missing"
    );

    // ── Link 4: verdict returned + merged into validator_response ───────
    // merge_l3_verdicts synthesizes a JSON string recording claim counts.
    // An empty validator_response means the verdict never landed (merge broken
    // or verify_claims_per_claim returned empty).
    assert!(
        !result.validator_response.is_empty(),
        "Link 4 broken (verdict returned): validator_response is empty — \
         merge_l3_verdicts never ran or verify_claims_per_claim returned no verdicts."
    );
    // Parse the synthetic JSON and confirm at least one hallucinated verdict
    // was recorded (the mock's verdict reached the merger).
    let vr: serde_json::Value = serde_json::from_str(&result.validator_response)
        .expect("validator_response must be valid JSON");
    let hallucinated = vr
        .get("claims_hallucinated")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        hallucinated >= 1,
        "Link 4 broken (verdict returned): claims_hallucinated={} (expected >=1). \
         The mock's hallucinated verdict did not reach merge_l3_verdicts. \
         validator_response={}",
        hallucinated,
        result.validator_response
    );

    // ── Link 5: warning emitted ─────────────────────────────────────────
    // aggregate_claims turns a hallucinated + conf>=0.6 verdict into a
    // "claim-hallucinated" warning. This is the user-visible surface — if it
    // is missing, the verdict never escaped into warnings.
    let has_warning = result
        .warnings
        .iter()
        .any(|w| w.contains("claim-hallucinated"));
    assert!(
        has_warning,
        "Link 5 broken (warning emitted): no 'claim-hallucinated' warning in \
         result.warnings (got {} warnings). aggregate_claims / merge_l3_verdicts \
         dropped the verdict. Warnings: {:?}",
        result.warnings.len(),
        result.warnings
    );
    assert!(
        result.risk_score > 0.0,
        "Link 5 broken (warning emitted): risk_score={} must be > 0 when a \
         hallucinated verdict fires.",
        result.risk_score
    );
    assert!(
        !result.clean,
        "Link 5 broken (warning emitted): result.clean must be false when a \
         hallucination warning fires."
    );
}

// ────────────────────────────────────────────────────────────────────────────
// NEGATIVE CONTROL: L3 must NOT fire when no API key is configured.
// Catches the opposite broken link — L3 firing when the gate says it
// shouldn't, which would waste tokens / produce phantom verdicts.
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn l3_does_not_fire_without_api_key() {
    std::env::remove_var("DELULU_FORGE_ONLY");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_l3_hallucinated_body()))
        .mount(&server)
        .await;

    // Empty api_key → scan_response must take the FORGE-only path and never
    // call the LLM (see mod.rs L3 gate: `!ctx.llm_api_key.is_empty()`).
    let ctx = make_ctx(server.uri(), "");
    let result = scan_response(HALLUCINATED_CONTENT, &ctx).await;

    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "L3 gate broken: mock received {} requests with an EMPTY api_key — \
         the `!ctx.llm_api_key.is_empty()` gate is not respected.",
        received.len()
    );
    // No L3 → no L3-derived warning. (Deterministic layers may still warn on
    // the hallucinated `flatten()` call — that's fine, we only assert no
    // claim-hallucinated L3 warning.)
    let has_l3_warning = result
        .warnings
        .iter()
        .any(|w| w.contains("claim-hallucinated"));
    assert!(
        !has_l3_warning,
        "L3 gate broken: claim-hallucinated warning emitted without an api_key — \
         warnings: {:?}",
        result.warnings
    );
}

// ────────────────────────────────────────────────────────────────────────────
// REGRESSION: identifier-anchored prose (no trigger words) reaches L3.
//
// Broken-link #10 regression: classify_claim is trigger-word-based, so a
// prose sentence like "The flatten method returns a copy." that references
// a code identifier but contains NO trigger words would be classified CODE
// and silently skipped before reaching the LLM. The fix is the
// `prose_claim_count` bypass in verify_claims_per_claim (caller asserts
// prose-ness; L3 trusts the caller instead of re-deriving).
//
// This test FAILS without the bypass: extract_prose_claims returns []
// (no trigger words), extract_identifier_anchored_claims surfaces the
// sentence via `flatten`/`nested` identifier match, classify_claim then
// returns Code, and the claim is dropped before L3.
// ────────────────────────────────────────────────────────────────────────────

/// Prose with NO trigger words. References code identifier `flatten`/`nested`.
/// `extract_identifier_anchored_claims` surfaces this; `extract_prose_claims`
/// does NOT (no "O(n)", "thread-safe", etc.). Without the prose_claim_count
/// bypass, L3 would never fire.
const IDENTIFIER_ANCHORED_CONTENT: &str = "\
Here's how to flatten a list:

```python
nested = [[1, 2], [3, 4]]
flat = nested.flatten()
```

The flatten method returns a copy of the nested elements.
";

#[tokio::test]
async fn identifier_anchored_prose_reaches_l3_without_trigger_words() {
    std::env::remove_var("DELULU_FORGE_ONLY");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(mock_l3_hallucinated_body()))
        .mount(&server)
        .await;

    let ctx = make_ctx(server.uri(), "test-key-nonempty");
    let result = scan_response(IDENTIFIER_ANCHORED_CONTENT, &ctx).await;

    println!(
        "identifier-anchored scan: clean={} risk={}\nwarnings ({}):",
        result.clean, result.risk_score, result.warnings.len()
    );
    for w in &result.warnings {
        println!("  - {}", w);
    }
    println!("details ({}):", result.details.len());
    for d in &result.details {
        println!("  - {}", d);
    }

    // L3 MUST have fired. If the prose_claim_count bypass is removed, L3
    // never receives the identifier-anchored claim (classify_claim → Code →
    // skipped) and the mock records zero requests.
    let received = server
        .received_requests()
        .await
        .expect("wiremock request recording must be enabled");
    assert!(
        !received.is_empty(),
        "REGRESSION (BL-10): L3 received ZERO requests for identifier-anchored \
         prose without trigger words. The prose_claim_count bypass in \
         verify_claims_per_claim is missing or broken — classify_claim \
         re-filtered the claim as CODE before L3 could fire."
    );

    // The claim reached L3 — confirm the falsification-judge prompt was
    // built (framing always emitted by build_judge_system_prompt).
    let l3_request = &received[0];
    let system_prompt = system_prompt_from_request(&l3_request.body);
    assert!(
        system_prompt.contains("prove the claim WRONG"),
        "L3 system prompt missing the falsification framing that \
          build_judge_system_prompt must always emit. Prompt head: {:?}",
        &system_prompt[..system_prompt.len().min(400)]
    );

    // Verdict reached the merger.
    assert!(
        !result.validator_response.is_empty(),
        "L3 verdict did not reach merge_l3_verdicts — validator_response empty."
    );
    let vr: serde_json::Value = serde_json::from_str(&result.validator_response)
        .expect("validator_response must be valid JSON");
    let hallucinated = vr
        .get("claims_hallucinated")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(
        hallucinated >= 1,
        "Mock hallucinated verdict did not reach validator_response — \
         claims_hallucinated={}. validator_response={}",
        hallucinated,
        result.validator_response
    );
}
