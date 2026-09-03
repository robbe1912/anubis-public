// HTTP proxy server — intercepts LLM requests, forwards to upstream, scans responses.
//
// Uses axum for the HTTP server + reqwest for upstream forwarding.
// Streaming responses are buffered in windows (matching the TS implementation).
//
// Architecture: see docs/STREAMING_SCHEMA_REFERENCE.md for SSE protocol details.

use crate::api;
use crate::classify;
use crate::config::{self, ANUBISConfig, RoutingMode};
use crate::license;
use crate::scanner::{self, ScanContext};
use crate::stats::{self, RequestLogEntry, ScanResult, SharedStats};
use crate::trial;

// ─── Warning injection helpers ──────────────────────────────────────
//
// Anubis is advisory-only by default — scans + warns but doesn't modify
// responses. The functions below opt into RESPONSE MODIFICATION when
// risk_score crosses configurable thresholds:
//
//   risk < 0.3  → silent (clean enough)
//   0.3 ≤ risk < 0.7 → append warning footer (agent sees warning, can self-correct)
//   risk ≥ 0.7 → block + retry with correction system message (max 1 retry)
//
// Thresholds chosen based on FORGE 2026 + Cost-Effective 2024 research
// findings: at FPR ≤ 1%, simpler interventions beat aggressive ones.

const RISK_THRESHOLD_APPEND: f64 = 0.3;
const RISK_THRESHOLD_BLOCK: f64 = 0.7;

/// Build the synthetic assistant message body used when block mode intercepts
/// a hallucinated tool call. The message replaces the original response so
/// the LLM never sees the tool call succeed — instead it sees its own
/// "blocked" message and can correct on the next turn.
///
/// Format mirrors the warning footer (so dashboard stats stay consistent)
/// but framed as first-person assistant text so the LLM adopts it naturally
/// as its own utterance.
fn build_block_message(risk_score: f64, warnings: &[String], tool_call_summary: &str) -> String {
    let scaled = (risk_score * 10.0).round() as i32;
    let risk_int = scaled.clamp(0, 10);

    let mut lines = Vec::new();
    lines.push(format!(
        "I tried to call {} but Anubis blocked the tool call (risk={}/10) because it detected {} likely hallucination{}:",
        tool_call_summary,
        risk_int,
        warnings.len(),
        if warnings.len() == 1 { "" } else { "s" }
    ));
    lines.push(String::new());
    for w in warnings.iter().take(8) {
        lines.push(format!("- {}", w));
    }
    if warnings.len() > 8 {
        lines.push(format!("- ...and {} more", warnings.len() - 8));
    }
    lines.join("\n")
}

/// Build pre-emptive abort message text for streaming responses.
///
/// Similar to build_block_message but phrased for stream abort (not tool
/// call block). The agent adopts this as its own utterance — it reads as
/// if the agent itself decided to stop and self-correct.
fn build_preemptive_abort_message(risk_score: f64, warnings: &[String]) -> String {
    let scaled = (risk_score * 10.0).round() as i32;
    let risk_int = scaled.clamp(0, 10);

    let mut lines = Vec::new();
    lines.push(format!(
        "[Anubis] Tool call blocked: hallucinated APIs detected (risk={}/10). {} warning{}:",
        risk_int,
        warnings.len(),
        if warnings.len() == 1 { "" } else { "s" }
    ));
    for w in warnings.iter().take(8) {
        lines.push(format!("- {}", w));
    }
    if warnings.len() > 8 {
        lines.push(format!("- ...and {} more", warnings.len() - 8));
    }
    lines.push(String::new());
    lines.push(
        "The tool call was not executed. Verify these APIs exist in the \
         official documentation before retrying.".to_string(),
    );
    lines.join("\n")
}

/// Build SSE chunks for a pre-emptive stream abort.
///
/// Returns a Vec of Bytes chunks that form a complete SSE stream:
/// role chunk + content chunk + stop chunk + usage + [DONE].
/// The client sees this as the assistant's complete response.
fn build_preemptive_abort_chunks(
    risk_score: f64,
    warnings: &[String],
    blocks: &[String],
    provider: Provider,
    include_done: bool,
) -> Vec<Result<bytes::Bytes, std::io::Error>> {
    // Combine warnings + blocks for the message
    let mut all_issues: Vec<String> = warnings.to_vec();
    all_issues.extend(blocks.iter().cloned());

    let message = build_preemptive_abort_message(risk_score, &all_issues);
    let model = "anubis-preemptive";

    let mut sse_string = match provider {
        Provider::Anthropic => build_block_stream_anthropic(&message, model),
        Provider::OpenAi | Provider::Unknown => build_block_stream_openai(&message, model),
    };

    // When retry is planned, strip [DONE] — the retry response will add it.
    if !include_done {
        if let Some(pos) = sse_string.rfind("data: [DONE]") {
            sse_string.truncate(pos);
        }
    }

    // Return as a single Bytes chunk. The SSE string already contains
    // all events + [DONE] terminator.
    vec![Ok(bytes::Bytes::from(sse_string))]
}

/// Detect whether a response body contains a tool call (OpenAI or Anthropic
/// format). Used to decide whether block mode should engage — hallucinated
/// tool calls are the dangerous case; hallucinated chat text just gets the
/// warning footer appended.
fn response_has_tool_calls(body: &str) -> bool {
    // OpenAI: `"tool_calls":[...]` in choices[].message
    // Anthropic: `"tool_use` block type, or `"type":"tool_use"`
    // Cheap substring check — false positives acceptable (we'll just run the
    // scan, which is idempotent).
    body.contains("\"tool_calls\"")
        || body.contains("\"tool_use\"")
        || body.contains("\"type\":\"tool_use\"")
}

/// Build the synthetic OpenAI-compatible chat completion response for a
/// blocked tool call. Replaces the upstream response entirely.
fn build_block_response_openai(reasoning: &str, model: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("chatcmpl-anubis-block-{}", chrono::Utc::now().timestamp_millis()),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": reasoning,
            },
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
        "x_anubis_blocked": true,
    })
}

/// Build the synthetic Anthropic-compatible messages response for a blocked
/// tool call. Anthropic uses content blocks; we emit a single text block.
fn build_block_response_anthropic(reasoning: &str, model: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("msg_anubis_block_{}", chrono::Utc::now().timestamp_millis()),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{
            "type": "text",
            "text": reasoning,
        }],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 0,
            "output_tokens": 0,
        },
        "x_anubis_blocked": true,
    })
}

/// Extract a short human-readable summary of the tool call(s) in a response
/// body. Used in the block message so the LLM knows what it tried to call.
/// Returns "tool call" if parsing fails — never panics.
fn summarize_tool_call(body: &str) -> String {
    // OpenAI format: choices[].message.tool_calls[].function.name
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(calls) = v
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|m| m.get("tool_calls"))
            .and_then(|t| t.as_array())
        {
            let names: Vec<&str> = calls.iter()
                .filter_map(|c| c.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()))
                .collect();
            if !names.is_empty() {
                return names.join(", ");
            }
        }
        // Anthropic format: content[].type == "tool_use", .name
        if let Some(blocks) = v.get("content").and_then(|c| c.as_array()) {
            let names: Vec<&str> = blocks.iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                .filter_map(|b| b.get("name").and_then(|n| n.as_str()))
                .collect();
            if !names.is_empty() {
                return names.join(", ");
            }
        }
    }
    "tool call".to_string()
}


/// Returns the full SSE event sequence as a single string, ending with [DONE].
/// The chunks mimic an OpenAI streaming response so existing clients parse
/// them without modification.
fn build_block_stream_openai(reasoning: &str, model: &str) -> String {
    let id = format!("chatcmpl-anubis-block-{}", chrono::Utc::now().timestamp_millis());
    let created = chrono::Utc::now().timestamp();

    // First chunk: role + start of content.
    let first = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {
                "role": "assistant",
                "content": "",
            },
        }]
    });

    // Content chunk(s): emit reasoning in one piece (clients concat anyway).
    let content_chunk = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {
                "content": reasoning,
            },
        }]
    });

    // Stop chunk.
    let stop = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {},
            "finish_reason": "stop",
        }]
    });

    let usage = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
    });

    let mut out = String::new();
    for chunk in [first, content_chunk, stop, usage] {
        out.push_str(&format!("data: {}\n\n", chunk.to_string()));
    }
    out.push_str("data: [DONE]\n\n");
    out
}

/// Build an SSE stream that forwards CORRECTED tool calls from a block+retry
/// response. Mimics OpenAI streaming tool_calls deltas so existing clients
/// (opencode etc.) accumulate and execute them natively — closing the
/// block → tool_error → corrected-call loop.
///
/// Each tool call is emitted as ONE self-contained delta fragment (id +
/// type + function.name + full arguments string). Clients concatenate
/// argument fragments, so a single complete fragment is spec-valid.
fn build_tool_call_stream_openai(
    text: &str,
    tool_calls: &[serde_json::Value],
    model: &str,
) -> String {
    let id = format!("chatcmpl-anubis-retry-{}", chrono::Utc::now().timestamp_millis());
    let created = chrono::Utc::now().timestamp();

    let chunk = |delta: serde_json::Value, finish: Option<&str>| {
        let mut choice = serde_json::json!({ "index": 0, "delta": delta });
        if let Some(f) = finish {
            choice["finish_reason"] = serde_json::json!(f);
        }
        serde_json::json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [choice],
        })
    };

    let mut chunks = vec![chunk(
        serde_json::json!({ "role": "assistant", "content": "" }),
        None,
    )];
    if !text.is_empty() {
        chunks.push(chunk(serde_json::json!({ "content": text }), None));
    }
    for (i, tc) in tool_calls.iter().enumerate() {
        let mut delta_tc = serde_json::json!({ "index": i, "type": "function" });
        if let Some(cid) = tc.get("id").and_then(|v| v.as_str()) {
            delta_tc["id"] = serde_json::json!(cid);
        }
        // Non-streaming OpenAI shape: { id, type, function: { name, arguments } }.
        if let Some(f) = tc.get("function") {
            delta_tc["function"] = f.clone();
        }
        chunks.push(chunk(serde_json::json!({ "tool_calls": [delta_tc] }), None));
    }
    chunks.push(chunk(serde_json::json!({}), Some("tool_calls")));

    let usage = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [],
        "usage": { "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 },
    });

    let mut out = String::new();
    for c in chunks {
        out.push_str(&format!("data: {}\n\n", c.to_string()));
    }
    out.push_str(&format!("data: {}\n\n", usage.to_string()));
    out.push_str("data: [DONE]\n\n");
    out
}

/// Build an Anthropic SSE stream carrying corrected tool_use blocks after a
/// block+retry (the Anthropic mirror of build_tool_call_stream_openai).
/// Tool calls arrive in normalized OpenAI shape ({id, function:{name,
/// arguments-JSON-string}}) and are emitted as content_block_start(tool_use)
/// + one input_json_delta + content_block_stop per call, closing with
/// stop_reason "tool_use" so the agent executes the corrected calls.
fn build_tool_call_stream_anthropic(
    text: &str,
    tool_calls: &[serde_json::Value],
    model: &str,
) -> String {
    let msg_id = format!("msg_anubis_retry_{}", chrono::Utc::now().timestamp_millis());
    let mut events: Vec<serde_json::Value> = vec![serde_json::json!({
        "type": "message_start",
        "message": {
            "id": msg_id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [],
            "stop_reason": null,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }
    })];
    let mut index: u64 = 0;
    if !text.is_empty() {
        events.push(serde_json::json!({
            "type": "content_block_start", "index": index,
            "content_block": {"type": "text", "text": ""}
        }));
        events.push(serde_json::json!({
            "type": "content_block_delta", "index": index,
            "delta": {"type": "text_delta", "text": text}
        }));
        events.push(serde_json::json!({"type": "content_block_stop", "index": index}));
        index += 1;
    }
    for tc in tool_calls {
        let id = tc.get("id").and_then(|v| v.as_str()).unwrap_or("toolu_retry");
        let name = tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("tool");
        let args = tc.get("function").and_then(|f| f.get("arguments")).and_then(|a| a.as_str()).unwrap_or("{}");
        events.push(serde_json::json!({
            "type": "content_block_start", "index": index,
            "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}
        }));
        events.push(serde_json::json!({
            "type": "content_block_delta", "index": index,
            "delta": {"type": "input_json_delta", "partial_json": args}
        }));
        events.push(serde_json::json!({"type": "content_block_stop", "index": index}));
        index += 1;
    }
    events.push(serde_json::json!({
        "type": "message_delta",
        "delta": {"stop_reason": "tool_use", "stop_sequence": null},
        "usage": {"output_tokens": 0}
    }));
    events.push(serde_json::json!({"type": "message_stop"}));
    let mut out = String::new();
    for e in events {
        out.push_str(&format!("event: {}\n", e.get("type").and_then(|t| t.as_str()).unwrap_or("")));
        out.push_str(&format!("data: {}\n\n", e.to_string()));
    }
    out
}

/// Build SSE event stream for a blocked Anthropic tool call.
/// Anthropic streaming uses event-typed SSE chunks: message_start, content_block_start,
/// content_block_delta, content_block_stop, message_delta, message_stop.
fn build_block_stream_anthropic(reasoning: &str, model: &str) -> String {
    let msg_id = format!("msg_anubis_block_{}", chrono::Utc::now().timestamp_millis());

    let message_start = serde_json::json!({
        "type": "message_start",
        "message": {
            "id": msg_id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [],
            "stop_reason": null,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }
    });

    let block_start = serde_json::json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": {"type": "text", "text": ""}
    });

    let block_delta = serde_json::json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": reasoning}
    });

    let block_stop = serde_json::json!({
        "type": "content_block_stop",
        "index": 0,
    });

    let message_delta = serde_json::json!({
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn"},
        "usage": {"output_tokens": 0}
    });

    let message_stop = serde_json::json!({
        "type": "message_stop",
    });

    let mut out = String::new();
    for event in [message_start, block_start, block_delta, block_stop, message_delta, message_stop] {
        out.push_str(&format!("event: {}\n", event["type"].as_str().unwrap_or("")));
        out.push_str(&format!("data: {}\n\n", event.to_string()));
    }
    out
}


/// Build a markdown warning footer to append to LLM responses.
///
/// Format:
///   ```markdown
///
///   ---
///   ⚠ **Anubis** (risk=7/10): 2 hallucinations detected
///   - foo.bar() — class foo exists but method bar is missing
///   - Scan ran 4 hours ago. Cached symbols may be stale.
///   ```
///
/// Visible to the agent in conversation history — it can self-correct on
/// the next turn. Doesn't change early content (preserves what user saw).
fn build_warning_footer(risk_score: f64, warnings: &[String], blocks: &[String]) -> String {
    let scaled = (risk_score * 10.0).round() as i32;
    let risk_int = scaled.clamp(0, 10);
    let count = warnings.len() + blocks.len();

    let mut lines = Vec::new();
    lines.push(String::new()); // blank line before divider
    lines.push("---".to_string());
    lines.push(format!(
        "⚠ **Anubis** (risk={}/10): {} hallucination{} detected",
        risk_int,
        count,
        if count == 1 { "" } else { "s" }
    ));

    // Show blocks first (most severe), then warnings.
    for b in blocks.iter().take(5) {
        lines.push(format!("- {}", b));
    }
    for w in warnings.iter().take(5 - blocks.len().min(5)) {
        lines.push(format!("- {}", w));
    }
    if count > 5 {
        lines.push(format!("- ...and {} more", count - 5));
    }

    lines.join("\n")
}

/// Levenshtein distance for short strings (method name matching).
fn levenshtein(a: &str, b: &str, max_dist: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > max_dist { return max_dist + 1; }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// For each warning, check if the hallucinated method exists elsewhere
/// in the symbol cache. If so, suggest the correct location.
pub fn enrich_warnings_with_suggestions(warnings: &[String]) -> Vec<String> {
    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return warnings.to_vec(),
    };
    warnings.iter().map(|w| {
        let lower = w.to_lowercase();
        let claim_part = if let Some(idx) = lower.find("api: ") {
            &w[idx + 5..]
        } else if let Some(idx) = lower.find("- ") {
            &w[idx + 2..]
        } else {
            return w.clone();
        };
        let clean = claim_part.trim().trim_end_matches('(').trim();
        let method_name = clean.rsplit('.').next().unwrap_or(clean);
        if method_name.len() < 3 { return w.clone(); }
        let candidates = cache.lookup_global(method_name);
        if let Some(best) = candidates.iter()
            .filter(|s| s.path != clean)
            .min_by_key(|s| levenshtein(clean, &s.path, 10))
        {
            return format!("{} → '{}' exists as {} (in {})", w, clean, best.path, best.library);
        }
        w.clone()
    }).collect()
}
/// Append warning footer to choices[0].message.content of a non-streaming
/// OpenAI-compatible response. Returns the modified JSON string.
///
/// Falls back to the original body if parsing fails — never breaks the
/// response path. Anthropic-native body shape (`content` is array, not str)
/// is handled separately via `append_anthropic_warning`.
fn append_openai_warning_footer(body: &str, footer: &str) -> String {
    let mut v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };
    // Extract current content (immutable borrow), build new value, then
    // assign back via a second mutable traversal. Can't do both in one
    // chain because of borrow-checker rules.
    let new_content = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .map(|s| format!("{}{}", s, footer));

    if let Some(nc) = new_content {
        if let Some(content_field) = v
            .get_mut("choices")
            .and_then(|c| c.get_mut(0))
            .and_then(|c| c.get_mut("message"))
            .and_then(|m| m.get_mut("content"))
        {
            *content_field = serde_json::Value::String(nc);
        }
        return serde_json::to_string(&v).unwrap_or_else(|_| body.to_string());
    }
    body.to_string()
}

/// Build a synthetic OpenAI-format SSE delta chunk carrying `text` as
/// assistant content. Used to inject warning footers into streaming
/// responses BEFORE the upstream's `data: [DONE]` marker.
fn build_warning_delta_chunk(text: &str) -> String {
    // Pure standard OpenAI streaming chunk — no custom fields.
    // Strict schema validators (OpenCode's Protocol.jsonEvent) reject
    // unknown fields like "anubis_warning". Including all standard
    // fields (id, object, created, model) ensures compatibility.
    let json = serde_json::json!({
        "id": format!("chatcmpl-anubis-{}", chrono::Utc::now().timestamp_millis()),
        "object": "chat.completion.chunk",
        "created": chrono::Utc::now().timestamp(),
        "model": "anubis",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}]
    });
    format!("data: {}\n\n", serde_json::to_string(&json).unwrap_or_default())
}


/// Append warning footer to an Anthropic-native non-streaming response body.
/// Anthropic content is an ARRAY of blocks. Appends a new text block.
fn append_anthropic_warning_footer(body: &str, footer: &str) -> String {
    let mut v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return body.to_string(),
    };
    if let Some(arr) = v.get_mut("content").and_then(|c| c.as_array_mut()) {
        arr.push(serde_json::json!({"type":"text","text":footer}));
        return serde_json::to_string(&v).unwrap_or_else(|_| body.to_string());
    }
    body.to_string()
}

/// Build a synthetic Anthropic SSE content_block sequence carrying a warning.
/// Emits start → delta → stop with a sequential block index so Claude Code's
/// SDK accumulates it into the final message content array.
/// Per Anthropic SSE spec: content_block_start/delta/stop must share the
/// same index. Orphan deltas without start/stop are silently dropped by
/// the SDK.
fn build_anthropic_warning_delta(text: &str) -> String {
    // Use index 999 as a sentinel — real blocks are 0-indexed and
    // Claude Code rarely emits more than a handful. A high index avoids
    // collision with model-emitted blocks.
    let index = 999u32;
    let start = serde_json::json!({
        "type":"content_block_start",
        "index":index,
        "content_block":{"type":"text","text":""}
    });
    let delta = serde_json::json!({
        "type":"content_block_delta",
        "index":index,
        "delta":{"type":"text_delta","text":text}
    });
    let stop = serde_json::json!({
        "type":"content_block_stop",
        "index":index
    });
    let start_data = serde_json::to_string(&start).unwrap_or_default();
    let delta_data = serde_json::to_string(&delta).unwrap_or_default();
    let stop_data = serde_json::to_string(&stop).unwrap_or_default();
    format!(
        "event: content_block_start\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\nevent: content_block_stop\ndata: {}\n\n",
        start_data, delta_data, stop_data
    )
}

/// Dispatch warning footer format based on provider.
fn append_warning_footer_for_provider(body: &str, footer: &str, provider: Provider) -> String {
    match provider {
        Provider::Anthropic => append_anthropic_warning_footer(body, footer),
        _ => append_openai_warning_footer(body, footer),
    }
}

/// Dispatch streaming delta format based on provider.
fn build_warning_delta_for_provider(text: &str, provider: Provider) -> String {
    match provider {
        Provider::Anthropic => build_anthropic_warning_delta(text),
        _ => build_warning_delta_chunk(text),
    }
}

/// Find the first SSE event boundary (`\n\n` or `\r\n\r\n`) in a byte buffer.
/// Returns the position AFTER the delimiter (start of next event).
fn find_sse_boundary(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
        if i + 3 < buf.len()
            && buf[i] == b'\r'
            && buf[i + 1] == b'\n'
            && buf[i + 2] == b'\r'
            && buf[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
    }
    None
}

/// Wrap a raw TCP byte stream into a stream of complete SSE events.
///
/// Accumulates raw chunks and yields only data up to (and including) the last
/// `\n\n` boundary. Partial events are held back until the next chunk completes
/// them. This guarantees that downstream consumers (process_stream_chunk) always
/// receive complete SSE events — making mid-stream warning injection safe.
///
/// Per SSE spec §9.2.6, incomplete events at EOF are still forwarded (some
/// providers send `data: [DONE]` without a trailing `\n\n`).
fn sse_buffered_stream(
    upstream: impl futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + 'static,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + 'static {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(64);

    tokio::spawn(async move {
        use futures::StreamExt;
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        let mut upstream = Box::pin(upstream);

        while let Some(result) = upstream.next().await {
            match result {
                Ok(chunk) => {
                    buf.extend_from_slice(&chunk);
                    // Flush all complete SSE events
                    while let Some(pos) = find_sse_boundary(&buf) {
                        let data: Vec<u8> = buf.drain(..pos).collect();
                        if tx.send(Ok(bytes::Bytes::from(data))).await.is_err() {
                            return; // client disconnected
                        }
                    }
                    // Prevent unbounded buffer growth
                    if buf.len() > 1_048_576 {
                        tracing::warn!(target: "proxy", "SSE buffer exceeded 1MB — dropping partial event");
                        buf.clear(); // drop partial event rather than forwarding corrupted bytes
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("upstream stream error: {e}"),
                        )))
                        .await;
                }
            }
        }

        // Flush remaining partial event at EOF (forward as-is)
        if !buf.is_empty() {
            let _ = tx.send(Ok(bytes::Bytes::from(buf))).await;
        }
        drop(tx);
    });

    tokio_stream::wrappers::ReceiverStream::new(rx)
}

/// Extract assistant content text from a non-streaming API response.
/// Used by block+retry to get the corrected response content.
fn extract_content_from_response(body: &str, provider: Provider) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    match provider {
        Provider::Anthropic => Some(
            v.get("content")?
                .as_array()?
                .iter()
                .filter_map(|block| block.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        _ => v
            .get("choices")?
            .get(0)?
            .get("message")?
            .get("content")?
            .as_str()
            .map(|s| s.to_string()),
    }
}

/// Extract tool calls from a NON-STREAMING block+retry response so the
/// retry stream can forward corrected tool calls to the agent.
/// OpenAI: choices[0].message.tool_calls[].
/// Anthropic: content[].type == "tool_use".
fn extract_tool_calls_from_response(
    body: &str,
    provider: Provider,
) -> Option<Vec<serde_json::Value>> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    match provider {
        Provider::Anthropic => {
            let arr = v.get("content")?.as_array()?;
            // Normalize tool_use blocks to the OpenAI shape used everywhere
            // downstream (build_tool_call_stream_* reads function.name /
            // function.arguments; input JSON is re-stringified).
            let tcs: Vec<serde_json::Value> = arr
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                .map(|b| {
                    let input = b.get("input").cloned().unwrap_or(serde_json::json!({}));
                    serde_json::json!({
                        "id": b.get("id").cloned().unwrap_or(serde_json::json!("")),
                        "type": "function",
                        "function": {
                            "name": b.get("name").cloned().unwrap_or(serde_json::json!("")),
                            "arguments": serde_json::to_string(&input).unwrap_or_else(|_| "{}".into())
                        }
                    })
                })
                .collect();
            if tcs.is_empty() { None } else { Some(tcs) }
        }
        _ => {
            let tcs = v
                .get("choices")?
                .get(0)?
                .get("message")?
                .get("tool_calls")?
                .as_array()?
                .clone();
            if tcs.is_empty() { None } else { Some(tcs) }
        }
    }
}

/// Extract only the NEW code from a tool call's arguments.
/// For edit/write tools: returns newString/content only (NOT oldString).
/// For bash/other tools: returns full args. Fail-safe on parse error.
/// For edit tools: returns ONLY the newString/content (not oldString) —
/// returns None if no new-code field is found, so the block decision
/// can distinguish "edit tool with unknown new code" (fail-open: don't
/// block) from "non-edit tool" (block on any hallucination).
fn extract_new_code_from_tool_args(tool_name: &str, args_json: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(args_json).ok()?;
    let is_edit = tool_name.contains("edit")
        || tool_name.contains("write")
        || tool_name.contains("str_replace")
        || tool_name.contains("replace")
        || tool_name.contains("patch")
        || tool_name.contains("apply");
    if is_edit {
        for field in &["newString", "new_string", "content", "newCode", "insertion"] {
            if let Some(s) = parsed.get(*field).and_then(|v| v.as_str()) {
                if !s.is_empty() { return Some(s.to_string()); }
            }
        }
        return None; // Edit tool but no newString found → no new code to scan
    }
    Some(args_json.to_string()) // Non-edit tool → scan full args
}

/// Extract import/use/include statements from a file on disk.
///
/// Used to give FORGE the import context it needs to resolve module
/// aliases (e.g., `import numpy as np` → alias_map["np"] = "numpy").
/// Edit tool calls only send a CHUNK of the file (oldString/newString);
/// import statements at the file top are invisible without this.
fn extract_imports_from_file(file_path: &str) -> String {
    if file_path.is_empty() { return String::new(); }
    let Ok(content) = std::fs::read_to_string(file_path) else {
        tracing::warn!(target: "proxy", file_path = %file_path, "extract_imports: file not readable");
        return String::new();
    };
    let imports: Vec<String> = content.lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.starts_with("import ")
                || t.starts_with("from ")
                || t.starts_with("use ")
                || t.starts_with("#include")
                || t.starts_with("require(")
                || (t.starts_with("const ") && t.contains("require("))
                || (t.starts_with("import *") || t.starts_with("import type "))
            {
                Some(t.to_string())
            } else {
                None
            }
        })
        .collect();
    tracing::info!(target: "proxy", file_path = %file_path, import_count = imports.len(), imports = ?imports.iter().take(5).collect::<Vec<_>>(), "extract_imports: result");
    imports.join("\n")
}

/// Extract ALL code content from tool call args for scanning.
///
/// For edit tools: concatenates oldString + newString (and similar fields)
/// as actual source code — NOT the raw JSON. FORGE's AST parser needs real
/// Python/Rust/TS code, not JSON with code trapped inside string values.
/// Without this, `import numpy as np` inside newString is invisible to
/// the parser → alias_map empty → receiver types unresolved → hallucinated
/// methods like `np.quantum_sort()` pass silently.
///
/// CRITICAL: Edit tools only send a CHUNK of the file (oldString/newString).
/// Import statements at the file top are invisible to FORGE. This function
/// also reads the file from `filePath`, extracts import/use/include lines,
/// and PREPENDS them so FORGE can build alias_map (e.g., np→numpy).
///
/// For non-edit tools (bash etc.): returns full args_json as-is.
/// Best-effort JSON → source-text reconstruction for the scan fail-safe
/// path. When tool args are unparseable (mid-stream SSE truncation) or carry
/// no known code field, the raw JSON used to be scanned as-is — but JSON
/// string values contain literal `\n` escapes, so every line-anchored
/// regex downstream (method-def extraction, import/package line-shape
/// guards, `(?m)^` decl patterns) sees one giant line and misfires
/// (task-010 e2e: `findBy*` interface methods flagged hallucinated because
/// `method_def_re` never matched inside the JSON blob).
///
/// This walker emits the UNESCAPED contents of all JSON string values,
/// with real newlines at structural separators — approximating the
/// original code closely enough for line-anchored analysis.
fn json_to_text_best_effort(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut escape = false;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if !in_string {
            match c {
                '"' => in_string = true,
                '{' | '[' | ',' => out.push('\n'),
                _ => {} // : } ] whitespace — skip
            }
            continue;
        }
        if escape {
            escape = false;
            match c {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'u' => {
                    let mut code = 0u32;
                    for _ in 0..4 {
                        match chars.peek().and_then(|h| h.to_digit(16)) {
                            Some(d) => {
                                code = code * 16 + d;
                                chars.next();
                            }
                            None => break,
                        }
                    }
                    if let Some(ch) = char::from_u32(code) {
                        out.push(ch);
                    }
                }
                other => out.push(other),
            }
            continue;
        }
        match c {
            '\\' => escape = true,
            '"' => in_string = false,
            _ => out.push(c),
        }
    }
    out
}

fn extract_scan_content_from_tool_args(tool_name: &str, args_json: &str) -> String {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(args_json) else {
        // Fail-safe: scan reconstructed text (unescaped string values with
        // real newlines) — raw JSON breaks line-anchored regexes.
        return json_to_text_best_effort(args_json);
    };
    let is_edit = tool_name.contains("edit")
        || tool_name.contains("write")
        || tool_name.contains("str_replace")
        || tool_name.contains("replace")
        || tool_name.contains("patch")
        || tool_name.contains("apply");
    if !is_edit {
        return args_json.to_string();
    }

    // Extract import context from the file on disk.
    let file_path = parsed.get("filePath")
        .or_else(|| parsed.get("file_path"))
        .or_else(|| parsed.get("path"))
        .and_then(|p| p.as_str())
        .unwrap_or("");
    let import_prefix = extract_imports_from_file(file_path);

    // The write/edit this tool-call performs will CHANGE a Python module on
    // disk. Cached introspection ("submodule X does not exist") is now stale
    // and would manufacture hallucinated-import FPs for the rest of the
    // session. Drop the introspect cache for the affected top-level package
    // (derived from the file path: .../notes_cli/database.py -> notes_cli).
    // Detached - must not block the extraction path.
    if file_path.ends_with(".py") {
        if let Some(pkg) = std::path::Path::new(file_path)
            .parent()
            .and_then(|d| d.file_name())
            .and_then(|n| n.to_str())
        {
            let pkg = pkg.to_string();
            tokio::spawn(async move {
                crate::scanner::local_introspect::invalidate_introspect_cache(&pkg).await;
            });
        }
    }

    // COLD-003: prewarm the LSP for this file's language so the cold-start
    // (rust-analyzer 5-60s, csharp-ls 30-45s) overlaps with the agent's
    // edit. By the time `scan_response` runs `lsp_gate::suppress_fps`,
    // the client is warm. No-op for languages without an LSP spawn config
    // (Java/Godot). Spawned as a detached tokio task — must NOT block the
    // tool_call extraction path.
    if !file_path.is_empty() {
        prewarm_lsp_for_file(file_path);
    }

    let mut code = String::new();
    // Prepend import context so FORGE can build alias_map.
    if !import_prefix.is_empty() {
        code.push_str(&import_prefix);
        code.push_str("\n\n");
    }
    // Use ONLY newString/content for scanning. oldString is pre-existing
    // code already scanned in prior edits. Concatenating oldString+newString
    // creates syntactically invalid Python (duplicate defs, orphaned if
    // blocks) → parse_fragments silently skips them → method calls lost.
    for field in &["newString", "new_string", "content", "newCode", "insertion"] {
        if let Some(s) = parsed.get(*field).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                code.push_str(s);
                code.push('\n');
            }
        }
    }
    if code.is_empty() {
        // No known code field (other edit-tool arg shapes): reconstruct
        // text from all string values instead of scanning raw JSON.
        json_to_text_best_effort(args_json)
    } else {
        code
    }
}

/// COLD-003: prewarm the LSP for the file's language based on extension.
///
/// Detects language from extension, resolves workspace root from the file
/// path (walks parents for markers), then spawns a detached tokio task
/// that calls `scanner::lsp::prewarm`. No-op for languages without an LSP
/// config. Must return immediately — this is on the hot tool_call extract
/// path.
///
/// Languages + markers (per lsp_config.rs FOUND-008):
/// - .rs → Rust (Cargo.toml)
/// - .go → Go (go.mod)
/// - .py → Python (pyproject.toml, setup.py)
/// - .ts/.tsx → TypeScript (package.json, tsconfig.json)
/// - .js/.jsx → JavaScript (package.json)
/// - .c/.h → C (compile_commands.json, CMakeLists.txt, Makefile)
/// - .cpp/.cc/.hpp → C++ (same as C)
/// - .cs → C# (global.json, *.csproj)
fn prewarm_lsp_for_file(file_path: &str) {
    let Some(lang) = language_for_extension(file_path) else {
        return;
    };
    let path = std::path::Path::new(file_path);
    // Resolve workspace root using the language's configured markers.
    let cfg = match lang.lsp_config() {
        Some(c) => c,
        None => return,
    };
    let markers: Vec<&str> = cfg.root_markers.iter().copied().collect();
    let Some(workspace) = crate::scanner::lsp::detect_workspace_root(path, &markers) else {
        return;
    };
    // Detached spawn — must not block the tool_call extraction path.
    tokio::spawn(async move {
        crate::scanner::lsp::prewarm(lang, &workspace).await;
    });
}

/// Map a file extension to its `Language` enum value. Returns `None` for
/// languages without LSP support (Java, Godot langs) or unknown extensions.
fn language_for_extension(file_path: &str) -> Option<crate::scanner::language::Language> {
    use crate::scanner::language::Language;
    let ext = file_path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "rs" => Some(Language::Rust),
        "go" => Some(Language::Go),
        "py" | "pyw" => Some(Language::Python),
        "ts" | "tsx" => Some(Language::TypeScript),
        "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "c" | "h" => Some(Language::C),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Some(Language::Cpp),
        "cs" => Some(Language::CSharp),
        _ => None,
    }
}

/// Detect when an agent runs test/build verification commands via tool calls.
/// Passive measurement: logs to target="self_gate" so we can measure what
/// percentage of agents self-gate (run their own verification) before stopping.
/// High self-gate rate → external gate (block+retry) adds redundant latency.
/// Low self-gate rate → external gate has real value.
fn log_self_gate_if_detected(tcs: &[serde_json::Value]) {
    for tc in tcs {
        let name = tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("");
        let args = tc.get("function").and_then(|f| f.get("arguments")).and_then(|a| a.as_str()).unwrap_or("");
        // Only check shell/bash command tools. Match by underscore-split
        // components to avoid false-positives (contains("sh") would match
        // "publish", contains("run") would match "rerun").
        let components: Vec<&str> = name.split('_').collect();
        const SHELL_KEYWORDS: &[&str] = &[
            "bash", "shell", "sh", "execute", "terminal", "run",
            "command", "cmd", "powershell", "pwsh",
        ];
        let is_shell = components.iter().any(|c| SHELL_KEYWORDS.contains(c));
        if !is_shell {
            continue;
        }
        let lower = args.to_lowercase();
        let gate_patterns = [
            "cargo test", "cargo check", "cargo clippy", "cargo build", "cargo fmt",
            "npm test", "npm run test", "npx tsc", "npx jest", "yarn test",
            "pnpm test", "bun test", "npm run build", "npm run lint",
            "go test", "go vet", "go build",
            "pytest", "python -m pytest", "python -m unittest", "tox",
            "ruff check", "mypy", "pyright", "flake8", "black --check",
            "mvn test", "gradle test", "dotnet test", "dotnet build",
            "make test", "make check", "make build",
            "tsc --noemit",
        ];
        for pattern in &gate_patterns {
            if lower.contains(pattern) {
                tracing::info!(
                    target: "self_gate",
                    event = "agent_self_gate",
                    tool = %name,
                    pattern = %pattern,
                    "agent ran verification command"
                );
                return; // One log per scan is enough
            }
        }
    }
}

/// Parse SSE chunks containing OpenAI tool_call deltas and merge into complete objects.
fn extract_tool_calls_from_chunks(chunks: &[bytes::Bytes]) -> Vec<serde_json::Value> {
    let mut calls: Vec<serde_json::Value> = Vec::new();
    // Anthropic wire: tool_use blocks keyed by SSE content-block index.
    // content_block_start carries {id, name}; input_json_delta fragments
    // carry partial JSON that must be concatenated (debt 2ecccf6: the
    // OpenAI-only parser returned nothing on Anthropic streams, making
    // block-mode scans empty and the block+retry loop a no-op).
    let mut anthropic_blocks: std::collections::BTreeMap<u64, (String, String, String)> =
        std::collections::BTreeMap::new(); // index -> (id, name, partial_json)
    let mut saw_anthropic = false;
    for raw in chunks {
        for line in String::from_utf8_lossy(raw).lines() {
            let d = line.trim().strip_prefix("data: ").unwrap_or("");
            if d.is_empty() || d == "[DONE]" { continue; }
            let Ok(j) = serde_json::from_str::<serde_json::Value>(d) else { continue };
            // Anthropic events: data JSON has "type" field at top level.
            if let Some(evt) = j.get("type").and_then(|t| t.as_str()) {
                match evt {
                    "content_block_start" => {
                        let idx = j.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                        if let Some(cb) = j.get("content_block") {
                            if cb.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                                saw_anthropic = true;
                                let id = cb.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                                let name = cb.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                                anthropic_blocks.entry(idx).or_insert((id, name, String::new()));
                            }
                        }
                    }
                    "content_block_delta" => {
                        let idx = j.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                        if let Some(delta) = j.get("delta") {
                            if delta.get("type").and_then(|t| t.as_str()) == Some("input_json_delta") {
                                if let Some(pj) = delta.get("partial_json").and_then(|p| p.as_str()) {
                                    if let Some(entry) = anthropic_blocks.get_mut(&idx) {
                                        entry.2.push_str(pj);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            let Some(choices) = j.get("choices").and_then(|c| c.as_array()) else { continue };
            for ch in choices {
                let Some(deltas) = ch.get("delta").and_then(|d| d.get("tool_calls")).and_then(|t| t.as_array()) else { continue };
                for delta in deltas {
                    let idx = delta.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                    while calls.len() <= idx {
                        calls.push(serde_json::json!({"id":"","type":"function","function":{"name":"","arguments":""}}));
                    }
                    let tc = &mut calls[idx];
                    if let Some(id) = delta.get("id").and_then(|i| i.as_str()) { tc["id"] = id.into(); }
                    if let Some(n) = delta.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()) { tc["function"]["name"] = n.into(); }
                    if let Some(a) = delta.get("function").and_then(|f| f.get("arguments")).and_then(|a| a.as_str()) {
                        let cur = tc["function"]["arguments"].as_str().unwrap_or("");
                        tc["function"]["arguments"] = format!("{cur}{a}").into();
                    }
                }
            }
        }
    }
    // Emit Anthropic tool_use blocks in the SAME normalized OpenAI shape the
    // rest of the block path expects (scan-content extraction, retry body,
    // steering tracker all read tc.function.name / tc.function.arguments).
    if saw_anthropic {
        for (_idx, (id, name, json_args)) in anthropic_blocks {
            calls.push(serde_json::json!({
                "id": id,
                "type": "function",
                "function": { "name": name, "arguments": json_args }
            }));
        }
    }
    calls
}

/// Detect whether a chunk contains the SSE `[DONE]` sentinel.
/// Used to hold [DONE] so we can inject warning chunks before it.
/// Structural tool_call detection: parse SSE data line and inspect delta.
/// Avoids false-positives from prose containing the literal "tool_calls":[
/// (JSON-escaped form still matches substring scan — oracle issue #4).
fn sse_chunk_has_tool_call(chunk: &[u8]) -> bool {
    let text = String::from_utf8_lossy(chunk);
    for line in text.lines() {
        let d = line.trim().strip_prefix("data: ").unwrap_or("");
        if d.is_empty() || d == "[DONE]" { continue; }
        let Ok(j) = serde_json::from_str::<serde_json::Value>(d) else { continue };
        // OpenAI: choices[].delta.tool_calls non-empty array
        if let Some(choices) = j.get("choices").and_then(|c| c.as_array()) {
            for ch in choices {
                if let Some(tcs) = ch.get("delta").and_then(|d| d.get("tool_calls")).and_then(|t| t.as_array()) {
                    if !tcs.is_empty() { return true; }
                }
            }
        }
        // Anthropic: type contains "tool_use" or delta.type == "input_json_delta"
        if j.get("type").and_then(|t| t.as_str()).map_or(false, |t| t.contains("tool_use")) { return true; }
        if j.get("delta").and_then(|d| d.get("type")).and_then(|t| t.as_str()) == Some("input_json_delta") { return true; }
        // Anthropic content_block_start with a tool_use content block: the
        // top-level type is "content_block_start" (no "tool_use" substring),
        // the marker lives in content_block.type. Missing this meant the
        // tool_use start chunk streamed through unheld and the buffered-chunk
        // extractor never saw a start event → tool call never reconstructed.
        if j.get("type").and_then(|t| t.as_str()) == Some("content_block_start") {
            if j.get("content_block").and_then(|c| c.get("type")).and_then(|t| t.as_str()) == Some("tool_use") {
                return true;
            }
        }
    }
    false
}

fn chunk_contains_done(chunk: &[u8]) -> bool {
    // The [DONE] marker is an SSE data line: `data: [DONE]`.
    // We match on the data-line prefix to avoid false-positives from
    // model output that contains the literal string "[DONE]" in text or
    // code (which gets escaped into JSON as `"[DONE]"`, not `data: [DONE]`).
    //
    // We look for `data: [DONE]` as a line-delimited SSE directive:
    // either at the start of the chunk or preceded by `\n`.
    let pattern = b"data: [DONE]";
    if chunk.len() < pattern.len() {
        return false;
    }
    // Check if the chunk starts with the pattern or contains it after \n
    chunk.starts_with(pattern) || {
        chunk.windows(pattern.len()).any(|w| {
            // The byte before this window must be \n (SSE line boundary)
            let start = w.as_ptr() as usize - chunk.as_ptr() as usize;
            start > 0 && chunk[start - 1] == b'\n' && w == pattern
        })
    }
}

//
// Determines which LLM provider a request targets so we can:
//   - Skip OpenAI-specific stream_options for Anthropic (rejected by API)
//   - Parse native SSE event formats (Anthropic uses `event:` lines)
//   - Extract provider-specific features (Anthropic extended thinking)
//
// Detection is path-first (cheapest, deterministic), body-second (fallback
// for proxies that rewrite paths). Unknown defaults to OpenAI-compat
// since that's the de facto standard.

use once_cell::sync::Lazy;
use regex::Regex;
use std::path::PathBuf;
use parking_lot::Mutex as StdMutex;

// ─── Project root auto-detection ────────────────────────────────────
//
// The daemon doesn't know which project the agent is working in. We infer
// it from file paths in the request body — tool call arguments like
// edit("E:\path\to\file.rs", ...) reveal the project root via common prefix.
//
// Detection runs once per project. The cache validates each request's
// paths against the cached root — if none match (user switched
// projects), the cache is invalidated and re-detected. Restart not
// required.

static DETECTED_PROJECT_ROOT: StdMutex<Option<PathBuf>> = StdMutex::new(None);

// Shared forwarding client — avoids re-creating TLS context + connection
// pool on every proxied request (was: Client::builder().build().unwrap()
// per-request, a panic risk + perf hit).
static FORWARD_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .expect("reqwest TLS backend must be available")
});

/// Regex patterns for absolute file paths in request content.
/// Matches Windows (C:\...) and Unix (/home/...) absolute paths.
static RE_WIN_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[A-Z]:\\(?:[^\n"']+\\)*[^\n"']+\.\w{1,10}"#)
        .expect("RE_WIN_PATH invalid")
});

static RE_UNIX_PATH: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"/(?:[^\n"']+/)+[^\n"']+\.\w{1,10}"#)
        .expect("RE_UNIX_PATH invalid")
});

/// Detect the agent's project root from file paths in the request body.
///
/// Walks messages + tool_calls for absolute file paths, finds the common
/// parent directory. Caches result in DETECTED_PROJECT_ROOT — subsequent
/// calls return the cached value without re-parsing.
///
/// Returns None if no paths found (first request, or agent doesn't use
/// absolute paths). Caller falls back to config or current_dir.
pub fn detect_project_root(body: &serde_json::Value) -> Option<PathBuf> {
    let mut paths: Vec<String> = Vec::new();

    // Walk messages for file paths.
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            // Check tool_calls[].function.arguments for file paths
            if let Some(tool_calls) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                for tc in tool_calls {
                    if let Some(args) = tc
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(|a| a.as_str())
                    {
                        collect_paths(args, &mut paths);
                    }
                }
            }
            // Check content string for file paths (system/user messages)
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                collect_paths(content, &mut paths);
            }
            // Check content array (some APIs use array of content blocks)
            if let Some(content_arr) = msg.get("content").and_then(|c| c.as_array()) {
                for block in content_arr {
                    if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                        collect_paths(text, &mut paths);
                    }
                }
            }
        }
    }

    if paths.is_empty() {
        // No file paths in this request — return cached value (if any)
        // so callers without absolute paths still get the previously
        // detected root.
        return DETECTED_PROJECT_ROOT.lock().clone();
    }

    // Cache validation: if any of the current request's paths falls
    // inside the cached root, treat the cache as still valid and skip
    // re-computation. If none match, the user likely switched projects
    // and the cache must be invalidated.
    {
        let cached = DETECTED_PROJECT_ROOT.lock();
        if let Some(ref root) = *cached {
            let root_str = root.to_string_lossy();
            if paths.iter().any(|p| p.starts_with(&*root_str)) {
                return Some(root.clone());
            }
        }
    }
    // Cache empty or stale — recompute.

    // Find common parent directory.
    let root = common_parent_dir(&paths);
    if let Some(ref r) = root {
        tracing::info!(
            target: "proxy",
            root = %r.display(),
            paths_found = paths.len(),
            "detected project root from request file paths"
        );
        // Update cache.
        let mut cached = DETECTED_PROJECT_ROOT.lock();
        *cached = root.clone();
    }

    root
}

/// Extract file paths from a text string using both regex patterns.
fn collect_paths(text: &str, out: &mut Vec<String>) {
    for m in RE_WIN_PATH.find_iter(text) {
        out.push(m.as_str().to_string());
    }
    for m in RE_UNIX_PATH.find_iter(text) {
        out.push(m.as_str().to_string());
    }
}

/// Find the common parent directory from a list of file paths.
///
/// Strategy: take the first path's parent dir as candidate, then shorten
/// it against every other path until we find a common prefix.
fn common_parent_dir(paths: &[String]) -> Option<PathBuf> {
    if paths.is_empty() {
        return None;
    }

    // Filter out system/config/tool directories — they pollute the common
    // parent to the user's home directory (C:\Users\robin).
    // Only keep paths that look like real project source files.
    let filtered: Vec<&String> = paths
        .iter()
        .filter(|p| {
            let l = p.to_lowercase();
            const SKIP: &[&str] = &[
                "\\appdata\\", "\\appdata/",
                "/.config/", "\\.config\\",
                "/.anubis/", "\\.anubis\\",
                "/.cargo/", "\\.cargo\\",
                "/.rustup/", "\\.rustup\\",
                "/.git/", "\\.git\\",
                "/.npm/", "\\.npm\\",
                "/.cache/", "\\.cache\\",
                "/node_modules/", "\\node_modules\\",
                "/.vscode/", "\\.vscode\\",
                "/.claude/", "\\.claude\\",
                "/.opencode/", "\\.opencode\\",
                "/.local/", "\\.local\\",
                "/.gradle/", "\\.gradle\\",
                "/.m2/", "\\.m2\\",
                "/temp/", "\\temp\\",
                "/tmp/", "\\tmp\\",
            ];
            !SKIP.iter().any(|s| l.contains(s))
        })
        .collect();

    if filtered.is_empty() {
        return None;
    }

    // Convert to PathBuf parent dirs.
    let dirs: Vec<PathBuf> = filtered
        .iter()
        .filter_map(|p| {
            let pb = PathBuf::from(p);
            pb.parent().map(|p| p.to_path_buf())
        })
        .collect();

    if dirs.is_empty() {
        return None;
    }

    // Start with first dir, progressively shorten.
    let mut common = dirs[0].clone();
    for dir in &dirs[1..] {
        while !dir.starts_with(&common) {
            if !common.pop() {
                return None;
            }
        }
    }

    // Require 4+ path components to avoid resolving to home directory.
    // Windows: C:\Users\robin = 3 components (too broad).
    //          C:\Users\robin\project = 4 (acceptable).
    // Unix:    /home/user = 2, /home/user/project = 3 (acceptable).
    if common.components().count() < 4 {
        tracing::debug!(
            target: "proxy",
            root = %common.display(),
            components = common.components().count(),
            "common_parent_dir too shallow (< 4 components) — rejecting"
        );
        return None;
    }

    Some(common)
}
// ─── Provider detection ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// OpenAI Chat Completions or any OpenAI-compatible endpoint
    /// (z.ai GLM, OpenRouter, Together, local llama.cpp server, etc.).
    OpenAi,
    /// Anthropic Messages API (`/v1/messages`).
    Anthropic,
    /// Path/body didn't match a known pattern. Treated as OpenAI-compat —
    /// safest default since most providers emulate OpenAI's protocol.
    Unknown,
}

impl Provider {
    /// Detect provider from request path (preferred) + body shape (fallback).
    pub fn detect(path: &str, body: &serde_json::Value) -> Self {
        // Path-based detection is authoritative when present.
        if path.contains("/v1/messages") {
            return Provider::Anthropic;
        }
        if path.contains("/v1/chat/completions") || path.contains("/v1/completions") {
            return Provider::OpenAi;
        }
        if path.contains("/v1beta/models/") || path.contains(":generateContent") {
            // Google Gemini — not yet fully supported, but mark distinctly.
            // Falls through to Unknown handling for now.
        }
        // Body-shape fallback: Anthropic-native requires max_tokens + has
        // top-level `system` field. OpenAI puts system inside messages.
        if body.get("max_tokens").is_some()
            && body.get("system").is_some()
            && body.get("messages").is_some()
        {
            return Provider::Anthropic;
        }
        Provider::Unknown
    }

    /// Whether to inject `stream_options.include_usage` for streaming.
    /// OpenAI needs it; Anthropic always returns usage natively.
    pub fn needs_stream_options(&self) -> bool {
        matches!(self, Provider::OpenAi | Provider::Unknown)
    }

    /// Human-readable name for logging / audit.
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::OpenAi => "openai",
            Provider::Anthropic => "anthropic",
            Provider::Unknown => "unknown",
        }
    }
}


use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing;

/// CLI options for the daemon.
pub struct DaemonOpts {
    pub port: Option<u16>,
    pub host: Option<String>,
}

/// Shared state passed to all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub stats: SharedStats,
    pub config: Arc<RwLock<ANUBISConfig>>,
    /// Pending post-edit verification results waiting to be injected
    /// into the next request. Populated by background verification tasks
    /// after edit/write tool calls, drained by the next proxy_handler call.
    pub pending_verifications: crate::verification::PendingVerifications,

    /// Pending hallucination warnings from deep scans. Populated by the
    /// background deep scan when it finds hallucinations after the response
    /// was already streamed. Drained into the NEXT request as injected
    /// system context so the agent self-corrects on its next turn.
    pub pending_warnings: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Vec<String>>>>,
    /// Council C2: global concurrency cap for deep-scan spawns. Each
    /// proxied request otherwise spawns an unbounded 90s deep-scan task
    /// plus N×MAX_CONCURRENT_L3 LLM calls. Fine for single-user, but a
    /// burst of N simultaneous requests (team/CI) would spawn N×90s
    /// tasks and saturate tokio workers + upstream quota.
    ///
    /// Tunable via config.scanner.max_concurrent_scans (default 8).
    /// Permits up to 8 deep scans in flight; the 9th waits for one to
    /// finish. Held for the whole task lifetime (spawn → timeout/exit).
    pub deep_scan_semaphore: Arc<tokio::sync::Semaphore>,

    /// Block-once-then-passthrough: when block+retry fires for a client,
    /// their client_key is inserted here. The NEXT request from the same
    /// client gets ONE passthrough (block disabled) so the agent can make
    /// progress on retry without getting stuck in a block loop.
    pub block_passthrough: Arc<tokio::sync::Mutex<std::collections::HashSet<String>>>,

    /// Steering rate tracker: maps client_key → (warning_injection_time, warning_tokens).
    /// When a warning is injected, the client is added. On the NEXT request from
    /// the same client, we log whether the response steered away from the warned
    /// tokens, then remove the entry. Enables offline steering-rate analysis.
    pub steering_tracker: Arc<tokio::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, Vec<String>)>>>,
}

use tokio::sync::RwLock;

/// Build the axum Router for the proxy daemon. Extracted from `start_daemon`
/// so integration tests can exercise the full request pipeline (incl. SSE
/// streaming + warning injection) without spawning a TCP listener or going
/// through the license gate.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/", any(root_handler))
        .fallback(proxy_handler)
        .with_state(state)
}

/// Start the daemon.
pub async fn start_daemon(opts: DaemonOpts) -> anyhow::Result<()> {
    let cfg = config::load_config();
    let port = opts.port.unwrap_or(cfg.proxy.port);
    let host = opts.host.unwrap_or_else(|| cfg.proxy.host.clone());

    // Populate user-extendable TS export allow-list from config (council A7).
    // OnceLock: subsequent calls (e.g. config reloads via /__anubis/scanner)
    // are no-ops — first-write-wins. Daemon restart required to pick up
    // changes to scanner.extra_ts_exports.
    if !cfg.scanner.extra_ts_exports.is_empty() {
        crate::scanner::forge_pipeline::set_extra_ts_exports(
            cfg.scanner.extra_ts_exports.clone(),
        );
        tracing::info!(
            "Loaded {} user-provided extra_ts_exports from config",
            cfg.scanner.extra_ts_exports.len()
        );
    }

    // Populate user-extendable Go framework skip-lists from config (A7).
    // Mirrors extra_ts_exports wiring above.
    if !cfg.scanner.extra_go_framework_pkgs.is_empty()
        || !cfg.scanner.extra_go_framework_funcs.is_empty()
    {
        crate::scanner::go_introspect::set_extra_go_framework(
            cfg.scanner.extra_go_framework_pkgs.clone(),
            cfg.scanner.extra_go_framework_funcs.clone(),
        );
        tracing::info!(
            "Loaded {} extra_go_framework_pkgs + {} extra_go_framework_funcs from config",
            cfg.scanner.extra_go_framework_pkgs.len(),
            cfg.scanner.extra_go_framework_funcs.len()
        );
    }

    // Populate user-extendable Rust ecosystem type allow-list (A7).
    if !cfg.scanner.extra_rust_ecosystem_types.is_empty() {
        crate::scanner::rust_ast_extractor::set_extra_rust_ecosystem_types(
            cfg.scanner.extra_rust_ecosystem_types.clone(),
        );
        tracing::info!(
            "Loaded {} user-provided extra_rust_ecosystem_types from config",
            cfg.scanner.extra_rust_ecosystem_types.len()
        );
    }

    // Populate user-extendable L1 fuzzy-match skip list (A7).
    if !cfg.scanner.extra_l1_skip_names.is_empty() {
        crate::scanner::project_index::set_extra_l1_skip_names(
            cfg.scanner.extra_l1_skip_names.clone(),
        );
        tracing::info!(
            "Loaded {} user-provided extra_l1_skip_names from config",
            cfg.scanner.extra_l1_skip_names.len()
        );
    }

    // Activation check at startup (paid license OR trial JWT)
    let has_paid = license::has_license();

    // Single validation call — Keygen is sole source of truth
    let licensed = if has_paid {
        let tier = license::validate_existing().await;
        match tier {
            license::LicenseTier::Licensed => {
                eprintln!("[anubis] License active (offline)");
                true
            }
            _ => {
                eprintln!("[anubis] License validation failed — checking trial...");
                false
            }
        }
    } else {
        false
    };

    if !licensed {
        let trial_state = trial::check_trial();
        match &trial_state {
            trial::TrialState::Active {
                email,
                days_remaining,
                ..
            } => {
                eprintln!(
                    "[anubis] Trial active for {} — {} remaining",
                    email,
                    if *days_remaining <= 1 {
                        format!("{} day", days_remaining)
                    } else {
                        format!("{} days", days_remaining)
                    }
                );
                if *days_remaining <= 2 {
                    eprintln!("[anubis] ⚠ Trial expires soon");
                }
            }
            trial::TrialState::Expired { exp } => {
                let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(*exp as i64, 0)
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".into());
                eprintln!("[anubis] Trial expired on {}.", dt);
                std::process::exit(1);
            }
            trial::TrialState::Invalid => {
                eprintln!("[anubis] Trial token invalid or tampered.");
                eprintln!("[anubis] Re-activate with: anubis activate --trial <token>");
                std::process::exit(1);
            }
            trial::TrialState::NotActivated => {
                eprintln!("[anubis] No trial or license found.");
                eprintln!("[anubis] (License enforcement is disabled in this build — all features unlocked.)");
                eprintln!("[anubis] Activate with: anubis activate --trial <token>");
                std::process::exit(1);
            }
        }
    }

    let max_concurrent_scans = cfg
        .scanner
        .max_concurrent_scans
        .unwrap_or(8);
    let state = AppState {
        stats: stats::create_shared_stats(),
        config: Arc::new(RwLock::new(cfg.clone())),
        pending_verifications: crate::verification::new_pending_verifications(),
        pending_warnings: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        deep_scan_semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent_scans)),
            block_passthrough: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            steering_tracker: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    };

    let target_url = cfg.target_url();
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    eprintln!("[anubis-proxy] proxy started on {} → {}", addr, target_url);
    eprintln!("[anubis-proxy] requests logged to ~/.anubis/proxy.jsonl");

    // Background license check-in (weekly, for subscription policies)
    if has_paid {
        let _check_in_state = state.clone();
        tokio::spawn(async move {
            // Check-in immediately on startup
            match license::check_in().await {
                Ok(_) => tracing::info!("startup check-in successful"),
                Err(e) => {
                    tracing::warn!("startup check-in failed: {} — scanner may be limited", e);
                    eprintln!("[anubis] ⚠ License check-in failed: {}", e);
                }
            }

            // Then check-in every 7 days
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(7 * 24 * 60 * 60));
            interval.tick().await; // skip first tick (already did startup check-in)

            loop {
                interval.tick().await;
                match license::check_in().await {
                    Ok(_) => tracing::info!("weekly check-in successful"),
                    Err(e) => {
                        tracing::warn!("weekly check-in failed: {}", e);
                        eprintln!("[anubis] ⚠ License check-in failed: {}", e);
                        eprintln!("[anubis] Scanner limited. Re-activate with: anubis auth <key>");
                    }
                }
            }
        });
    }

    // Build router — catch-all handler processes both LLM traffic + internal API
    let app = build_app(state);

    // Bind listener with retry — Windows holds ports in TIME_WAIT for up to
    // 4 minutes after process exit. First bind attempt often fails right
    // after deploy.ps1 kills the previous instance. Retry up to 10 times
    // with 1s backoff so the daemon survives the port-free race.
    let listener = {
        const MAX_ATTEMPTS: u32 = 10;
        let mut last_err: Option<String> = None;
        let mut attempt: u32 = 0;
        let bound: Option<tokio::net::TcpListener> = loop {
            attempt += 1;
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => {
                    if attempt > 1 {
                        tracing::info!(
                            target: "proxy",
                            attempt,
                            "listener bound after retry"
                        );
                    }
                    break Some(l);
                }
                Err(e) => {
                    let msg = e.to_string();
                    // EADDRINUSE on Windows = os error 10048.
                    // Don't retry on permission denied (10013) — that's a
                    // permanent problem (port reserved by Hyper-V/WSL/etc).
                    let retryable = msg.contains("10048")
                        || msg.contains("address already in use")
                        || msg.contains("in use");
                    if !retryable || attempt >= MAX_ATTEMPTS {
                        last_err = Some(msg);
                        break None;
                    }
                    tracing::warn!(
                        target: "proxy",
                        attempt,
                        max = MAX_ATTEMPTS,
                        error = %msg,
                        "bind failed, will retry in 1s (port still held by previous instance)"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        };
        match bound {
            Some(l) => l,
            None => {
                return Err(anyhow::anyhow!(
                    "bind {addr} failed after retries: {}",
                    last_err.unwrap_or_else(|| "unknown".to_string())
                ))
            }
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Root path — health check.
async fn root_handler() -> impl IntoResponse {
    (StatusCode::OK, "ANUBIS proxy")
}

/// Extract tool-result content from an intercepted REQUEST body and
/// accumulate its symbols into the per-project session store.
///
/// Fragment-visibility FP fix: when an agent READS a project file (read/glob
/// tool result carrying real source), then quotes or uses symbols from it in
/// its next response, the scanner's scope checkers — which only see the
/// response — flag those real symbols as hallucinated. The proxy sees the
/// full wire: request tool results are ground-truth project code. Accumulating
/// their declarations/imports here makes `emit_forge_warnings`' session_defined
/// filter suppress those FPs on the NEXT response scan.
///
/// Handles both wires:
/// - OpenAI: `messages[]` with `role == "tool"`, `content` = string
/// - Anthropic: `messages[].content[]` with `type == "tool_result"`,
///   content = string or `[{type:"text", text}]`
///
/// Language tag is `""` (universal): these symbols come from real project
/// files, so cross-language suppression is safe — the model cannot
/// "hallucinate" a symbol that verifiably exists in code it just read.
fn accumulate_request_tool_symbols(body_json: &serde_json::Value, root: &str) {
    if root.is_empty() {
        return;
    }
    let Some(messages) = body_json.get("messages").and_then(|m| m.as_array()) else {
        return;
    };

    // Perf: requests carry the FULL message history every turn; without a
    // watermark we'd re-run ~15 regexes over every tool result on every
    // request (O(n²) over session length). Skip contents already processed
    // for this root (64-bit content hash; collision odds negligible).
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, std::collections::HashSet<u64>>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut seen_guard = seen.lock().unwrap_or_else(|p| p.into_inner());
    let seen_set = seen_guard.entry(root.to_string()).or_default();

    let mut accumulate = |text: &str| {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut h);
        if !seen_set.insert(h.finish()) {
            return false; // already processed
        }
        crate::scanner::project_index::accumulate_session_symbols(root, text, "");
        true
    };

    let mut accumulated = 0usize;
    for msg in messages {
        // OpenAI tool-result message: {"role":"tool","content": ...} where
        // content is a plain string OR the spec-legal block form
        // [{"type":"text","text": ...}].
        if msg.get("role").and_then(|r| r.as_str()) == Some("tool") {
            let text: Option<String> = match msg.get("content") {
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(serde_json::Value::Array(blocks)) => {
                    let mut t = String::new();
                    for b in blocks {
                        if b.get("type").and_then(|x| x.as_str()) == Some("text") {
                            if let Some(s) = b.get("text").and_then(|x| x.as_str()) {
                                t.push_str(s);
                            }
                        }
                    }
                    if t.is_empty() { None } else { Some(t) }
                }
                _ => None,
            };
            if let Some(text) = text {
                if !text.trim().is_empty() && accumulate(&text) {
                    accumulated += 1;
                }
            }
            continue;
        }
        // Anthropic tool_result block:
        // {"role":"user","content":[{"type":"tool_result","content": ...}]}
        let Some(blocks) = msg.get("content").and_then(|c| c.as_array()) else {
            continue;
        };
        for block in blocks {
            if block.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
                continue;
            }
            match block.get("content") {
                Some(serde_json::Value::String(text)) => {
                    if !text.trim().is_empty() && accumulate(text) {
                        accumulated += 1;
                    }
                }
                Some(serde_json::Value::Array(parts)) => {
                    for part in parts {
                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                            if !text.trim().is_empty() && accumulate(text) {
                                accumulated += 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    if accumulated > 0 {
        tracing::debug!(
            target: "proxy",
            root = %root,
            tool_results = accumulated,
            "accumulated request tool-result symbols into session store"
        );
    }
}

/// Main proxy handler — intercepts ALL requests except internal API.
async fn proxy_handler(State(state): State<AppState>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();
    let start_time = std::time::Instant::now();

    // ── Internal API check ─────────────────────────────────────────────
    if path.starts_with("/__anubis/") {
        return api::handle_internal_api(path, method, req, state).await;
    }

    // ── Collect request body ──────────────────────────────────────────
    let headers = req.headers().clone();
    let client_key = headers.get("authorization").and_then(|v| v.to_str().ok()).map(|s| s.to_string()).unwrap_or_default();
    let egress_client_key = client_key.clone();

    // ── Steering rate tracker: log if this client was previously warned ──
    {
        let mut tracker = state.steering_tracker.lock().await;
        if let Some((warned_at, tokens)) = tracker.remove(&client_key) {
            let elapsed_ms = warned_at.elapsed().as_millis();
            tracing::info!(
                target: "steering",
                event = "next_request_after_warning",
                elapsed_ms = elapsed_ms,
                warning_tokens = ?tokens,
                "client returning after warning injection — check if response steers away from warned tokens"
            );
        }
    }
    let mut body_bytes = match collect_body(req).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "failed to read body").into_response(),
    };

    // ── Parse body for model + streaming flag ─────────────────────────
    let mut body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
    let model = body_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();

    // ── Detect project root from request content ──────────────────────
    // The daemon runs as a background service — std::env::current_dir()
    // gives the daemon's cwd, NOT the user's project. Instead, we parse file
    // paths from tool call arguments in the intercepted request to find
    // the real project root (walks up looking for .git, package.json, etc.).
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    let detected_root = crate::project_root::detect_project_root(&body_text)
        .await
        .unwrap_or_else(|| {
            std::env::current_dir()
                .map(|d| d.to_string_lossy().to_string())
                .unwrap_or_default()
        });
    tracing::debug!(target: "proxy", root = %detected_root, "project root detected from request");

    // ── Fire cache warming for newly-seen projects ────────────────────
    // First sight of a new project root kicks off a background task that
    // (a) scans the project source for locally-defined symbols and
    // (b) pre-fetches docs.rs/unpkg/Godot-XML bundles for declared deps.
    // Dedup'd per-process — second request to same root is a no-op.
    // See src/cache_warming.rs for design rationale (fire-and-forget vs
    // blocking, dedup semantics).
    if !detected_root.is_empty() {
        crate::cache_warming::maybe_warm_for_project(detected_root.clone());
    }

    // ── Fragment-visibility FP fix: accumulate symbols from tool results ──
    // The request body carries the agent's conversation, including tool
    // results (file contents the agent read). Those are ground-truth project
    // symbols — record them so response scans don't flag quoted-real-code
    // symbols as hallucinated.
    accumulate_request_tool_symbols(&body_json, &detected_root);

    let streaming = body_json
        .get("stream")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    // Detect LLM provider for protocol-specific handling. Determines whether
    // to inject stream_options (OpenAI-only), how to parse SSE events, etc.
    let provider = Provider::detect(&path, &body_json);

    // ── Read config early — needed for auto-doc injection + downstream use ──
    let cfg = state.config.read().await.clone();

    // ── Cold-cache notice (one-shot per process) ──────────────────────
    //
    // When the symbol cache is cold (fresh install), inject a system message
    // into the first LLM request telling the user how to fix it.
    // One-shot: COLD_CACHE_WARNED AtomicBool ensures it fires exactly once.
    if crate::injection::is_cache_cold() {
        let is_anthropic = matches!(provider, Provider::Anthropic);
        if crate::injection::inject_cold_cache_notice(&mut body_json, is_anthropic) {
            if let Ok(new_bytes) = serde_json::to_vec(&body_json) {
                body_bytes = new_bytes;
            }
            tracing::info!(
                target: "injection",
                "cold-cache notice injected — first request with empty symbol cache"
            );
        }
    }

    // ── Auto-doc injection (opt-in via cfg.scanner.auto_inject_docs) ──────
    //
    // When enabled, scans request content for library references
    // (imports/requires/use/includes across all supported languages),
    // queries the symbol cache for each, and injects a focused API
    // reference as a system message BEFORE forwarding upstream.
    //
    // Goal: prevent hallucinations at the source by giving the LLM
    // current API signatures for libraries it's about to use, rather
    // than catching hallucinations after the fact via FORGE.
    //
    // Token budget: 2000 tokens (~8KB). Snippets are deduplicated and
    // prioritized (top-level Functions/Classes/Types before Methods).
    // If a system message already exists, snippets are appended to it
    // rather than replacing the user's existing instructions.
    if cfg.scanner.auto_inject_docs {
        let is_anthropic = matches!(provider, Provider::Anthropic);
        let modified = crate::injection::maybe_inject_docs(
            &mut body_json,
            is_anthropic,
            2000, // max_total_tokens
        )
        .await;
        tracing::info!(
            target: "injection",
            auto_inject_docs = true,
            modified = modified,
            "auto-doc injection check"
        );
        if modified {
            // Re-serialize body_bytes so the forward_body fallback path
            // (non-streaming or no stream_options) uses the modified body.
            if let Ok(new_bytes) = serde_json::to_vec(&body_json) {
                body_bytes = new_bytes;
            }
        }
    }

    // ── Post-edit verification injection ──────────────────────────────
    //
    // Drain any pending verification results from the previous turn's
    // edit/write tool calls. If results exist (e.g., "tsc found 2 errors
    // in main.ts"), inject them as a system message so the LLM sees real
    // compiler output before generating its next response.
    //
    // This runs regardless of whether post_edit_verify is currently enabled
    // — if a previous turn had it enabled and queued results, we should
    // deliver them. The flag only controls whether NEW verifications are
    // spawned, not whether existing results are delivered.
    {
        let verification_text = crate::verification::drain_pending_verifications(
            &state.pending_verifications,
        )
        .await;
        if let Some(text) = verification_text {
            let is_anthropic = matches!(provider, Provider::Anthropic);
            let snippet = crate::injection::DocSnippet {
                library: "post-edit-verification".to_string(),
                version: None,
                text,
                estimated_tokens: 0, // already sized internally
            };
            let modified = crate::injection::inject_into_request(
                &mut body_json,
                &[snippet],
                is_anthropic,
            );
            if modified {
                if let Ok(new_bytes) = serde_json::to_vec(&body_json) {
                    body_bytes = new_bytes;
                }
                tracing::info!(
                    target: "verification",
                    "post-edit verification results injected into request"
                );
            }
        }
    }
    // NOTE: Deferred request-side warning injection REMOVED — caused
    // "prompt exceeds max length" because injected system text bloats
    // every subsequent request. Warning injection is now response-side
    // only: SSE content_block events emitted before message_stop reaches
    // the client (see process_stream_chunk).
    //
    // RE-ENABLED with concise format: the original injection used the full
    // verbose footer (~500+ tokens with markdown formatting). This version
    // injects a ~50-token one-liner so the LLM sees the warning on its next
    // turn without bloating the prompt.
    {
        let drained: Vec<String> = {
            let mut pw = state.pending_warnings.lock().await;
            pw.remove(&client_key).unwrap_or_default()
        };
        if !drained.is_empty() {
            let summary = drained
                .iter()
                .flat_map(|f| f.lines())
                .filter(|l| l.contains("hallucinated") || l.contains("compiler:") || l.contains("Unverified"))
                .take(5)
                .collect::<Vec<_>>()
                .join("\n");
            if !summary.is_empty() {
                let concise = format!(
                    "[Anubis scanner] Your previous response was flagged for potential hallucinations:\n{}\nVerify these APIs exist before using them.",
                    summary
                );
                let is_anthropic = matches!(provider, Provider::Anthropic);
                let snippet = crate::injection::DocSnippet {
                    library: "anubis-warning".to_string(),
                    version: None,
                    text: concise,
                    estimated_tokens: 0,
                };
                let modified = crate::injection::inject_into_request(
                    &mut body_json,
                    &[snippet],
                    is_anthropic,
                );
                if modified {
                    if let Ok(new_bytes) = serde_json::to_vec(&body_json) {
                        body_bytes = new_bytes;
                    }
                    tracing::info!(
                        target: "proxy",
                        "deferred hallucination warning injected into request (concise)"
                    );
                }
            }
        }
    }

    // ── Inject stream_options for usage tracking ──────────────────────
    // OpenAI-compatible APIs (z.ai GLM, OpenAI, etc.) only include token
    // usage in streaming responses when stream_options.include_usage = true.
    // Anthropic's /v1/messages always returns usage natively — injecting
    // stream_options there would be rejected by the API as an unknown field.
    let forward_body = if streaming && provider.needs_stream_options() {
        let mut modified = body_json.clone();
        if let Some(obj) = modified.as_object_mut() {
            obj.insert(
                "stream_options".to_string(),
                serde_json::json!({"include_usage": true}),
            );
        }
        serde_json::to_vec(&modified).unwrap_or_else(|_| body_bytes.clone())
    } else {
        body_bytes.clone()
    };

    // ── Classify request ──────────────────────────────────────────────
    let classification = classify::classify_request(&body_json);
    let request_class = classification.class.class.clone();
    if request_class != "chat" {
        tracing::info!(target: "proxy", request_id, class = %request_class, reason = %classification.reason, "non-chat classified");
    }

    // ── Resolve target ────────────────────────────────────────────────
    // Priority 1: x-anubis-target header (set by harness installer for
    //             harnesses that support custom headers — opencode)
    //             BUT: ignored in Sleev mode — Sleev always routes through
    //             127.0.0.1:17321 regardless of what the header says.
    // Priority 2: Direct mode + no header → harness backup fallback.
    // Priority 3: cfg.target_url() (Sleev / Custom mode global URL)
    let header_target = if matches!(cfg.routing.mode, RoutingMode::Sleev) {
        None // Sleev mode: always route through Sleev gateway
    } else {
        headers
            .get("x-anubis-target")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let target_base = if let Some(ref ht) = header_target {
        ht.trim_end_matches('/').to_string()
    } else if matches!(cfg.routing.mode, RoutingMode::Direct) {
        // No per-request target. Try to identify the source harness from path
        // shape, then fall back to scanning all installed harnesses.
        let candidates: Vec<&str> = if path.starts_with("/v1/messages") {
            // Anthropic API shape — Claude Code, or opencode-via-anthropic.
            vec!["claude-code", "opencode", "cline", "continue"]
        } else if path.starts_with("/v1/chat/completions") {
            // OpenAI API shape — Codex, Continue, or opencode-via-openai.
            vec!["codex", "continue", "opencode", "cline"]
        } else {
            vec!["opencode", "claude-code", "codex", "cline", "continue"]
        };
        let mut found = String::new();
        for hid in candidates {
            if let Some(url) = crate::harness::direct_target_for(hid) {
                found = url.trim_end_matches('/').to_string();
                break;
            }
        }
        found
    } else {
        cfg.target_url().trim_end_matches('/').to_string()
    };
    let target_path = format!("{}{}", target_base, path);

    // ── Forward to upstream ───────────────────────────────────────────
    let client = &*FORWARD_CLIENT;

    let mut fwd_headers = HeaderMap::new();
    for (key, val) in &headers {
        let lk = key.as_str().to_lowercase();
        if is_hop_by_hop(&lk) {
            continue;
        }
        fwd_headers.insert(key.clone(), val.clone());
    }
    // Preserve original content-type if present, default to JSON
    if !fwd_headers.contains_key("content-type") {
        fwd_headers.insert("content-type", HeaderValue::from_static("application/json"));
    }
    // Add target headers (Sleev tags etc.)
    for (key, val) in cfg.target_headers() {
        match (
            HeaderName::from_lowercase(key.to_lowercase().as_bytes()),
            HeaderValue::from_str(&val),
        ) {
            (Ok(name), Ok(value)) => {
                fwd_headers.insert(name, value);
            }
            _ => {
                tracing::warn!(
                    "skipping invalid target header: {}={}",
                    key,
                    val
                );
            }
        }
    }

    let retry_fwd_headers = fwd_headers.clone();

    let upstream_res = match client
        .request(method.clone(), &target_path)
        .headers(fwd_headers)
        .body(forward_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            let mut stats = state.stats.write().await;
            stats.total_errors += 1;
            stats.total_requests += 1;
            if request_class == "compaction" {
                stats.compaction_count += 1;
            }
            if request_class == "background" {
                stats.background_count += 1;
            }
            let entry = RequestLogEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                request_id,
                method: method.to_string(),
                path,
                model,
                streaming,
                status: 502,
                latency_ms: start_time.elapsed().as_millis() as u32,
                ..Default::default()
            };
            stats.push_recent(entry);
            return (
                StatusCode::BAD_GATEWAY,
                format!("ANUBIS proxy: target unreachable: {}", msg),
            )
                .into_response();
        }
    };

    let status = upstream_res.status();
    let response_headers = upstream_res.headers().clone();

    // ── Scanner API key ─────────────────────────────────────────────────
    // Prefer config-provided scanner key. Fall back to inbound Bearer.
    // When scanner endpoint differs from proxy target, inbound key may be wrong provider.
    let inbound_key = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    let scanner_api_key = if !cfg.scanner.api_key.is_empty() {
        cfg.scanner.api_key.clone()
    } else {
        inbound_key.to_string()
    };

    let scanner_model = cfg.scanner.model.clone();
    let scanner_url = cfg.scanner.base_url.clone();
    let scanner_headers = cfg.scanner_headers();

    // Block-once-then-passthrough: if block+retry already fired for this
    // client, give them ONE passthrough so the agent can retry without
    // getting stuck. Flag is consumed on use.
    let block_already_fired = {
        let mut s = state.block_passthrough.lock().await;
        s.remove(&client_key)
    };
    if block_already_fired {
        tracing::info!(target: "proxy", "block passthrough — previous block consumed, letting this attempt through");
    }

    // ── Non-streaming response ────────────────────────────────────────
    if !streaming {
        let response_text = upstream_res.text().await.unwrap_or_default();

        // ── Parse usage from response body ──────────────────────────────
        // Non-streaming OpenAI/Anthropic responses include the final `usage`
        // object directly in the response JSON (no stream_options needed).
        // Without this, the dashboard shows "—" for every non-streaming request.
        let (prompt_tokens, completion_tokens, reasoning_tokens, total_tokens) =
            parse_usage_from_response(&response_text);

        // ── Update basic stats synchronously (tokens + request count) ──
        {
            let mut s = state.stats.write().await;
            s.total_requests += 1;
            s.total_errors += if status.is_success() { 0 } else { 1 };
            if request_class == "compaction" { s.compaction_count += 1; }
            if request_class == "background" { s.background_count += 1; }
            s.prompt_tokens += prompt_tokens;
            s.completion_tokens += completion_tokens;
            s.reasoning_tokens += reasoning_tokens;
            s.total_tokens += total_tokens;
            s.record_latency(start_time.elapsed().as_millis() as u32);
        }

        // ── Spawn background scan (NEVER blocks the response) ──────────
        // Non-streaming responses are forwarded IMMEDIATELY. Scan runs in
        // a background tokio task. This makes the proxy truly transparent
        // — no latency, no timeouts, no killed agent tasks.
        //
        // Tradeoff: non-streaming loses warning footer injection + block+retry.
        // Those are streaming-only features. Non-streaming gets audit + stats
        // + dashboard updates after the fact.
        if status.is_success() {
            let state_bg = state.clone();
            // Extract the assistant's text content from the JSON response
            // wrapper. Without this, scan_response receives raw JSON and
            // can't find code blocks (newlines are escaped as \n in JSON).
            let scan_content_bg = extract_scan_content_from_response(&response_text)
                .unwrap_or_default();
            let response_bg = scan_content_bg;
            let request_id_bg = request_id.clone();
            let method_bg = method.to_string();
            let path_bg = path.clone();
            let model_bg = model.clone();
            let request_class_bg = request_class.clone();
            let scanner_model_bg = scanner_model.clone();
            let scanner_url_bg = scanner_url.clone();
            let scanner_api_key_bg = scanner_api_key.clone();
            let scanner_headers_bg = scanner_headers.clone();
            let detected_root_bg = detected_root.clone();
            let start_bg = start_time;
            let p_tok = prompt_tokens;
            let c_tok = completion_tokens;
            let r_tok = reasoning_tokens;
            let t_tok = total_tokens;
            let status_bg = status;
            let post_edit_verify_bg = cfg.scanner.post_edit_verify;

    tokio::spawn(async move {
                let ctx = ScanContext {
                    project_root: detected_root_bg,
                    logic_model: scanner_model_bg,
                    llm_base_url: scanner_url_bg,
                    llm_api_key: scanner_api_key_bg,
                    llm_extra_headers: scanner_headers_bg,
                    request_class: request_class_bg.clone(),
                    language: String::new(),
                    cancel: tokio_util::sync::CancellationToken::new(),
                };

                use futures::FutureExt;
                use std::panic::AssertUnwindSafe;
                let scan = match AssertUnwindSafe(crate::scanner::scan_response(&response_bg, &ctx))
                    .catch_unwind()
                    .await
                {
                    Ok(s) => s,
                    Err(panic_payload) => {
                        // Scanner panicked. Log + record as scan_failed so the
                        // daemon survives and the dashboard shows something useful.
                        let msg = panic_payload
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| panic_payload.downcast_ref::<String>().map(|s| s.as_str()))
                            .unwrap_or("<non-string panic>");
                        tracing::error!(
                            target: "proxy",
                            panic = %msg,
                            "background scan_response panicked — recording as scan_failed"
                        );
                        let mut fallback = crate::scanner::ScanResultData::default();
                        fallback.scan_failed = true;
                        fallback.details.push(format!("scanner-panic: {}", msg));
                        fallback
                    }
                };

                let (scan_result, mut scan_details) = if !scan.blocks.is_empty() {
                    (ScanResult::Blocked, scan.blocks.clone())
                } else if !scan.warnings.is_empty() {
                    (ScanResult::Warning, scan.warnings.clone())
                } else if scan.scan_failed {
                    (ScanResult::Error, vec!["validator-failed".to_string()])
                } else {
                    (ScanResult::Clean, vec!["scanned".to_string()])
                };
                if scan.scan_failed && !scan.warnings.is_empty() {
                    scan_details.push("validator-failed (warnings from L1/L1.5)".to_string());
                }

                record_scan_outcome(
                    &state_bg.stats,
                    &RequestMeta {
                        request_id: request_id_bg,
                        method: method_bg,
                        path: path_bg,
                        model: model_bg,
                        request_class: request_class_bg.clone(),
                        start: start_bg,
                        client_key: String::new(),
                    },
                    ScanOutcome {
                        scan_result: scan_result.clone(),
                        scan_details: scan_details.clone(),
                        scan_warnings: scan.warnings.clone(),
                        scan_blocks: scan.blocks.clone(),
                        validator_response: scan.validator_response.clone(),
                        validator_tokens: scan.validator_tokens,
                        risk_score: scan.risk_score,
                        confidence: scan.confidence,
                        docs_assisted: scan.docs_assisted,
                    },
                    Some(&serde_json::json!({
                        "prompt_tokens": p_tok,
                        "completion_tokens": c_tok,
                        "reasoning_tokens": r_tok,
                        "total_tokens": t_tok,
                    })),
                    false,
                    status_bg,
                )
                .await;

                tracing::info!(
                    target: "proxy",
                    risk_score = format!("{:.3}", scan.risk_score),
                    result = %scan_result,
                    "background scan completed for non-streaming response"
                );

                // ── Post-edit verification ──────────────────────────────
                //
                // If enabled, detect edit/write tool calls in the response
                // and run compilers/linters on the affected files. Results
                // are queued in state.pending_verifications and injected into
                // the agent's next request as system context.
                //
                // Runs AFTER scan completes (not blocking response). Compiler
                // output is real ground truth — catches the 20% of
                // hallucinations FORGE misses.
                if post_edit_verify_bg {
                    crate::verification::maybe_verify_edits(
                        &response_bg,
                        &ctx.project_root,
                        &state_bg.pending_verifications,
                    )
                    .await;
                }
            });
        }

        // ── Fast scan (L0+L1+L1.5 only, <100ms) for warning injection ──
        // Runs synchronously before returning. If it finds hallucinations,
        // appends footer to response. L3 (validator LLM) runs separately
        // in the background task above. Max added latency: ~100ms.
        let mut final_body = response_text.clone();
        let mut intervention_header = String::new();
        if status.is_success() {
            // Extract content for fast scan too (same JSON wrapper issue)
            let scan_content_fast = extract_scan_content_from_response(&response_text)
                .unwrap_or_default();

            // Passive self-gate measurement for non-streaming path too.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&response_text) {
                if let Some(calls) = v.get("choices").and_then(|c| c.as_array()).and_then(|c| c.first()).and_then(|c| c.get("message")).and_then(|m| m.get("tool_calls")).and_then(|t| t.as_array()) {
                    log_self_gate_if_detected(calls);
                }
            }
            let fast_ctx = ScanContext {
                project_root: std::env::current_dir().map(|d| d.to_string_lossy().to_string()).unwrap_or_default(),
                logic_model: scanner_model.clone(),
                llm_base_url: scanner_url.clone(),
                llm_api_key: String::new(), // EMPTY → skips L3
                llm_extra_headers: scanner_headers.clone(),
                    request_class: request_class.clone(),
                    language: String::new(),
                    cancel: tokio_util::sync::CancellationToken::new(),
            };
            use futures::FutureExt;
            use std::panic::AssertUnwindSafe;
            let fast = match AssertUnwindSafe(crate::scanner::scan_fast(&scan_content_fast, &fast_ctx))
                .catch_unwind()
                .await
            {
                Ok(s) => s,
                Err(panic_payload) => {
                    // Fast scan panicked. Treat as scan_failed so we don't
                    // inject bogus warnings or block on partial data.
                    let msg = panic_payload
                        .downcast_ref::<&str>()
                        .copied()
                        .or_else(|| panic_payload.downcast_ref::<String>().map(|s| s.as_str()))
                        .unwrap_or("<non-string>");
                    tracing::error!(
                        target: "proxy",
                        panic = %msg,
                        "non-streaming fast scan panicked — skipping footer injection"
                    );
                    let mut fallback = crate::scanner::ScanResultData::default();
                    fallback.scan_failed = true;
                    fallback
                }
            };
            let is_tool_call_only = response_text.contains("\"tool_calls\"")
                && !response_text.contains("\"content\"");

            // ── Block mode: replace hallucinated tool call with reasoning ──
            // Engages ONLY when all of:
            //   1. block_on_hallucination is ON in config
            //   2. response actually contains a tool call
            //   3. fast scan found hallucinations above append threshold
            //
            // When engaged, the original response is discarded and replaced
            // with a synthetic assistant message describing why the call was
            // blocked. The agent sees its own "I was blocked" message on the
            // next turn and can self-correct.
            if cfg.scanner.block_on_hallucination && !block_already_fired
                && response_has_tool_calls(&response_text)
                && fast.risk_score >= RISK_THRESHOLD_APPEND
                && !fast.warnings.is_empty()
            {
                let tool_summary = summarize_tool_call(&response_text);
                let reasoning = build_block_message(
                    fast.risk_score,
                    &fast.warnings,
                    &tool_summary,
                );
                final_body = match provider {
                    Provider::Anthropic => serde_json::to_string(
                        &build_block_response_anthropic(&reasoning, &model)
                    ).unwrap_or_else(|_| reasoning.clone()),
                    _ => serde_json::to_string(
                        &build_block_response_openai(&reasoning, &model)
                    ).unwrap_or_else(|_| reasoning.clone()),
                };
                intervention_header = "blocked-tool-call".to_string();
                // Set passthrough so agent's next attempt gets through.
                { let mut s = state.block_passthrough.lock().await; s.insert(client_key.clone()); }
                tracing::info!(
                    target: "proxy",
                    risk_score = format!("{:.3}", fast.risk_score),
                    warnings = fast.warnings.len(),
                    tool = %tool_summary,
                    "non-streaming: BLOCKED tool call (block mode)"
                );
            } else if fast.risk_score >= RISK_THRESHOLD_APPEND && !fast.warnings.is_empty() && !is_tool_call_only {
                let enriched = enrich_warnings_with_suggestions(&fast.warnings);
                let footer = build_warning_footer(fast.risk_score, &enriched, &[]);
                final_body = append_warning_footer_for_provider(&response_text, &footer, provider);
                intervention_header = if fast.risk_score >= RISK_THRESHOLD_BLOCK {
                    "blocked-fast".to_string()
                } else {
                    "footer-appended".to_string()
                };
                tracing::info!(
                    target: "proxy",
                    risk_score = format!("{:.3}", fast.risk_score),
                    warnings = fast.warnings.len(),
                    "non-streaming fast scan: intervention applied"
                );
            }
        }

        // ── Return response (with footer if fast scan found issues) ──────
        let mut out_headers = response_headers.clone();
        out_headers.remove("transfer-encoding");
        if !intervention_header.is_empty() {
            out_headers.insert("x-anubis-risk", HeaderValue::from_static("fast"));
            out_headers.insert(
                "x-anubis-intervention",
                HeaderValue::from_str(&intervention_header).unwrap_or(HeaderValue::from_static("applied")),
            );
        }
        let mut response = Response::new(Body::from(final_body));
        *response.status_mut() = status;
        *response.headers_mut() = out_headers;
        return response;
    }

    // ── Streaming response (SSE) ──────────────────────────────────────
    // Buffer first 8KB, scan for hallucinations, inject warnings,
    // then forward remaining chunks. Periodic re-scan every 16KB.
    //
    // Block mode: when block_on_hallucination is ON and hallucinated tool
    // calls are detected, abort the stream and replace with a synthetic
    // response. The agent never sees the hallucinated tool call — broken
    // code never reaches disk. The agent receives the warning and can
    // reattempt with corrected APIs.
    let preemptive = cfg.scanner.block_on_hallucination && !block_already_fired;
    tracing::info!(target: "proxy", target_path = %target_path, mode = ?cfg.routing.mode, "forwarding request");
    return handle_streaming_response(
        upstream_res,
        status,
        response_headers,
        state.clone(),
        request_id,
        method.to_string(),
        path,
        model,
        start_time,
        request_class,
        scanner_model,
        scanner_url,
        scanner_api_key,
        scanner_headers,
        provider,
        detected_root,
        preemptive,
        egress_client_key,
        body_json,
        target_path,
        retry_fwd_headers,
    )
    .await;
}

/// Collect full body from a request. Caps at 10MB to prevent OOM.
async fn collect_body(req: Request<Body>) -> anyhow::Result<Vec<u8>> {
    use http_body_util::BodyExt;
    const MAX_BODY: usize = 10 * 1024 * 1024; // 10MB
    let bytes = req.into_body().collect().await?.to_bytes();
    if bytes.len() > MAX_BODY {
        return Err(anyhow::anyhow!(
            "request body too large: {} bytes (max {})",
            bytes.len(),
            MAX_BODY
        ));
    }
    Ok(bytes.to_vec())
}

/// Check if a header is hop-by-hop (should not be forwarded).
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// Generate a cryptographically secure auth token.
#[allow(dead_code)]
fn _generate_auth_token_unused() -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // OsRng provides cryptographic randomness
    let uuid = uuid::Uuid::new_v4();
    hasher.update(uuid.as_bytes());
    hasher.update(
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_string(),
    );
    Some(hex::encode(hasher.finalize()))
}

/// Write auth token to ~/.anubis/.daemon-token.
#[allow(dead_code)]
fn _write_auth_token_unused(_token: &str) {}

/// Graceful shutdown signal handler.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received, draining...");
    eprintln!("[anubis] shutting down...");
}

// ---------------------------------------------------------------------------
// Scan outcome consolidation (Phase A1 / S1 + S2)
//
// Both streaming + non-streaming paths assemble a ScanOutcome from their scan
// results and hand it to `record_scan_outcome`, which performs ALL counter
// updates, audit append, and push_recent in one place. Previously the
// streaming path scattered these across ~95 lines and the non-streaming path
// duplicated the logic — a previous parity fix (651d03a) proved how easy it
// is to drift.
//
// `ScanOutcome.scan_warnings` / `scan_blocks` flow into the audit `warnings`
// / `blocks` fields UNFILTERED. The old code filtered audit warnings to just
// the `Unverified API` / `cached-hallucination` prefixes (S2) — most
// warnings (logic:, api-claim:, etc.) were silently dropped from the audit
// trail. Now everything is persisted; the dashboard can filter at display.

/// Request metadata needed to record a scan outcome in stats + audit +
/// recent log. Both streaming and non-streaming paths build one of these
/// from their proxy_handler locals.
struct RequestMeta {
    request_id: String,
    method: String,
    path: String,
    model: String,
    request_class: String,
    start: std::time::Instant,
    client_key: String,
}

/// Snapshot of a completed scan that needs to be recorded. Owns its data so
/// it can be moved across the stats-lock acquisition + audit-write boundary.
struct ScanOutcome {
    scan_result: ScanResult,
    scan_details: Vec<String>,
    scan_warnings: Vec<String>,
    scan_blocks: Vec<String>,
    validator_response: String,
    validator_tokens: u64,
    risk_score: f64,
    confidence: f64,
    docs_assisted: bool,
}

/// Update all counters, write the audit entry, and push a recent log entry.
/// Single source of truth for scan-result bookkeeping — caller does not
/// touch `stats` fields directly.
async fn record_scan_outcome(
    stats: &SharedStats,
    meta: &RequestMeta,
    outcome: ScanOutcome,
    last_usage: Option<&serde_json::Value>,
    streaming: bool,
    status: reqwest::StatusCode,
) {
    let latency_ms = meta.start.elapsed().as_millis() as u32;
    let ts_iso = chrono::Utc::now().to_rfc3339();
    let get_tok = |k: &str| {
        last_usage
            .and_then(|u| u.get(k))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    let p_tok = get_tok("prompt_tokens");
    let c_tok = get_tok("completion_tokens");
    let r_tok = get_tok("reasoning_tokens");
    let t_tok = get_tok("total_tokens");

    // ── Single lock acquisition for counters + recent entries ─────────
    {
        let mut s = stats.write().await;
        s.total_requests += 1;
        if !status.is_success() {
            s.total_errors += 1;
        }
        match outcome.scan_result {
            ScanResult::Clean => s.clean_count += 1,
            ScanResult::Warning => s.warning_count += 1,
            ScanResult::Blocked => s.blocked_count += 1,
            _ => s.skipped_count += 1,
        }
        if meta.request_class == "compaction" {
            s.compaction_count += 1;
        }
        if meta.request_class == "background" {
            s.background_count += 1;
        }
        // Pipeline stage tracking — without this, requests with details
        // like "scanned N chars" but no warnings showed as "not scanned"
        // in the dashboard.
        if !outcome
            .scan_details
            .iter()
            .any(|d| d.contains("timeout") || d.contains("skipped") || d.contains("too few"))
        {
            s.local_check_count += 1;
        }
        if !outcome.validator_response.is_empty() {
            s.validator_calls += 1;
            s.agent_check_count += 1;
        }
        s.validator_tokens += outcome.validator_tokens;
        if outcome.docs_assisted {
            s.docs_hit_count += 1;
        }
        let (cache_hits, _, _) = crate::scanner::verdict_cache_stats();
        s.cache_hit_count = cache_hits;
        s.prompt_tokens += p_tok;
        s.completion_tokens += c_tok;
        s.reasoning_tokens += r_tok;
        s.total_tokens += t_tok;
        s.record_latency(latency_ms);
        s.risk_score_sum += outcome.risk_score;
        s.risk_score_count += 1;

        s.push_recent(RequestLogEntry {
            ts: ts_iso.clone(),
            request_id: meta.request_id.clone(),
            method: meta.method.clone(),
            path: meta.path.clone(),
            model: meta.model.clone(),
            streaming,
            status: status.as_u16(),
            latency_ms,
            prompt_tokens: p_tok,
            completion_tokens: c_tok,
            reasoning_tokens: r_tok,
            total_tokens: t_tok,
            scan_result: outcome.scan_result.clone(),
            scan_details: outcome.scan_details.clone(),
            validator_response: outcome.validator_response.clone(),
            risk_score: outcome.risk_score,
            confidence: outcome.confidence,
        });
    }

    // ── Append to JSONL scan log (single source of truth for dashboard) ──
    crate::scan_log::append(&crate::scan_log::ScanLogLine {
        ts: ts_iso.clone(),
        request_id: meta.request_id.clone(),
        phase: if streaming { "egress".to_string() } else { "fast".to_string() },
        scan_result: outcome.scan_result.to_string(),
        risk_score: outcome.risk_score,
        confidence: outcome.confidence,
        scan_details: outcome.scan_details.clone(),
        validator_response: outcome.validator_response.clone(),
        model: meta.model.clone(),
        streaming,
        status: status.as_u16(),
        latency_ms,
        prompt_tokens: p_tok,
        completion_tokens: c_tok,
        reasoning_tokens: r_tok,
        total_tokens: t_tok,
    });

    // ── Audit append (best-effort — append() swallows I/O errors) ─────
    crate::audit::append(&crate::audit::AuditEntry::from_proxy_data(
        ts_iso,
        meta.request_id.clone(),
        meta.model.clone(),
        meta.path.clone(),
        streaming,
        status.as_u16(),
        latency_ms,
        &outcome.scan_result.to_string(),
        outcome.scan_warnings,
        outcome.scan_blocks,
        outcome.scan_details,
        &outcome.validator_response,
        p_tok,
        c_tok,
        t_tok,
        outcome.risk_score,
    ));
}

// ---------------------------------------------------------------------------

// StreamingState + Phase B helpers (chunk 1 of N)
struct StreamingState {
    full_content: String,
    last_usage: Option<serde_json::Value>,
    sse_buf: String,
    has_text_content: bool,
    midstream_scanned: bool,
    /// Content length when the last scan ran. Used to detect content growth
    /// after a midstream scan — if content keeps arriving (e.g., imports at
    /// end of stream), we re-scan on [DONE] to catch late-arriving
    /// hallucinations the midstream scan missed.
    last_scan_content_len: usize,
    /// True once a warning delta has been injected into the stream. Prevents
    /// duplicate injection if both midstream and [DONE] scans find warnings.
    warning_injected: bool,
    scan_result: ScanResult,
    scan_details: Vec<String>,
    scan_warnings: Vec<String>,
    scan_blocks: Vec<String>,
    validator_response: String,
    scan_validator_tokens: u64,
    scan_risk_score: f64,
    scan_confidence: f64,
    scan_docs_assisted: bool,
    /// True once pre-emptive scan has aborted the stream. When set, all
    /// subsequent upstream chunks are dropped and a synthetic abort message
    /// replaces the response content.
    preemptive_aborted: bool,
    /// Set when preemptive abort fires. Signals the stream pipeline to make
    /// a retry API call with the warning injected as system context.
    needs_retry: bool,
    /// Warning text for the retry system message (e.g., "- forge: hallucinated-variable: __fish_sort__").
    retry_warning_context: String,
    /// When block mode is active, tool_call delta chunks are buffered here
    /// instead of forwarded to the client. At stream end, the accumulated
    /// tool call content is scanned. If hallucinated, buffered chunks are
    /// discarded and a warning+finish_reason:stop+[DONE] replaces them.
    /// If clean, all buffered chunks are flushed at once.
    /// 
    /// This is safe because ALL harnesses defer tool execution until
    /// finish_reason — no harness executes tool calls from partial deltas.
    /// See docs/STREAMING_SCHEMA_REFERENCE.md §3.2.
    tool_call_buffer: Vec<bytes::Bytes>,
    /// True once the first tool_call delta has been buffered. While active,
    /// ALL subsequent chunks (including finish_reason) are held until [DONE].
    buffering_active: bool,
    /// Every chunk withheld while buffering (in arrival order, superset of
    /// tool_call_buffer). The clean-flush path re-emits these so the client
    /// receives a complete, well-ordered stream — without it, held non-tool
    /// chunks (content_block_stop, message_delta, …) were silently dropped
    /// and the client saw a malformed stream.
    held_chunks: Vec<bytes::Bytes>,
}

impl Default for StreamingState {
    fn default() -> Self {
        Self {
            full_content: String::new(),
            last_usage: None,
            sse_buf: String::new(),
            has_text_content: false,
            midstream_scanned: false,
            last_scan_content_len: 0,
            warning_injected: false,
            scan_result: ScanResult::Skipped,
            scan_details: Vec::new(),
            scan_warnings: Vec::new(),
            scan_blocks: Vec::new(),
            validator_response: String::new(),
            scan_validator_tokens: 0,
            scan_risk_score: 0.0,
            scan_confidence: 1.0,
            scan_docs_assisted: false,
            preemptive_aborted: false,
            needs_retry: false,
            retry_warning_context: String::new(),
            tool_call_buffer: Vec::new(),
            buffering_active: false,
            held_chunks: Vec::new(),
        }
    }
}

impl StreamingState {
    /// Push a chunk into the SSE line buffer and process complete lines.
    /// Wraps `process_sse_line` so callers don't need three separate
    /// `&mut s.field` borrows (which the borrow checker rejects when done
    /// inline).
    fn push_chunk(&mut self, chunk: &[u8]) {
        self.sse_buf.push_str(&String::from_utf8_lossy(chunk));
        while let Some(nl) = self.sse_buf.find('\n') {
            let line: String = self.sse_buf.drain(..=nl).collect();
            process_sse_line(
                &line,
                &mut self.full_content,
                &mut self.last_usage,
                &mut self.has_text_content,
            );
        }
    }

    /// Flush any trailing partial line (no terminating newline yet).
    fn flush_partial(&mut self) {
        if !self.sse_buf.is_empty() {
            let line = std::mem::take(&mut self.sse_buf);
            process_sse_line(
                &line,
                &mut self.full_content,
                &mut self.last_usage,
                &mut self.has_text_content,
            );
        }
    }
}


/// Run scan_fast inside the stream transformer. Wraps in catch_unwind +
/// timeout so a scanner panic or stall never truncates the response (R1).
///


async fn run_midstream_scan_with_budget(
    full_content: &str,
    ctx: &ScanContext,
    budget: std::time::Duration,
) -> Result<crate::scanner::ScanResultData, &'static str> {
    use futures::FutureExt;
    use std::panic::AssertUnwindSafe;
    let scan_fut = AssertUnwindSafe(crate::scanner::scan_fast(full_content, ctx)).catch_unwind();
    match tokio::time::timeout(budget, scan_fut).await {
        Ok(Ok(scan)) => Ok(scan),
        Ok(Err(_panic)) => Err("scan-fast-panic"),
        Err(_) => Err("scan-fast-timeout"),
    }
}

/// Apply scan results to streaming state. Sets scan_result, scan_details,
/// scan_warnings, etc. Returns Some(warning_delta_bytes) if risk crossed
/// threshold and the response had text content.
fn apply_scan_to_state(
    s: &mut StreamingState,
    scan: crate::scanner::ScanResultData,
    full_content_len: usize,
    provider: Provider,
    is_terminal: bool,
) -> Option<bytes::Bytes> {
    s.scan_risk_score = scan.risk_score;
    s.scan_confidence = scan.confidence;
    s.scan_warnings = scan.warnings.clone();
    s.scan_blocks = scan.blocks.clone();
    s.scan_validator_tokens = scan.validator_tokens;
    s.scan_docs_assisted = scan.docs_assisted;
    s.validator_response = scan.validator_response.clone();

    if !scan.warnings.is_empty() {
        s.scan_result = ScanResult::Warning;
        s.scan_details.extend(scan.warnings.clone());
        if scan.scan_failed {
            s.scan_details.push("validator-failed (warnings from L1/L1.5)".to_string());
        }
    } else if scan.scan_failed {
        s.scan_result = ScanResult::Error;
        s.scan_details.push("validator-failed".to_string());
    } else {
        s.scan_result = ScanResult::Clean;
        // "scanned N chars" detail removed — noise in explanation panel.
    // Scan size is logged via tracing::info scanResponse end event.
    }

    // SSE boundary buffering (sse_buffered_stream) guarantees that
    // process_stream_chunk always receives complete SSE events. Warning
    // injection is safe because both the warning and the chunk are
    // complete, properly-delimited events.
    // Method 1 deprecation for tool-call responses:
    // Post-hoc annotation after tool calls already executed is structurally
    // late — can't un-execute a bash command or file write. When tool calls
    // are present, suppress the inline footer and rely on deferred injection
    // via egress deep scan → pending_warnings → Method 3 user-append on next
    // request. Inline footer is kept for text-only responses (no tool calls =
    // no structural lateness problem).
    if s.scan_risk_score >= RISK_THRESHOLD_APPEND
        && !s.full_content.is_empty()
        && s.has_text_content
        && !s.warning_injected
        && s.tool_call_buffer.is_empty()
    {
        let enriched = enrich_warnings_with_suggestions(&s.scan_warnings);
        let footer = build_warning_footer(s.scan_risk_score, &enriched, &s.scan_blocks);
        let delta = build_warning_delta_for_provider(&footer, provider);
        s.warning_injected = true;
        tracing::warn!(target: "proxy", risk = s.scan_risk_score, footer_len = footer.len(), "DIAG injection FIRED — warning bytes generated");
        Some(bytes::Bytes::from(delta))
    } else {
        tracing::warn!(
            target: "proxy",
            risk = s.scan_risk_score,
            threshold = RISK_THRESHOLD_APPEND,
            content_empty = s.full_content.is_empty(),
            has_text = s.has_text_content,
            already_injected = s.warning_injected,
            "DIAG injection BLOCKED — gate condition failed"
        );
        None
    }
}

/// Per-chunk stream transformer. Returns a Vec of chunks to emit (in order)
/// for this one upstream chunk. Usually just the original chunk, but when
/// midstream scan triggers + risk crossed, prepends a warning delta.
///
/// Three phases (lock acquired + released 2x max per chunk):
///   1. Accumulate chunk into shared state, decide if scan should fire
///   2. Run scan WITHOUT holding lock (egress isn't blocked)
///   3. Apply scan results + queue warning delta if risk crossed
async fn process_stream_chunk(
    state: &std::sync::Arc<tokio::sync::Mutex<StreamingState>>,
    chunk: bytes::Bytes,
    scanner_model: &str,
    scanner_url: &str,
    scanner_api_key: &str,
    scanner_headers: &[(String, String)],
    request_class: &str,
    provider: Provider,
    preemptive_scan: bool,
) -> Vec<Result<bytes::Bytes, std::io::Error>> {
    let is_done = chunk_contains_done(&chunk);
    // Detect message_stop (Anthropic terminal event) — this arrives BEFORE
    // [DONE] and signals the model is done emitting. We must inject any
    // warning content_blocks BEFORE message_stop reaches the client.
    // Once the SDK sees message_stop, it closes the stream.
    let has_message_stop = chunk.iter().any(|b| *b == b'{')
            && String::from_utf8_lossy(&chunk).contains("\"message_stop\"");

    // Force a final scan on message_stop — the midstream scan may have
    // returned risk=0 (FORGE not complete), but now we have the full
    // content. This is our LAST chance to inject before the client
    // closes the stream.
    let force_final_scan = has_message_stop;

    // Anthropic ping events are passthrough — buffering them kills keep-alive.
    // Computed once, used in both buffer-push (Phase 1) and holding check.
    let is_ping = String::from_utf8_lossy(&chunk).contains("\"ping\"");

    // Phase 1: Update state under lock, decide if scan should run.
    let scan_needed;
    let already_aborted;
    let buffering_active;
    {
        let mut s = state.lock().await;
        // If pre-emptive scan already aborted this stream, drop all chunks.
        if s.preemptive_aborted {
            already_aborted = true;
            scan_needed = false;
            buffering_active = false;
        } else {
            already_aborted = false;
            if is_done || force_final_scan {
                s.flush_partial();
            }
            if !is_done && !force_final_scan {
                s.push_chunk(&chunk);
            }

            // ── Tool call buffering (block mode) ──────────────────────
            // When block_on_hallucination is active, detect tool_call delta
            // chunks and hold them in tool_call_buffer. At stream end, the
            // accumulated content is scanned — hallucinated tool calls are
            // discarded, clean ones are flushed. This is safe because ALL
            // harnesses defer tool execution until finish_reason.
            // See docs/STREAMING_SCHEMA_REFERENCE.md §3.2 + §4.4.
            // Structural check: parse the SSE data line and inspect delta
            // fields. Avoids false-positives from prose containing the
            // literal string "tool_calls":[ which JSON-escapes to
            // \"tool_calls\":[ — the unescaped pattern still matches
            // inside the escaped form (oracle review issue #4).
            let has_tool_call = sse_chunk_has_tool_call(&chunk);
            if preemptive_scan {
                if has_tool_call && !s.buffering_active {
                    s.buffering_active = true;
                    tracing::info!(
                        target: "proxy",
                        "tool_call buffering activated — holding chunks until scan completes"
                    );
                }
            }

            let content_len = s.full_content.len();
            let usage_arrived = s.last_usage.is_some();

        // Midstream scan: fire once when content crosses 500 chars OR usage
        // arrives (early signal that stream is ending). Skips if already
        // scanned. Goal: catch obvious hallucinations early so warning can
        // be injected before too much content streams.
        let midstream_should_fire = !s.midstream_scanned
            && content_len > 50
            && (content_len >= 500 || usage_arrived);

        // Final scan on [DONE]: re-scan if content grew since the last scan.
        // Critical for streams where imports/code appear LATE — without this,
        // a midstream scan at 500 chars misses hallucinations in the trailing
        // content. Threshold: must have grown by ≥10% or ≥50 chars (whichever
        // is smaller) to justify re-scan cost.
        let growth = content_len.saturating_sub(s.last_scan_content_len);
        let growth_threshold = (s.last_scan_content_len / 10).max(50);
        let done_should_rescan = is_done
            && content_len > 50
            && s.midstream_scanned
            && growth >= growth_threshold;

        // Also scan on [DONE] if no scan has fired at all (short streams).
        let done_first_scan = is_done && !s.midstream_scanned && content_len > 50;

        // Force scan at stream end when buffering tool calls — must decide
        // whether to flush buffered chunks or discard them.
        let buffer_flush = s.buffering_active && (is_done || force_final_scan);

        scan_needed = midstream_should_fire || done_should_rescan || done_first_scan || force_final_scan || buffer_flush;
        buffering_active = s.buffering_active;
        if scan_needed {
            s.midstream_scanned = true;
            s.last_scan_content_len = content_len;
        }

        // Always collect tool_call chunks for code extraction, even when
        // block mode is OFF. Without this, non-block scans run on raw JSON
        // (full_content) instead of extracted Python/Rust/TS code → FORGE
        // can't see imports/defs → hallucinations like np.chronosort pass
        // silently. Block mode only controls HOLDING chunks, not collecting.
        //
        // Anthropic ping events are passthrough — buffering them kills
        // keep-alive and can cause client timeouts (Oracle M3).
        if has_tool_call && !is_done && !force_final_scan && !is_ping {
            s.tool_call_buffer.push(chunk.clone());
        }
        } // close else block
    }

    // If stream was already aborted by pre-emptive scan, drop this chunk.
    if already_aborted {
        return Vec::new();
    }

    // If buffering tool calls and this isn't the terminal event, hold the
    // chunk (recorded in held_chunks so the clean flush can re-emit it in
    // order — the chunk must reach the client eventually). Terminal events
    // pass through to Phase 2/3 where the scan + flush/block decision is made.
    // Anthropic ping events pass through to maintain keep-alive (Oracle M3).
    if buffering_active && !is_done && !force_final_scan && !is_ping {
        let mut s = state.lock().await;
        s.held_chunks.push(chunk.clone());
        return Vec::new();
    }

    // Phase 2 + 3: Scan + apply.
    if scan_needed {
        // When block mode is active and tool calls are buffered, scan the
        // EXTRACTED code content (not raw JSON) so FORGE's AST parser can
        // see imports, defs, and method calls. Track which code is NEW
        // (newString) so the block decision can skip warnings from
        // pre-existing fakes in oldString context.
        let (scan_content, has_text_content, new_code, has_edit_tool) = {
            let s = state.lock().await;
            if !s.tool_call_buffer.is_empty() {
                let tcs = extract_tool_calls_from_chunks(&s.tool_call_buffer);
                // Passive measurement: detect if agent ran test/build commands
                log_self_gate_if_detected(&tcs);
                let mut full_code = String::new();
                let mut new_only = String::new();
                let mut saw_edit = false;
                for tc in &tcs {
                    let name = tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("");
                    let args_str = tc.get("function").and_then(|f| f.get("arguments")).and_then(|a| a.as_str()).unwrap_or("");
                    let is_edit = name.contains("edit")
                        || name.contains("write")
                        || name.contains("str_replace")
                        || name.contains("replace")
                        || name.contains("patch")
                        || name.contains("apply");
                    if is_edit { saw_edit = true; }
                    // Extract ACTUAL CODE from args (not raw JSON) for scanning.
                    // Without this, FORGE can't see imports/defs inside JSON values.
                    full_code.push_str(&extract_scan_content_from_tool_args(name, args_str));
                    full_code.push('\n');
                    if let Some(n) = extract_new_code_from_tool_args(name, args_str) {
                        new_only.push_str(&n);
                        new_only.push('\n');
                    }
                }
                (full_code, s.has_text_content, new_only, saw_edit)
            } else {
                (s.full_content.clone(), s.has_text_content, String::new(), false)
            }
        };
        let ctx = ScanContext {
            project_root: std::env::current_dir().map(|d| d.to_string_lossy().to_string()).unwrap_or_default(),
            logic_model: scanner_model.to_string(),
            llm_base_url: scanner_url.to_string(),
            llm_api_key: scanner_api_key.to_string(),
            llm_extra_headers: scanner_headers.to_vec(),
            request_class: request_class.to_string(),
            language: String::new(),
            cancel: tokio_util::sync::CancellationToken::new(),
        };
        let budget = if is_done || force_final_scan {
            std::time::Duration::from_secs(60)
        } else {
            std::time::Duration::from_secs(5)
        };
        let scan_result = if is_done || force_final_scan {
            // Terminal scan: use full scan_response pipeline (FORGE L2 + C#
            // compiler gate) instead of scan_fast (L0+L1+L1.5 only). The
            // compiler gate needs the full response to parse all using
            // directives for auto-PackageReference injection. Tool calls are
            // already buffered — 2-5s overhead is invisible to user.
            match tokio::time::timeout(budget, crate::scanner::scan_response(&scan_content, &ctx)).await {
                Ok(result) => Ok(result),
                Err(_) => Ok(crate::scanner::ScanResultData { scan_failed: true, ..Default::default() }),
            }
        } else {
            run_midstream_scan_with_budget(&scan_content, &ctx, budget).await
        };
        match scan_result {
            Ok(scan) => {
                let (warning_bytes, risk_score, has_warnings, warnings, blocks) = {
                    let mut s = state.lock().await;
                    let wb = apply_scan_to_state(&mut s, scan, scan_content.len(), provider, is_done || force_final_scan);
                    (
                        wb,
                        s.scan_risk_score,
                        !s.scan_warnings.is_empty(),
                        s.scan_warnings.clone(),
                        s.scan_blocks.clone(),
                    )
                };

                // ── Pre-emptive scan: abort the stream on hallucination ──
                //
                // When enabled, if the midstream scan detects hallucinations
                // above the risk threshold, we abort the upstream stream
                // immediately. The client receives a synthetic abort message
                // instead of the hallucinated content. This saves tokens
                // (no more chunks consumed from upstream) and gives the
                // agent immediate feedback to self-correct.
                //
                // Only fires once (preemptive_aborted flag prevents re-entry).
                // Subsequent chunks are dropped via the already_aborted guard
                // at the top of this function.
                if preemptive_scan && buffering_active && has_warnings && risk_score >= RISK_THRESHOLD_APPEND {
                    // Only block if at least one hallucinated token appears in
                    // the NEW code (newString). If all warnings come from
                    // oldString context (pre-existing fakes), skip the block —
                    // the warnings are still stored for deferred injection.
                    let new_has_hallucination = if !has_edit_tool {
                        true // Non-edit tool (bash etc.) — block on all hallucinations
                    } else if new_code.is_empty() {
                        false // Edit tool but couldn't extract newString → fail-open (don't block)
                    } else {
                        warnings.iter().any(|w| {
                            // Extract the backtick-quoted token from the warning
                            // and check if it appears in the new code.
                            if let Some(start) = w.find('`') {
                                if let Some(end) = w[start + 1..].find('`') {
                                    let token = &w[start + 1..start + 1 + end];
                                    return new_code.contains(token);
                                }
                            }
                            // Fallback: check if any word from the warning appears
                            w.split_whitespace()
                                .any(|word| word.len() > 4 && new_code.contains(word))
                        })
                    };
                    if !new_has_hallucination {
                        tracing::info!(target: "proxy", "block skipped — hallucinations only in oldString context");
                    } else {
                    // ── Block hallucinated tool calls ──────────────────────
                    // Block: set retry flags and hold chunks for block+retry.
                    // The chain closure at stream-end will make a second API
                    // call with tool_error context. The agent sees a natural
                    // tool error → correction sequence, not an authority block.
                    {
                        let mut s = state.lock().await;
                        s.preemptive_aborted = true;
                        s.warning_injected = true;
                        s.needs_retry = true;
                        s.retry_warning_context = warnings.iter().take(5).cloned().collect::<Vec<_>>().join("\n");
                        // Record the block for the audit trail (blocks[] field).
                        // Without this the intervention is invisible in audit —
                        // the receipt run showed empty blocks[] on the
                        // streaming path.
                        if s.scan_blocks.is_empty() {
                            let first = warnings.first().cloned().unwrap_or_default();
                            s.scan_blocks.push(format!(
                                "blocked tool call (risk {risk_score:.2}): {first}"
                            ));
                        }
                        // DON'T clear tool_call_buffer — chain closure needs it
                    }
                    tracing::info!(
                        target: "proxy",
                        risk = risk_score,
                        warnings = warnings.len(),
                        buffered = buffering_active,
                        "pre-emptive scan: holding tool calls for block+retry"
                    );
                    return Vec::new(); // hold everything — chain closure handles retry
                    } // close else (new_has_hallucination)
                }

                // ── Clean: flush buffered tool calls if any ──────────────
                // Tool calls were held while scanning. Now that scan is clean,
                // release them to the client. Re-emit ALL held chunks in
                // arrival order (held_chunks is the ordered superset — the
                // tool-call chunks plus the structural events around them)
                // so the client stream stays complete and well-formed.
                if buffering_active {
                    let buffered: Vec<bytes::Bytes> = {
                        let mut s = state.lock().await;
                        s.buffering_active = false; // stop buffering after flush
                        std::mem::take(&mut s.tool_call_buffer);
                        std::mem::take(&mut s.held_chunks)
                    };
                    let mut result: Vec<Result<bytes::Bytes, std::io::Error>> =
                        buffered.into_iter().map(Ok).collect();
                    if let Some(bytes) = warning_bytes {
                        let _ = has_text_content;
                        result.push(Ok(bytes));
                    }
                    result.push(Ok(chunk));
                    return result;
                }

                if let Some(bytes) = warning_bytes {
                    let _ = has_text_content; // already used inside apply
                    return vec![Ok(bytes), Ok(chunk)];
                }
            }
            Err(detail) => {
                let mut s = state.lock().await;
                tracing::error!(target: "proxy", detail, "scan_fast failed inside stream transformer");
                s.scan_result = ScanResult::Error;
                s.scan_details.push(detail.to_string());
            }
        }
    }

    // Final fallback: flush any remaining buffered chunks (fail-open on
    // scan error or when scan didn't run). Better to let the tool call
    // through than hold it indefinitely.
    if buffering_active {
        let buffered: Vec<bytes::Bytes> = {
            let mut s = state.lock().await;
            s.buffering_active = false;
            std::mem::take(&mut s.tool_call_buffer)
        };
        if !buffered.is_empty() {
            let mut result: Vec<Result<bytes::Bytes, std::io::Error>> =
                buffered.into_iter().map(Ok).collect();
            result.push(Ok(chunk));
            return result;
        }
    }

    vec![Ok(chunk)]
}

/// Egress task: runs AFTER the stream is fully consumed (sentinel fired).
/// Takes a snapshot of accumulated state, runs scan_fast if midstream never
/// fired, calls record_scan_outcome (stats + audit + recent log), and
/// spawns a top-level deep scan if risk warrants it.
///
/// Top-level task (not nested inside the stream closure) so a panic in any
/// phase doesn't prevent later phases from running (A2).
async fn run_streaming_egress(
    state: std::sync::Arc<tokio::sync::Mutex<StreamingState>>,
    stats: SharedStats,
    meta: RequestMeta,
    scanner_model: String,
    scanner_url: String,
    scanner_api_key: String,
    scanner_headers: Vec<(String, String)>,
    status: reqwest::StatusCode,
    project_root: String,
    deep_scan_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    pending_warnings: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Vec<String>>>>,
    client_key: String,
) {
    let (
        full_content,
        last_usage,
        mut scan_result,
        mut scan_details,
        mut scan_warnings,
        mut scan_blocks,
        mut validator_response,
        mut scan_validator_tokens,
        mut scan_risk_score,
        mut scan_confidence,
        mut scan_docs_assisted,
        midstream_scanned,
        last_scan_content_len,
    ) = {
        let s = state.lock().await;
        (
            s.full_content.clone(),
            s.last_usage.clone(),
            s.scan_result.clone(),
            s.scan_details.clone(),
            s.scan_warnings.clone(),
            s.scan_blocks.clone(),
            s.validator_response.clone(),
            s.scan_validator_tokens,
            s.scan_risk_score,
            s.scan_confidence,
            s.scan_docs_assisted,
            s.midstream_scanned,
            s.last_scan_content_len,
        )
    };

    // Re-scan if midstream scan ran on PARTIAL content (content grew after
    // the scan). Egress runs after stream end, so we have the full content
    // now. Critical for catching hallucinations in trailing chunks that the
    // midstream scan missed. Also runs if no scan fired at all (short streams
    // that never crossed the 500-char threshold).
    let content_grew = full_content.len() > last_scan_content_len;
    let should_scan = !midstream_scanned || content_grew;
    if should_scan && full_content.len() > 50 {
        let ctx = ScanContext {
            project_root: project_root.clone(),
            logic_model: scanner_model.clone(),
            llm_base_url: scanner_url.clone(),
            llm_api_key: scanner_api_key.clone(),
            llm_extra_headers: scanner_headers.clone(),
            request_class: meta.request_class.clone(),
            language: String::new(),
            cancel: tokio_util::sync::CancellationToken::new(),
        };
        match run_midstream_scan_with_budget(&full_content, &ctx, std::time::Duration::from_secs(60)).await {
            Ok(scan) => {
                scan_risk_score = scan.risk_score;
                scan_confidence = scan.confidence;
                scan_warnings = scan.warnings.clone();
                scan_blocks = scan.blocks.clone();
                scan_validator_tokens = scan.validator_tokens;
                scan_docs_assisted = scan.docs_assisted;
                validator_response = scan.validator_response.clone();
                if !scan.warnings.is_empty() {
                    scan_result = ScanResult::Warning;
                    scan_details.extend(scan.warnings.clone());
                    if scan.scan_failed {
                        scan_details.push("validator-failed (warnings from L1/L1.5)".to_string());
                    }
                } else if scan.scan_failed {
                    scan_result = ScanResult::Error;
                    scan_details.push("validator-failed".to_string());
                } else {
                    scan_result = ScanResult::Clean;
                    scan_details.push(format!("scanned {} chars", full_content.len()));
                }
            }
            Err(detail) => {
                tracing::error!(target: "proxy", detail, "scan_fast failed inside egress");
                scan_result = ScanResult::Error;
                scan_details.push(detail.to_string());
            }
        }
    }

    record_scan_outcome(
        &stats,
        &meta,
        ScanOutcome {
            scan_result: scan_result.clone(),
            scan_details: scan_details.clone(),
            scan_warnings,
            scan_blocks,
            validator_response: validator_response.clone(),
            validator_tokens: scan_validator_tokens,
            risk_score: scan_risk_score,
            confidence: scan_confidence,
            docs_assisted: scan_docs_assisted,
        },
        last_usage.as_ref(),
        true,
        status,
    )
    .await;

    // Always spawn deep scan — it's the authoritative result.
    // The fast scan (5s timeout) may miss warnings or time out with risk=0.
    // The deep scan is bounded by DEEP_SCAN_TIMEOUT (90s) so a stuck
    // upstream or runaway validator cannot pin a tokio worker forever.
    // Mirrors egress spawn pattern at proxy.rs:2760 (60s stream-end wait).
    const DEEP_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
    if !full_content.is_empty() {
        let deep_state = stats.clone();
        let deep_request_class = meta.request_class.clone();
        let deep_request_id = meta.request_id.clone();
        let deep_model = scanner_model.clone();
        let deep_url = scanner_url.clone();
        let deep_key = scanner_api_key.clone();
        let deep_headers = scanner_headers.clone();
        // Council C2: acquire a permit before doing real work. The
        // semaphore lives on AppState and is sized from
        // config.scanner.max_concurrent_scans (default 8). The permit
        // is held for the full task lifetime — including the 90s
        // DEEP_SCAN_TIMEOUT — and released on drop when the task exits.
        //
        // We acquire inside the spawned task (not before spawning) so
        // the spawn itself is never back-pressured: a queued acquire
        // still occupies a tokio worker slot, but the request handler
        // is never blocked waiting for the spawn. This matches how
        // most bounded-concurrency patterns in proxy code are written.
        let deep_semaphore = deep_scan_semaphore.clone();
        tokio::spawn(async move {
            // Wait for a slot before any scan work begins. Under heavy
            // load this is where the 9th concurrent request parks; under
            // normal load the permit returns immediately.
            let _permit = match deep_semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    // Semaphore closed — daemon is shutting down.
                    // Skip this scan rather than running unbounded.
                    return;
                }
            };
            let deep_started = std::time::Instant::now();
            let deep_ctx = ScanContext {
                project_root: project_root.clone(),
                logic_model: deep_model,
                llm_base_url: deep_url,
                llm_api_key: deep_key,
                llm_extra_headers: deep_headers,
                request_class: deep_request_class,
            language: String::new(),
            cancel: tokio_util::sync::CancellationToken::new(),
            };
            // Clone before the timeout so the Err arm can fire .cancel().
            // The token is shared with every sub-task scan_response spawns
            // (auto_fetch_missing, refresh_local_cache, L3 per-claim) via
            // the spawned children's `ctx.cancel.clone()`.
            let deep_cancel = deep_ctx.cancel.clone();
            // Bound the await on the deep scan. On timeout, drop the
            // scan_response future (cancels its pending await points),
            // cancel the token (signals detached sub-tasks to exit),
            // log, and append an Error result so scan_log records the
            // timeout.
            //
            // Without the cancel, sub-tasks that scan_response already
            // spawned (auto_fetch_missing at scanner/mod.rs, local cache
            // refresh, L3 per-claim spawns in l3_per_claim.rs) keep
            // running and write to cache/logs after this task exits.
            let deep = match tokio::time::timeout(
                DEEP_SCAN_TIMEOUT,
                crate::scanner::scan_response(&full_content, &deep_ctx),
            ).await {
                Ok(deep) => deep,
                Err(_elapsed) => {
                    deep_cancel.cancel();
                    tracing::warn!(
                        target: "proxy",
                        phase = "deep",
                        duration_ms = deep_started.elapsed().as_millis(),
                        timeout_secs = DEEP_SCAN_TIMEOUT.as_secs(),
                        "deep scan timed out — recording Error and exiting task"
                    );
                    crate::scan_log::append(&crate::scan_log::ScanLogLine {
                        ts: chrono::Utc::now().to_rfc3339(),
                        request_id: deep_request_id.clone(),
                        phase: "deep".to_string(),
                        scan_result: ScanResult::Error.to_string(),
                        risk_score: 0.0,
                        confidence: 0.0,
                        scan_details: vec![format!(
                            "deep-scan-timeout-{}s",
                            DEEP_SCAN_TIMEOUT.as_secs()
                        )],
                        validator_response: String::new(),
                        model: String::new(),
                        streaming: true,
                        status: 200,
                        latency_ms: deep_started.elapsed().as_millis() as u32,
                        prompt_tokens: 0,
                        completion_tokens: 0,
                        reasoning_tokens: 0,
                        total_tokens: 0,
                    });
                    let _ = deep_state; // touch clone to silence unused warning
                    return;
                }
            };

            // Determine final scan result from deep scan
            let (deep_result, deep_details) = if !deep.blocks.is_empty() {
                (ScanResult::Blocked, deep.blocks.clone())
            } else if !deep.warnings.is_empty() {
                (ScanResult::Warning, deep.warnings.clone())
            } else if deep.scan_failed {
                (ScanResult::Error, vec!["validator-failed".to_string()])
            } else {
                (ScanResult::Clean, vec![format!("scanned {} chars (deep)", full_content.len())])
            };

            tracing::info!(
                target: "proxy",
                phase = "deep",
                duration_ms = deep_started.elapsed().as_millis(),
                risk_score = format!("{:.3}", deep.risk_score),
                warnings = deep.warnings.len(),
                validator = !deep.validator_response.is_empty(),
                "streaming deep scan completed (background)"
            );

            // Append to JSONL scan log — warnings-wins dedup ensures
            // this deep scan result does NOT overwrite an earlier egress
            // scan warning with a clean result.
            crate::scan_log::append(&crate::scan_log::ScanLogLine {
                ts: chrono::Utc::now().to_rfc3339(),
                request_id: deep_request_id.clone(),
                phase: "deep".to_string(),
                scan_result: deep_result.to_string(),
                risk_score: deep.risk_score,
                confidence: deep.confidence,
                scan_details: deep_details,
                validator_response: deep.validator_response.clone(),
                model: String::new(),
                streaming: true,
                status: 200,
                latency_ms: deep_started.elapsed().as_millis() as u32,
                prompt_tokens: 0,
                completion_tokens: 0,
                reasoning_tokens: 0,
                total_tokens: 0,
            });

            // Deferred injection: if the deep scan found hallucinations,
            // queue a warning for the NEXT request. The agent will see it
            // as injected system context on its next turn and self-correct.
            if deep.risk_score >= 0.3 && !deep.warnings.is_empty() {
                let footer = build_warning_footer(deep.risk_score, &deep.warnings, &deep.blocks);
                if !footer.is_empty() {
                    pending_warnings.lock().await.entry(client_key.clone()).or_default().push(footer);
                    tracing::info!(
                        target: "proxy",
                        phase = "deep",
                        risk_score = format!("{:.3}", deep.risk_score),
                        warnings = deep.warnings.len(),
                        "hallucination warning queued for deferred injection on next request"
                    );
                }
            }
        });
    }
}


/// Handle a streaming SSE response: forward chunks immediately, scan at end.
/// Build a provider-correct SSE stream from a text message.
/// Used by block+retry to emit corrected or error responses.
fn build_retry_sse(text: &str, model: &str, provider: Provider) -> bytes::Bytes {
    let sse = match provider {
        Provider::Anthropic => build_block_stream_anthropic(text, model),
        _ => build_block_stream_openai(text, model),
    };
    bytes::Bytes::from(sse)
}

/// Execute block+retry: make a 2nd API call with tool_error context so the
/// LLM sees a natural tool-error -> correction sequence.
///
/// The retry is necessary because the proxy sits between the harness and the
/// API. The proxy cannot prevent the harness from executing tool_calls it
/// already received. Buffering + retry is the only approach that both
/// prevents execution AND gives the LLM deterministic correction context.
///
/// Future: harness-native plugins (OpenCode, Claude Code) could handle blocks
/// client-side and eliminate this retry. The proxy must not depend on them.
async fn execute_block_retry(
    retry_body: &serde_json::Value,
    retry_target: &str,
    retry_fwd_headers: &reqwest::header::HeaderMap,
    provider: Provider,
    buffered: &[bytes::Bytes],
    warning_context: &str,
    risk: f64,
    egress_notify: &std::sync::Arc<tokio::sync::Notify>,
) -> bytes::Bytes {
    let tcs = extract_tool_calls_from_chunks(buffered);
    let model = retry_body.get("model").and_then(|m| m.as_str()).unwrap_or("anubis");

    if tcs.is_empty() {
        tracing::warn!(target: "proxy", "block+retry: no parseable tool calls — fail-open");
        egress_notify.notify_one();
        return build_retry_sse("", model, provider);
    }

    let is_anthropic = matches!(provider, Provider::Anthropic);
    let mut body = retry_body.clone();
    if let Some(o) = body.as_object_mut() { o.insert("stream".into(), false.into()); }
    // Provider-correct retry body. The upstream conversation must contain the
    // blocked attempt followed by a tool error, in each wire's native shape:
    //   OpenAI:    assistant {tool_calls:[...]} + role:"tool" {tool_call_id}
    //   Anthropic: assistant content [{type:"tool_use",...}] + user content
    //              [{type:"tool_result", is_error:true, ...}]
    // The old OpenAI-only shape made Anthropic retries 400 → text fallback
    // (debt 2ecccf6).
    if let Some(msgs) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        if is_anthropic {
            let blocks: Vec<serde_json::Value> = tcs
                .iter()
                .map(|tc| {
                    let args = tc
                        .get("function").and_then(|f| f.get("arguments"))
                        .and_then(|a| a.as_str())
                        .unwrap_or("{}");
                    let input: serde_json::Value =
                        serde_json::from_str(args).unwrap_or(serde_json::json!({}));
                    serde_json::json!({
                        "type": "tool_use",
                        "id": tc.get("id").and_then(|i| i.as_str()).unwrap_or("blocked"),
                        "name": tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("tool"),
                        "input": input
                    })
                })
                .collect();
            let results: Vec<serde_json::Value> = tcs
                .iter()
                .map(|tc| {
                    serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": tc.get("id").and_then(|i| i.as_str()).unwrap_or("blocked"),
                        "content": warning_context,
                        "is_error": true
                    })
                })
                .collect();
            msgs.push(serde_json::json!({"role":"assistant","content":blocks}));
            msgs.push(serde_json::json!({"role":"user","content":results}));
        } else {
            msgs.push(serde_json::json!({"role":"assistant","content":null,"tool_calls":tcs}));
            for tc in &tcs {
                let id = tc.get("id").and_then(|i| i.as_str()).unwrap_or("blocked");
                let _name = tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("tool");
                msgs.push(serde_json::json!({
                    "role":"tool","tool_call_id":id,
                    "content":format!("{}", warning_context)
                }));
            }
        }
    }

    let _ = crate::injection::maybe_inject_docs(&mut body, is_anthropic, 2000).await;

    tracing::info!(target: "proxy", "block+retry: tool_error simulation");
    let client = &*FORWARD_CLIENT;
    match tokio::time::timeout(
        std::time::Duration::from_secs(120),
        client.post(retry_target).headers(retry_fwd_headers.clone()).json(&body).send(),
    ).await {
        Ok(Ok(resp)) if resp.status().is_success() => {
            if let Ok(text) = resp.text().await {
                let retry_tcs = extract_tool_calls_from_response(&text, provider);
                let content = extract_content_from_response(&text, provider)
                    .or_else(|| retry_tcs.as_ref().map(|_| String::new()));
                if let Some(content) = content {
                    tracing::info!(
                        target: "proxy",
                        tool_calls = retry_tcs.as_ref().map_or(0, |t| t.len()),
                        "block+retry: streaming corrected response"
                    );
                    egress_notify.notify_one();
                    match (retry_tcs, provider) {
                        // OpenAI chain: forward corrected tool calls as native
                        // tool_calls deltas so the agent executes them — the
                        // closed block → tool_error → correction loop.
                        (Some(tcs), Provider::OpenAi | Provider::Unknown) => {
                            return bytes::Bytes::from(build_tool_call_stream_openai(
                                &content, &tcs, model,
                            ));
                        }
                        // Anthropic chain: forward corrected tool_use blocks
                        // as native content_block_start/input_json_delta
                        // events so the agent executes them (debt 2ecccf6).
                        (Some(tcs), Provider::Anthropic) => {
                            return bytes::Bytes::from(build_tool_call_stream_anthropic(
                                &content, &tcs, model,
                            ));
                        }
                        (None, _) => return build_retry_sse(&content, model, provider),
                    }
                }
                tracing::warn!(target: "proxy", "block+retry: couldn't extract content");
            }
        }
        Ok(Ok(r)) => tracing::warn!(target: "proxy", status = %r.status(), "block+retry: non-success"),
        Ok(Err(e)) => tracing::warn!(target: "proxy", error = %e, "block+retry: API call failed"),
        Err(_) => tracing::warn!(target: "proxy", "block+retry: timed out after 120s"),
    }

    egress_notify.notify_one();
    build_retry_sse("Tool call failed. Try a different approach.", model, provider)
}

/// Used when block_on_hallucination is OFF — preserves streaming UX and
/// appends warning footer if risk crosses threshold.
#[allow(clippy::too_many_arguments)]
async fn handle_streaming_response(
    upstream_res: reqwest::Response,
    status: reqwest::StatusCode,
    response_headers: reqwest::header::HeaderMap,
    state: AppState,
    request_id: String,
    method: String,
    path: String,
    model: String,
    start_time: std::time::Instant,
    request_class: String,
    scanner_model: String,
    scanner_url: String,
    scanner_api_key: String,
    scanner_headers: Vec<(String, String)>,
    provider: Provider,
    project_root: String,
    preemptive_scan: bool,
    client_key: String,
    retry_body: serde_json::Value,
    retry_target: String,
    retry_fwd_headers: reqwest::header::HeaderMap,
) -> Response {
    use futures::StreamExt;

    let shared = std::sync::Arc::new(tokio::sync::Mutex::new(StreamingState::default()));
    let egress_notify = std::sync::Arc::new(tokio::sync::Notify::new());

    let egress_state = shared.clone();
    let egress_signal = egress_notify.clone();
    let egress_stats = state.stats.clone();
    let egress_meta = RequestMeta {
        request_id,
        method,
        path,
        model,
        request_class: request_class.clone(),
        start: start_time,
        client_key: client_key.clone(),
    };
    let egress_status = status;
    let egress_scanner_model = scanner_model.clone();
    let egress_scanner_url = scanner_url.clone();
    let egress_scanner_api_key = scanner_api_key.clone();
    let egress_scanner_headers = scanner_headers.clone();
    let egress_project_root = project_root.clone();
    let egress_deep_scan_semaphore = state.deep_scan_semaphore.clone();
    let egress_pending_warnings = state.pending_warnings.clone();
    let egress_ck = egress_meta.client_key.clone();
    tokio::spawn(async move {
        // Wait for the stream-end sentinel. If the consumer drops the body
        // before reaching the sentinel (client disconnect, R2), the Notify
        // never fires — bound that wait so the egress task doesn't leak.
        // 60s is generous: real streams finish in seconds, but a stuck
        // upstream shouldn't pin a tokio worker forever.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            egress_signal.notified(),
        ).await;
        run_streaming_egress(
            egress_state,
            egress_stats,
            egress_meta,
            egress_scanner_model,
            egress_scanner_url,
            egress_scanner_api_key,
            egress_scanner_headers,
            egress_status,
            egress_project_root,
            egress_deep_scan_semaphore,
            egress_pending_warnings,
            egress_ck,
        )
        .await;
    });

    let transform_state = shared.clone();
    let transform_scanner_model = scanner_model.clone();
    let transform_scanner_url = scanner_url.clone();
    let transform_scanner_api_key = scanner_api_key.clone();
    let transform_scanner_headers = scanner_headers.clone();
    let transform_request_class = request_class.clone();
    let transform_provider = provider;
    let transform_preemptive_scan = preemptive_scan;

    let body_stream = sse_buffered_stream(upstream_res.bytes_stream())
        .then(move |result| {
            let s = transform_state.clone();
            let sm = transform_scanner_model.clone();
            let su = transform_scanner_url.clone();
            let sk = transform_scanner_api_key.clone();
            let sh = transform_scanner_headers.clone();
            let rc = transform_request_class.clone();
            async move {
                match result {
                    Ok(chunk) => process_stream_chunk(
                        &s,
                        chunk,
                        &sm,
                        &su,
                        &sk,
                        &sh,
                        &rc,
                        transform_provider,
                        transform_preemptive_scan,
                    )
                    .await,
                    Err(e) => vec![Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("upstream stream error: {e}"),
                    ))],
                }
            }
        })
        .flat_map(futures::stream::iter)
        // Stream-end: if block fired, make retry API call with tool_error
        // context so the agent sees a natural tool-error→correction sequence.
        // Otherwise flush orphaned buffer (fail-open) and send sentinel.
        .chain(futures::stream::once({
            let rs = shared.clone();
            let rb = retry_body.clone();
            let rt = retry_target.clone();
            let rp = provider;
            let rn = egress_notify.clone();
            let rh = retry_fwd_headers.clone();
            let bp = state.block_passthrough.clone();
            let bp_key = client_key.clone();
            let st = state.steering_tracker.clone();
            let ck = client_key.clone();
            async move {
                let (nr, ctx, buf, risk) = {
                    let s = rs.lock().await;
                    (s.needs_retry, s.retry_warning_context.clone(), s.tool_call_buffer.clone(), s.scan_risk_score)
                };

                // ── Block+retry: 2nd API call with tool_error context ──
                if nr && !buf.is_empty() {
                    // Set passthrough flag so the agent's next attempt gets
                    // through without re-blocking. Block once, not forever.
                    { let mut s = bp.lock().await; s.insert(bp_key); }
                    return Ok::<_, std::io::Error>(
                        execute_block_retry(&rb, &rt, &rh, rp, &buf, &ctx, risk, &rn).await
                    );
                }

                // ── Normal path: flush orphaned buffer + sentinel ─────
                let orphaned: Vec<bytes::Bytes> = {
                    let mut s = rs.lock().await;
                    if s.buffering_active && (!s.tool_call_buffer.is_empty() || !s.held_chunks.is_empty()) {
                        tracing::warn!(target: "proxy", count = s.tool_call_buffer.len(), "orphaned buffer — fail-open flush");
                        s.buffering_active = false;
                        std::mem::take(&mut s.tool_call_buffer);
                        std::mem::take(&mut s.held_chunks)
                    } else { Vec::new() }
                };

                // ── Steering tracker: if warning was injected, record tokens ──
                {
                    let s = rs.lock().await;
                    if s.warning_injected && !s.scan_warnings.is_empty() {
                        let tokens: Vec<String> = s.scan_warnings.iter()
                            .filter_map(|w| {
                                // Try backtick-quoted tokens first (forge_python, forge_rust).
                                if let Some(start) = w.find('`') {
                                    if let Some(end) = w[start+1..].find('`') {
                                        return Some(w[start+1..start+1+end].to_string());
                                    }
                                }
                                // Fallback: single-quoted tokens (TS2339 'sum').
                                if let Some(start) = w.find('\'') {
                                    if let Some(end) = w[start+1..].find('\'') {
                                        return Some(w[start+1..start+1+end].to_string());
                                    }
                                }
                                // Fallback: identifier after last colon (Hallucinated API: X).
                                if let Some(pos) = w.rfind(':') {
                                    let candidate = w[pos+1..].trim().trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '.');
                                    if candidate.len() > 2 && candidate.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false) {
                                        return Some(candidate.to_string());
                                    }
                                }
                                None
                            })
                            .take(5)
                            .collect();
                        if !tokens.is_empty() {
                            tracing::info!(
                                target: "steering",
                                event = "warning_injected",
                                warning_tokens = ?tokens,
                                "warning injected — watching next request for steering"
                            );
                            st.lock().await.insert(ck.clone(), (std::time::Instant::now(), tokens));
                        }
                    }
                }

                rn.notify_one();
                let mut out = String::new();
                for b in orphaned { out.push_str(&String::from_utf8_lossy(&b)); }
                out.push_str(": anubis-stream-end\n\n");
                Ok::<_, std::io::Error>(bytes::Bytes::from(out))
            }
        }));

    let body = Body::from_stream(body_stream);
    let mut response = Response::new(body);
    *response.status_mut() = status;

    let mut out_headers = response_headers;
    out_headers.remove("transfer-encoding");
    *response.headers_mut() = out_headers;
    response
}


/// Process one SSE line: extract content delta + usage object.
/// Replaces the per-chunk `extract_sse_content` + `extract_usage_from_sse` pair
/// — calling this per buffered line survives TCP chunk splits inside a single
/// `data: {...}` event.
///
/// `has_text_content` is set to true whenever a chat-content delta is observed
/// (OpenAI `delta.content` or Anthropic `delta.text` / `delta.thinking`).
/// The streaming handler uses it to detect tool-call-only responses where
/// injecting a content delta would corrupt the agent's JSON parser.
pub fn process_sse_line(
    line: &str,
    full_content: &mut String,
    last_usage: &mut Option<serde_json::Value>,
    has_text_content: &mut bool,
) {
    // Strip trailing CR (CRLF line endings)
    let line = line.trim_end_matches('\r');
    let Some(data) = line.strip_prefix("data: ") else {
        return;
    };
    if data == "[DONE]" {
        return;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
        return;
    };

    // ── Content extraction (OpenAI delta format) ─────────────────────
    // deltas arrive inside choices[0].delta as content / reasoning_content /
    // tool_calls[].function.arguments. Tool-call args are streamed as JSON
    // fragments — accumulating them lets the scanner see code the LLM is
    // writing via write/edit/bash tool calls, not just chat text.
    if let Some(delta) = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
    {
        if let Some(c) = delta.get("content").and_then(|c| c.as_str()) {
            full_content.push_str(c);
            *has_text_content = true;
        }
        // Reasoning/thinking content is NOT added to full_content.
        // Internal monologue contains pseudocode, variable names, and
        // design notes that trigger FORGE false positives. Scanning
        // tool calls (write/edit/bash) and chat text is sufficient —
        // thought scanning will be a separate opt-in feature later.
        // if let Some(r) = delta.get("reasoning_content").and_then(|r| r.as_str()) {
        //     full_content.push_str(r);
        //     *has_text_content = true;
        // }
        if let Some(tool_calls) = delta.get("tool_calls").and_then(|t| t.as_array()) {
            for tc in tool_calls {
                if let Some(args) = tc
                    .get("function")
                    .and_then(|f| f.get("arguments"))
                    .and_then(|a| a.as_str())
                {
                    full_content.push_str(args);
                }
            }
        }
    }

    // ── Anthropic delta content_block ────────────────────────────────
    // Anthropic streams `content_block_delta` events with `delta.text` (or
    // `delta.partial_json` for tool args, `delta.thinking` for extended
    // thinking, `delta.signature` for thinking signatures). Captures Claude's
    // chat content + reasoning content.
    // Anthropic event types: message_start, content_block_start,
    // content_block_delta, content_block_stop, message_delta, message_stop.
    //
    // delta.type values we handle:
    //   - text_delta       → delta.text (chat content)
    //   - input_json_delta → delta.partial_json (tool_use args)
    //   - thinking_delta   → delta.thinking (extended thinking content)
    //   - signature_delta  → delta.signature (thinking signature, ignored)
    if let Some(text) = v
        .get("delta")
        .and_then(|d| d.get("text"))
        .and_then(|t| t.as_str())
    {
        full_content.push_str(text);
        *has_text_content = true;
    }
    if let Some(pj) = v
        .get("delta")
        .and_then(|d| d.get("partial_json"))
        .and_then(|t| t.as_str())
    {
        full_content.push_str(pj);
    }
    // Anthropic extended thinking — NOT scanned. Same rationale as
    // reasoning_content above: internal monologue triggers FPs.
    // if let Some(thinking) = v
    //     .get("delta")
    //     .and_then(|d| d.get("thinking"))
    //     .and_then(|t| t.as_str())
    // {
    //     full_content.push_str(thinking);
    //     *has_text_content = true;
    // }

    // ── Usage extraction (multi-provider) ────────────────────────────
    // OpenAI/z.ai: usage.prompt_tokens / completion_tokens / total_tokens
    //             / reasoning_tokens
    // Anthropic:  usage.input_tokens / output_tokens (cumulative)
    //             — map to (prompt, completion, 0, total)
    // Final chunk with stream_options.include_usage=true carries the final
    // tally. Later chunks overwrite earlier ones (correct — we want final).
    if let Some(usage) = v.get("usage") {
        *last_usage = Some(normalize_usage(usage));
    }
}

/// Normalize a usage object from any provider into OpenAI's field names.
///
/// OpenAI sends `prompt_tokens` / `completion_tokens` / `total_tokens` /
/// `reasoning_tokens`. Anthropic sends `input_tokens` / `output_tokens`
/// (and `cache_creation_input_tokens` / `cache_read_input_tokens` which
/// we don't track separately). Map Anthropic → OpenAI so the dashboard
/// shows non-zero token counts for Claude traffic through the proxy.
fn normalize_usage(usage: &serde_json::Value) -> serde_json::Value {
    let prompt = usage
        .get("prompt_tokens")
        .and_then(|v| v.as_u64())
        .or_else(|| usage.get("input_tokens").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let completion = usage
        .get("completion_tokens")
        .and_then(|v| v.as_u64())
        .or_else(|| usage.get("output_tokens").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let reasoning = usage
        .get("reasoning_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total = usage
        .get("total_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(prompt + completion);
    serde_json::json!({
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "reasoning_tokens": reasoning,
        "total_tokens": total,
    })
}

/// Parse a non-streaming response body for the usage object.
/// Returns (prompt, completion, reasoning, total). All zero on parse failure
/// or missing usage — the caller treats zero as "no token data" for display.
///
/// Handles both OpenAI field names (`prompt_tokens` / `completion_tokens`)
/// and Anthropic field names (`input_tokens` / `output_tokens`). Without
/// Anthropic mapping, Claude traffic through the proxy showed 0 tokens on
/// the dashboard.
fn parse_usage_from_response(body: &str) -> (u64, u64, u64, u64) {
    let v = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => v,
        Err(_) => return (0, 0, 0, 0),
    };
    let Some(usage) = v.get("usage") else {
        return (0, 0, 0, 0);
    };
    let normalized = normalize_usage(usage);
    let get_u64 = |k: &str| normalized.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    (
        get_u64("prompt_tokens"),
        get_u64("completion_tokens"),
        get_u64("reasoning_tokens"),
        get_u64("total_tokens"),
    )
}

/// Extract text content PLUS tool_call args as actual code for scanning.
///
/// `extract_message_content` only gets text — tool_call args (where code
/// lives for edit/write tools) are invisible. Without this, non-streaming
/// fast scan can never detect hallucinated tool calls. This function
/// extracts text via `extract_message_content`, then walks tool_calls,
/// resolving each via `extract_scan_content_from_tool_args` (which parses
/// JSON args + reads file imports from disk).
fn extract_scan_content_from_response(body: &str) -> Option<String> {
    let text = extract_message_content(body).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(body).ok()?;

    // OpenAI format: choices[0].message.tool_calls[]
    let tool_calls_openai = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array());

    // Anthropic format: content[].type == "tool_use"
    let tool_calls_anthropic = v
        .get("content")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                .collect::<Vec<_>>()
        });

    let mut code = text;
    if let Some(calls) = tool_calls_openai {
        for tc in calls {
            let name = tc.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("");
            let args = tc.get("function").and_then(|f| f.get("arguments")).and_then(|a| a.as_str()).unwrap_or("");
            if !code.is_empty() { code.push('\n'); }
            code.push_str(&extract_scan_content_from_tool_args(name, args));
        }
    }
    if let Some(blocks) = tool_calls_anthropic {
        for b in blocks {
            let name = b.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = b.get("input").map(|i| i.to_string()).unwrap_or_default();
            if !code.is_empty() { code.push('\n'); }
            code.push_str(&extract_scan_content_from_tool_args(name, &args));
        }
    }
    if code.is_empty() { None } else { Some(code) }
}

/// Extract the assistant's text content from a non-streaming OpenAI/Anthropic
/// response JSON body. Without this, scan_response receives raw JSON and
/// extract_code_blocks_only can't find ```markdown fences (newlines are
/// escaped as \n in JSON, so the entire response is effectively one line).
///
/// Returns the unescaped content string, or None if the body isn't valid
/// JSON or doesn't match either provider format.
fn extract_message_content(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    // OpenAI format: choices[0].message.content
    if let Some(content) = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        return Some(content.to_string());
    }
    // Anthropic format: content[0].text
    if let Some(content) = v
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
    {
        return Some(content.to_string());
    }
    // Fallback: bare completion format (choices[0].text)
    if let Some(content) = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
    {
        return Some(content.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        build_block_message, build_block_response_anthropic, build_block_response_openai,
        build_block_stream_anthropic, build_block_stream_openai, parse_usage_from_response,
        process_sse_line, Provider, response_has_tool_calls, summarize_tool_call, ScanResult,
        detect_project_root, DETECTED_PROJECT_ROOT, json_to_text_best_effort,
        accumulate_request_tool_symbols, extract_tool_calls_from_chunks,
        build_tool_call_stream_anthropic,
    };

    // ── accumulate_request_tool_symbols (fragment-visibility FP fix) ────

    #[test]
    fn accumulate_openai_tool_result_makes_symbol_session_defined() {
        let root = format!("/test-fragvis-openai-{}", std::process::id());
        // Simulated request: agent read a file whose content defines `Database`.
        let body = serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "fix the bug"},
                {"role": "assistant", "content": "reading file"},
                {"role": "tool",
                 "content": "from sqlite3 import dbapi2 as Database\n\nclass Wrapper:\n    def query(self):\n        return Database.connect(x)\n"}
            ]
        });
        accumulate_request_tool_symbols(&body, &root);
        let session = crate::scanner::project_index::get_session_symbols(&root, "");
        assert!(
            session.contains("Database"),
            "aliased import from tool result must be session-defined, got: {session:?}"
        );
        assert!(
            session.contains("Wrapper"),
            "class decl from tool result must be session-defined, got: {session:?}"
        );
    }

    #[test]
    fn accumulate_anthropic_tool_result_string_and_block_forms() {
        let root = format!("/test-fragvis-anthropic-{}", std::process::id());
        let body = serde_json::json!({
            "model": "claude",
            "system": "sys",
            "max_tokens": 100,
            "messages": [
                {"role": "user", "content": [
                    {"type": "tool_use", "id": "t1", "name": "read", "input": {"path": "a.py"}},
                    {"type": "tool_result", "tool_use_id": "t1",
                     "content": "def calculate_total(items):\n    return sum(items)\n"}
                ]},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "t2", "name": "read", "input": {"path": "b.rs"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t2",
                     "content": [
                        {"type": "text", "text": "fn shipped_order() -> u32 { 7 }\n"}
                     ]}
                ]}
            ]
        });
        accumulate_request_tool_symbols(&body, &root);
        let session = crate::scanner::project_index::get_session_symbols(&root, "");
        assert!(
            session.contains("calculate_total"),
            "string-form tool_result content must be accumulated, got: {session:?}"
        );
        assert!(
            session.contains("shipped_order"),
            "block-form tool_result content must be accumulated, got: {session:?}"
        );
    }

    #[test]
    fn accumulate_empty_root_and_no_messages_are_noops() {
        // Must not panic on empty root / missing messages.
        accumulate_request_tool_symbols(&serde_json::json!({}), "");
        accumulate_request_tool_symbols(
            &serde_json::json!({"messages": []}),
            "/test-fragvis-noop",
        );
        accumulate_request_tool_symbols(
            &serde_json::json!({"messages": [{"role": "user", "content": "hi"}]}),
            "/test-fragvis-noop",
        );
    }

    // ── json_to_text_best_effort (task-010 mega-response FP fix) ──────

    #[test]
    fn json_to_text_unescapes_newlines_so_line_anchored_regexes_fire() {
        // Mid-stream tool_call args carry code with literal \n escapes.
        // Line-anchored regexes ((?m)^... method_def_re, import/package
        // guards) see ONE line on raw JSON → false hallucinated-method.
        let raw = r#"{"filePath":"EventRepository.java","content":"package com.example;\nimport jakarta.persistence.*;\npublic interface EventRepository {\n    List<Event> findByLocation(String loc);\n}"#;
        let text = json_to_text_best_effort(raw);
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines.iter().any(|l| l.contains("findByLocation")),
            "method decl must be on its own line, got: {text:?}"
        );
        assert!(
            lines.iter().any(|l| l.trim_start().starts_with("import ")),
            "import line-shape must survive, got: {text:?}"
        );
    }

    #[test]
    fn json_to_text_handles_unicode_escapes_and_plain_text() {
        let raw = r#"{"a":"héllo","b":"plain"}"#;
        let text = json_to_text_best_effort(raw);
        assert!(text.contains("héllo"), "unicode escape: {text:?}");
        assert!(text.contains("plain"));
    }

    #[test]
    fn json_to_text_truncated_json_still_yields_strings() {
        // SSE mid-stream: unparseable JSON — walker must still emit values.
        let raw = r#"{"content":"def foo():\n    return 1\n"#;
        let text = json_to_text_best_effort(raw);
        assert!(text.contains("def foo():"));
        assert!(text.lines().count() >= 2);
    }

    // ── detect_project_root cache invalidation (Council C5) ─────────

    fn body_with_paths(paths: &[&str]) -> serde_json::Value {
        let content = paths
            .iter()
            .map(|p| format!("editing {}", p))
            .collect::<Vec<_>>()
            .join("\n");
        serde_json::json!({ "messages": [ { "role": "user", "content": content } ] })
    }

    #[test]
    fn detect_project_root_invalidates_when_paths_leave_cached_root() {
        // Reset cache to a known state.
        *DETECTED_PROJECT_ROOT.lock() = None;

        // First call: detect project A.
        let body_a = body_with_paths(&[
            "C:\\projects\\alpha\\src\\main.rs",
            "C:\\projects\\alpha\\src\\lib.rs",
        ]);
        let root_a = detect_project_root(&body_a);
        assert!(root_a.is_some(), "first call should detect a root");
        let root_a = root_a.unwrap();
        assert!(
            root_a.to_string_lossy().contains("alpha"),
            "expected alpha root, got {:?}",
            root_a
        );

        // Second call with same project: cache fast-path. Must use a
        // path that lives inside the detected root (common parent of
        // the first call's files is `...\alpha\src`).
        let body_a2 = body_with_paths(&["C:\\projects\\alpha\\src\\mod.rs"]);
        let root_a2 = detect_project_root(&body_a2);
        assert_eq!(root_a2.as_ref(), Some(&root_a), "same project should hit cache");

        // Third call with paths from a different project: cache should
        // invalidate and re-detect the new root.
        let body_b = body_with_paths(&[
            "C:\\projects\\beta\\app\\index.tsx",
            "C:\\projects\\beta\\app\\App.tsx",
        ]);
        let root_b = detect_project_root(&body_b);
        assert!(root_b.is_some(), "switched project should detect a root");
        let root_b = root_b.unwrap();
        assert!(
            root_b.to_string_lossy().contains("beta"),
            "expected beta root after switch, got {:?}",
            root_b
        );
        assert_ne!(root_a, root_b, "root should have changed");

        // Cleanup.
        *DETECTED_PROJECT_ROOT.lock() = None;
    }

    #[test]
    fn detect_project_root_returns_cached_when_no_paths_in_body() {
        *DETECTED_PROJECT_ROOT.lock() = None;

        // Seed cache by detecting from a body with paths.
        let body_with = body_with_paths(&["C:\\proj\\x\\main.rs"]);
        let _ = detect_project_root(&body_with);
        assert!(DETECTED_PROJECT_ROOT.lock().is_some(), "cache should be populated");

        // Body without paths returns cached value (not None) so callers
        // without absolute paths still see the previously detected root.
        let body_without = serde_json::json!({ "messages": [ { "role": "user", "content": "hello" } ] });
        let root = detect_project_root(&body_without);
        assert!(root.is_some(), "should fall back to cached root");

        *DETECTED_PROJECT_ROOT.lock() = None;
    }

    // ── parse_usage_from_response ────────────────────────────────────

    #[test]
    fn parse_usage_from_response_extracts_all_token_fields() {
        let body = r#"{"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":34,"reasoning_tokens":5,"total_tokens":51}}"#;
        let (p, c, r, t) = parse_usage_from_response(body);
        assert_eq!((p, c, r, t), (12, 34, 5, 51));
    }

    #[test]
    fn parse_usage_from_response_handles_missing_usage() {
        let body = r#"{"choices":[{"message":{"content":"hi"}}"#;
        let (p, c, r, t) = parse_usage_from_response(body);
        assert_eq!((p, c, r, t), (0, 0, 0, 0));
    }

    #[test]
    fn parse_usage_from_response_handles_invalid_json() {
        let (p, c, r, t) = parse_usage_from_response("not json");
        assert_eq!((p, c, r, t), (0, 0, 0, 0));
    }

    #[test]
    fn parse_usage_from_response_defaults_missing_token_fields_to_zero() {
        // OpenAI only sends prompt_tokens + completion_tokens + total_tokens;
        // reasoning_tokens may be absent (non-reasoning models).
        let body = r#"{"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#;
        let (p, c, r, t) = parse_usage_from_response(body);
        assert_eq!((p, c, r, t), (10, 20, 0, 30));
    }

    #[test]
    fn parse_usage_from_response_handles_anthropic_field_names() {
        // Bug B9 regression: Anthropic uses input_tokens / output_tokens,
        // not prompt_tokens / completion_tokens. Without normalization, every
        // Claude request through the proxy showed 0 tokens on the dashboard.
        let body = r#"{"usage":{"input_tokens":42,"output_tokens":17}}"#;
        let (p, c, r, t) = parse_usage_from_response(body);
        assert_eq!(p, 42, "input_tokens must map to prompt");
        assert_eq!(c, 17, "output_tokens must map to completion");
        assert_eq!(r, 0, "Anthropic has no reasoning field");
        assert_eq!(t, 59, "total must be prompt+completion when missing");
    }

    #[test]
    fn parse_usage_from_response_anthropic_with_explicit_total_does_not_override() {
        // If Anthropic sends total_tokens explicitly, we should NOT compute
        // it from input+output. (Anthropic doesn't actually send total, but
        // the code path should respect it if present.)
        let body = r#"{"usage":{"input_tokens":5,"output_tokens":5,"total_tokens":999}}"#;
        let (_p, _c, _r, t) = parse_usage_from_response(body);
        assert_eq!(t, 999, "explicit total_tokens must win");
    }

    #[test]
    fn process_sse_line_extracts_anthropic_text_delta() {
        // Bug B9 part 2: Anthropic content_block_delta events carry text in
        // delta.text, not choices[0].delta.content. Without this branch, Claude
        // chat responses were invisible to the scanner.
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert_eq!(content, "hello", "Anthropic delta.text must be captured");
    }

    #[test]
    fn process_sse_line_extracts_anthropic_tool_partial_json() {
        // Tool args in Anthropic stream as delta.partial_json fragments.
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\""}}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert!(content.contains("ls"), "partial_json must be captured: {}", content);
    }

    #[test]
    fn process_sse_line_extracts_anthropic_usage_from_message_delta() {
        // Anthropic emits cumulative usage in message_delta's message.usage.
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":150}}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        let u = usage.expect("Anthropic usage must be captured");
        assert_eq!(u.get("completion_tokens").and_then(|v| v.as_u64()), Some(150));
    }

    #[test]
    fn process_sse_line_extracts_anthropic_thinking_delta() {
        // Anthropic extended thinking: content_block_delta with delta.type=thinking_delta.
        // The reasoning content lives in delta.thinking — must be captured so
        // the scanner can verify API calls inside the thinking trace.
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"I should call foo.bar() to verify"}}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert!(
            content.contains("I should call foo.bar() to verify"),
            "thinking content must be captured, got: {}",
            content
        );
    }

    // ── Provider detection tests ────────────────────────────────────

    #[test]
    fn provider_detect_anthropic_by_path() {
        let body = serde_json::json!({});
        assert_eq!(Provider::detect("/v1/messages", &body), Provider::Anthropic);
    }

    #[test]
    fn provider_detect_openai_by_path() {
        let body = serde_json::json!({});
        assert_eq!(
            Provider::detect("/v1/chat/completions", &body),
            Provider::OpenAi
        );
    }

    #[test]
    fn provider_detect_anthropic_by_body_shape() {
        // Path doesn't match, but body has Anthropic-native shape:
        // top-level `system` + required `max_tokens` + `messages`.
        let body = serde_json::json!({
            "model": "claude-sonnet-4-5",
            "max_tokens": 1024,
            "system": "You are helpful",
            "messages": [{"role": "user", "content": "hi"}]
        });
        assert_eq!(Provider::detect("/proxy/llm", &body), Provider::Anthropic);
    }

    #[test]
    fn provider_detect_openai_body_without_max_tokens() {
        // OpenAI doesn't require max_tokens — body shape without it must NOT
        // match Anthropic (would cause stream_options injection bug).
        let body = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}]
        });
        assert_eq!(Provider::detect("/proxy/llm", &body), Provider::Unknown);
    }

    #[test]
    fn provider_needs_stream_options_only_for_openai() {
        assert!(Provider::OpenAi.needs_stream_options());
        assert!(Provider::Unknown.needs_stream_options());
        assert!(
            !Provider::Anthropic.needs_stream_options(),
            "Anthropic rejects stream_options — must not inject"
        );
    }

    #[test]
    fn provider_as_str_returns_lowercase_name() {
        assert_eq!(Provider::OpenAi.as_str(), "openai");
        assert_eq!(Provider::Anthropic.as_str(), "anthropic");
        assert_eq!(Provider::Unknown.as_str(), "unknown");
    }

    // ── Warning injection helpers ───────────────────────────────────

    use super::{build_warning_footer, append_openai_warning_footer, append_anthropic_warning_footer, append_warning_footer_for_provider, build_anthropic_warning_delta, build_warning_delta_chunk, build_warning_delta_for_provider, chunk_contains_done};

    #[test]
    fn footer_includes_risk_score_and_count() {
        let warnings = vec!["foo.bar() missing".to_string()];
        let footer = build_warning_footer(0.7, &warnings, &[]);
        assert!(footer.contains("risk=7/10"), "missing risk: {}", footer);
        assert!(footer.contains("1 hallucination"), "missing count: {}", footer);
        assert!(footer.contains("foo.bar()"), "missing warning text: {}", footer);
        assert!(footer.contains("Anubis"), "missing brand: {}", footer);
    }

    #[test]
    fn footer_uses_plural_correctly() {
        let warnings = vec!["a".to_string(), "b".to_string()];
        let footer = build_warning_footer(0.5, &warnings, &[]);
        assert!(footer.contains("2 hallucinations"), "plural: {}", footer);
    }

    #[test]
    fn footer_caps_at_five_warnings() {
        let warnings: Vec<String> = (0..10).map(|i| format!("warn{}", i)).collect();
        let footer = build_warning_footer(0.9, &warnings, &[]);
        assert!(footer.contains("...and 5 more"), "should cap at 5: {}", footer);
    }

    #[test]
    fn footer_does_not_include_escape_clause() {
        let footer = build_warning_footer(0.5, &["x".to_string()], &[]);
        assert!(
            !footer.contains("forward references"),
            "escape clause should be removed — it functions as dismissal license: {}",
            footer
        );
        assert!(
            !footer.contains("ignore this warning"),
            "escape clause should be removed: {}",
            footer
        );
    }

    #[test]
    fn footer_clamps_risk_above_one() {
        // Defensive — should never happen but clamp just in case.
        let footer = build_warning_footer(1.5, &["x".to_string()], &[]);
        assert!(footer.contains("risk=10/10"), "should clamp to 10: {}", footer);
    }

    #[test]
    fn append_footer_modifies_openai_content() {
        let body = r#"{"choices":[{"message":{"content":"hello"}}]}"#;
        let modified = append_openai_warning_footer(body, "\n\n[warning]");
        assert!(
            modified.contains("hello"),
            "should preserve original: {}",
            modified
        );
        assert!(
            modified.contains("[warning]"),
            "should append footer: {}",
            modified
        );
    }

    #[test]
    fn append_footer_preserves_other_fields() {
        let body = r#"{"id":"abc","choices":[{"message":{"content":"hi"}}],"usage":{"total_tokens":5}}"#;
        let modified = append_openai_warning_footer(body, "\n[foot]");
        assert!(modified.contains("\"id\":\"abc\""));
        assert!(modified.contains("\"total_tokens\":5"));
        assert!(modified.contains("[foot]"));
    }

    #[test]
    fn append_footer_returns_original_on_parse_failure() {
        let body = "not valid json {{{";
        let modified = append_openai_warning_footer(body, "[foot]");
        assert_eq!(modified, body, "parse failure should return original");
    }

    #[test]
    fn append_footer_handles_missing_choices() {
        // Body without choices array — should not panic.
        let body = r#"{"error":"oops"}"#;
        let modified = append_openai_warning_footer(body, "[foot]");
        // Either returns original (safer) or unchanged body.
        assert!(!modified.contains("[foot]") || modified == body);
    }

    #[test]
    fn delta_chunk_is_valid_sse() {
        let delta = build_warning_delta_chunk("hello world");
        assert!(
            delta.starts_with("data: "),
            "should start with data: prefix: {}",
            delta
        );
        assert!(delta.ends_with("\n\n"), "should end with \\n\\n: {}", delta);
        assert!(delta.contains("hello world"));
        assert!(delta.contains("\"choices\""));
        assert!(delta.contains("\"delta\""));
        assert!(delta.contains("\"content\""));
    }

    #[test]
    fn delta_chunk_escapes_special_chars() {
        // Quotes + newlines in footer text must be valid JSON.
        let delta = build_warning_delta_chunk("line1\nline2 \"quoted\"");
        // Should not panic; should be parseable JSON inside data: prefix.
        let json_str = delta.strip_prefix("data: ").unwrap().trim();
        let parsed: serde_json::Value = serde_json::from_str(json_str).expect("must be valid JSON");
        assert_eq!(
            parsed["choices"][0]["delta"]["content"],
            "line1\nline2 \"quoted\""
        );
    }

    #[test]
    fn anthropic_footer_appends_text_block() {
        let body = r#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi"}]}"#;
        let modified = append_anthropic_warning_footer(body, "\n\n[warning]");
        let v: serde_json::Value = serde_json::from_str(&modified).unwrap();
        let arr = v.get("content").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[1].get("type").and_then(|t| t.as_str()), Some("text"));
        assert_eq!(arr[1].get("text").and_then(|t| t.as_str()), Some("\n\n[warning]"));
    }

    #[test]
    fn anthropic_footer_returns_original_on_invalid_json() {
        let body = "not json";
        let modified = append_anthropic_warning_footer(body, "[warning]");
        assert_eq!(modified, body);
    }

    #[test]
    fn anthropic_warning_delta_has_event_and_data_lines() {
        let delta = build_anthropic_warning_delta("hello");
        assert!(delta.starts_with("event: content_block_delta\n"), "missing event line: {}", delta);
        assert!(delta.contains("data: "), "missing data line: {}", delta);
        assert!(delta.ends_with("\n\n"), "SSE events must end with blank line: {}", delta);
        let v: serde_json::Value = serde_json::from_str(delta.split("data: ").nth(1).unwrap().trim()).unwrap();
        assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("content_block_delta"));
        assert_eq!(v.get("delta").and_then(|d| d.get("type")).and_then(|t| t.as_str()), Some("text_delta"));
        assert_eq!(v.get("delta").and_then(|d| d.get("text")).and_then(|t| t.as_str()), Some("hello"));
    }

    #[test]
    fn append_warning_dispatcher_uses_anthropic_for_anthropic_provider() {
        let body = r#"{"content":[{"type":"text","text":"x"}]}"#;
        let modified = append_warning_footer_for_provider(body, "[w]", Provider::Anthropic);
        let v: serde_json::Value = serde_json::from_str(&modified).unwrap();
        assert_eq!(v.get("content").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn append_warning_dispatcher_uses_openai_for_openai_provider() {
        let body = r#"{"choices":[{"message":{"content":"x"}}]}"#;
        let modified = append_warning_footer_for_provider(body, "[w]", Provider::OpenAi);
        let v: serde_json::Value = serde_json::from_str(&modified).unwrap();
        assert!(v.get("choices").and_then(|c| c.get(0)).and_then(|c| c.get("message")).and_then(|m| m.get("content")).and_then(|c| c.as_str()).unwrap().contains("[w]"));
    }

    #[test]
    fn build_warning_delta_dispatcher_returns_anthropic_format() {
        let d = build_warning_delta_for_provider("x", Provider::Anthropic);
        assert!(d.starts_with("event:"));
    }

    #[test]
    fn build_warning_delta_dispatcher_returns_openai_format() {
        let d = build_warning_delta_for_provider("x", Provider::OpenAi);
        assert!(d.starts_with("data:"));
    }

    #[test]
    fn chunk_contains_done_detects_marker() {
        assert!(chunk_contains_done(b"data: [DONE]\n\n"));
        assert!(chunk_contains_done(b"[DONE]"));
    }

    #[test]
    fn chunk_contains_done_ignores_normal_chunks() {
        assert!(!chunk_contains_done(b"data: {\"content\":\"hi\"}\n\n"));
        assert!(!chunk_contains_done(b""));
        assert!(!chunk_contains_done(b"some other content"));
    }

    #[test]
    fn chunk_contains_done_handles_short_chunks() {
        // Short chunks can't contain the marker — must not panic.
        assert!(!chunk_contains_done(b"ab"));
        assert!(!chunk_contains_done(b"data"));
    }

    // ── process_sse_line ─────────────────────────────────────────────

    #[test]
    fn process_sse_line_extracts_chat_content_delta() {
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"choices":[{"delta":{"content":"hello"}}]}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert_eq!(content, "hello");
        assert!(usage.is_none());
    }

    #[test]
    fn process_sse_line_extracts_reasoning_content() {
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"choices":[{"delta":{"reasoning_content":"thinking..."}}]}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert_eq!(content, "thinking...");
    }

    #[test]
    fn process_sse_line_extracts_tool_call_arguments() {
        // Tool-call args stream as JSON fragments — scanner must see them
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"choices":[{"delta":{"tool_calls":[{"function":{"arguments":"{\"path\":\"foo.rs\""}}]}}]}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert!(content.contains("foo.rs"));
    }

    #[test]
    fn process_sse_line_has_text_content_stays_false_for_tool_calls_only() {
        // F1 regression: tool-call-only stream must NOT set has_text_content.
        // Without this, is_tool_call_only would be false and the proxy would
        // inject a delta.content footer into a tool-call-only response,
        // corrupting the agent's JSON parser.
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        process_sse_line(
            r#"data: {"choices":[{"delta":{"tool_calls":[{"function":{"arguments":"{\"x\":1}"}}]}}]}"#,
            &mut content,
            &mut usage,
            &mut has_text_content,
        );
        assert!(
            !has_text_content,
            "tool_calls alone must not set has_text_content"
        );
    }

    #[test]
    fn process_sse_line_has_text_content_true_when_chat_starts_with_brace() {
        // F1 regression: a chat response whose first character happens to be
        // `{` (e.g. a code block) must still set has_text_content=true. The
        // old `starts_with('{')` heuristic wrongly suppressed the footer.
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        process_sse_line(
            r#"data: {"choices":[{"delta":{"content":"{ \"key\": \"value\" }"}}]}"#,
            &mut content,
            &mut usage,
            &mut has_text_content,
        );
        assert!(
            has_text_content,
            "chat content (even if it starts with {{) must set has_text_content"
        );
        assert!(content.starts_with('{'));
    }

    #[test]
    fn process_sse_line_has_text_content_true_for_anthropic_thinking() {
        // Anthropic extended thinking counts as text content — the warning
        // footer is meaningful there (claims inside reasoning).
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        process_sse_line(
            r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"..."}}"#,
            &mut content,
            &mut usage,
            &mut has_text_content,
        );
        assert!(has_text_content, "thinking_delta must set has_text_content");
    }

    #[test]
    fn process_sse_line_extracts_usage_from_final_chunk() {
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        let line = r#"data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}"#;
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert!(content.is_empty());
        let u = usage.expect("usage captured");
        assert_eq!(u.get("prompt_tokens").and_then(|v| v.as_u64()), Some(5));
        assert_eq!(u.get("completion_tokens").and_then(|v| v.as_u64()), Some(7));
    }

    #[test]
    fn process_sse_line_ignores_done_marker() {
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        process_sse_line("data: [DONE]", &mut content, &mut usage, &mut has_text_content);
        assert!(content.is_empty());
        assert!(usage.is_none());
    }

    #[test]
    fn process_sse_line_ignores_non_data_lines() {
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        process_sse_line("event: ping", &mut content, &mut usage, &mut has_text_content);
        process_sse_line(": comment", &mut content, &mut usage, &mut has_text_content);
        process_sse_line("", &mut content, &mut usage, &mut has_text_content);
        assert!(content.is_empty());
        assert!(usage.is_none());
    }

    #[test]
    fn process_sse_line_handles_crlf_endings() {
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        // Simulate CRLF — the line passed in still has trailing \r
        let line = "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\r\n";
        process_sse_line(line, &mut content, &mut usage, &mut has_text_content);
        assert_eq!(content, "x");
    }

    #[test]
    fn process_sse_line_later_usage_overwrites_earlier() {
        // Streaming sends incremental usage in some providers; final chunk wins
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;
        process_sse_line(
            r#"data: {"choices":[],"usage":{"prompt_tokens":3,"total_tokens":3}}"#,
            &mut content,
            &mut usage,
            &mut has_text_content,
        );
        process_sse_line(
            r#"data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#,
            &mut content,
            &mut usage,
            &mut has_text_content,
        );
        let u = usage.expect("final usage captured");
        assert_eq!(u.get("prompt_tokens").and_then(|v| v.as_u64()), Some(10));
        assert_eq!(u.get("total_tokens").and_then(|v| v.as_u64()), Some(30));
    }

    // ── Chunk-split regression: line buffer must accumulate partial events ─
    //
    // Simulates the real-world bug: a single SSE event split across two TCP
    // reads. Per-chunk parsing silently lost both content AND usage. The line
    // buffer in handle_streaming_response drains complete lines only; this
    // test exercises the underlying line processor the same way.
    #[test]
    fn sse_line_buffer_survives_chunk_split() {
        let mut content = String::new();
        let mut usage = None;
        let mut has_text_content = false;

        // First chunk arrives mid-line — incomplete JSON, would fail to parse
        let partial = "data: {\"choices\":[{\"delta\":{\"content\":\"hel";
        let rest = "lo\"}}]}\n";

        // Simulate the buffer-and-drain loop in handle_streaming_response
        let mut buf = String::new();
        buf.push_str(partial);
        // No complete line yet — nothing should be processed
        while let Some(nl) = buf.find('\n') {
            let line: String = buf.drain(..=nl).collect();
            process_sse_line(&line, &mut content, &mut usage, &mut has_text_content);
        }
        assert!(content.is_empty(), "no content before newline");

        // Second chunk completes the line
        buf.push_str(rest);
        while let Some(nl) = buf.find('\n') {
            let line: String = buf.drain(..=nl).collect();
            process_sse_line(&line, &mut content, &mut usage, &mut has_text_content);
        }
        assert_eq!(content, "hello");
    }

    // ── Phase B streaming helpers ─────────────────────────────────────
    //
    // The stream transformer is hard to unit-test end-to-end (needs a live
    // upstream + downstream consumer), but the helper functions it calls
    // are pure and exercise the behavior the design cares about:
    //   - StreamingState accumulates across chunk splits
    //   - flush_partial handles trailing partial lines
    //   - apply_scan_to_state queues a warning delta only when risk crossed
    //     AND chat text was present (not tool-call-only)

    use super::{StreamingState, apply_scan_to_state};
    use crate::scanner::ScanResultData;

    fn scan_with_risk(risk: f64, warnings: Vec<String>) -> ScanResultData {
        ScanResultData {
            clean: warnings.is_empty(),
            warnings,
            blocks: vec![],
            details: vec![],
            validator_response: String::new(),
            scan_failed: false,
            docs_assisted: false,
            validator_tokens: 0,
            risk_score: risk,
            confidence: 1.0,
        }
    }

    #[test]
    fn streaming_state_push_chunk_accumulates_content() {
        // Simulate an SSE stream split across two chunks: the second half of
        // a `data:` event arrives in a separate push_chunk call. The line
        // buffer must hold the partial until newline, then process it.
        let mut s = StreamingState::default();
        s.push_chunk(b"data: {\"choices\":[{\"delta\":{\"content\":\"hel");
        assert!(s.full_content.is_empty(), "partial line must not be processed yet");
        s.push_chunk(b"lo\"}}]}\n");
        assert_eq!(s.full_content, "hello");
        assert!(s.has_text_content);
    }

    #[test]
    fn streaming_state_flush_partial_handles_trailing_line() {
        // Some servers omit the trailing newline on the final event.
        // flush_partial must still process the buffered partial.
        let mut s = StreamingState::default();
        s.push_chunk(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}");
        assert!(s.full_content.is_empty());
        s.flush_partial();
        assert_eq!(s.full_content, "hi");
    }

    #[test]
    fn streaming_state_tracks_usage_arrival() {
        let mut s = StreamingState::default();
        s.push_chunk(
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}\n",
        );
        assert!(s.last_usage.is_some());
        let u = s.last_usage.as_ref().unwrap();
        assert_eq!(u.get("prompt_tokens").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(u.get("total_tokens").and_then(|v| v.as_u64()), Some(7));
    }

    #[test]
    fn apply_scan_to_state_queues_warning_when_risk_crossed_with_text() {
        // Standard case: chat response with hallucinations → warning delta
        // must be queued so the stream transformer can emit it.
        let mut s = StreamingState::default();
        s.full_content = "some chat response mentioning foo.bar()".to_string();
        s.has_text_content = true;
        let scan = scan_with_risk(0.6, vec!["Unverified API: foo.bar()".to_string()]);
        let warning = apply_scan_to_state(&mut s, scan, 36, Provider::OpenAi, false);
        assert!(warning.is_some(), "risk + text → warning queued");
        let bytes = warning.unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("data: "), "OpenAI provider → data: format");
        assert!(s.contains("foo.bar()"));
    }

    #[test]
    fn apply_scan_to_state_skips_warning_when_no_text_content() {
        // Tool-call-only response: even with high risk, NO warning delta —
        // injecting delta.content would corrupt the agent's JSON parser.
        let mut s = StreamingState::default();
        s.full_content = "{\"args\":\"...\"}".to_string();
        s.has_text_content = false; // tool-call-only
        let scan = scan_with_risk(0.9, vec!["Unverified API: x.y()".to_string()]);
        let warning = apply_scan_to_state(&mut s, scan, 16, Provider::OpenAi, false);
        assert!(warning.is_none(), "tool-call-only → no warning injection");
    }

    #[test]
    fn apply_scan_to_state_skips_warning_when_risk_below_threshold() {
        // Clean response: risk below RISK_THRESHOLD_APPEND (0.3) → no warning.
        let mut s = StreamingState::default();
        s.full_content = "perfectly fine response".to_string();
        s.has_text_content = true;
        let scan = scan_with_risk(0.1, vec![]);
        let warning = apply_scan_to_state(&mut s, scan, 23, Provider::OpenAi, false);
        assert!(warning.is_none(), "low risk → no warning");
        assert_eq!(s.scan_result, ScanResult::Clean);
    }

    #[test]
    fn apply_scan_to_state_uses_provider_for_warning_format() {
        // Anthropic provider → event: content_block_delta format.
        let mut s = StreamingState::default();
        s.full_content = "chat with issue foo.bar()".to_string();
        s.has_text_content = true;
        let scan = scan_with_risk(0.5, vec!["Unverified API: foo.bar()".to_string()]);
        let warning = apply_scan_to_state(&mut s, scan, 24, Provider::Anthropic, false);
        let bytes = warning.unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            text.starts_with("event: content_block_delta"),
            "Anthropic provider → event: format, got: {text}"
        );
    }

    #[test]
    fn apply_scan_to_state_marks_warning_result_when_warnings_present() {
        let mut s = StreamingState::default();
        s.full_content = "chat".to_string();
        s.has_text_content = true;
        let scan = scan_with_risk(
            0.4,
            vec!["cached-hallucination: foo.bar()".to_string()],
        );
        let _ = apply_scan_to_state(&mut s, scan, 4, Provider::OpenAi, false);
        assert_eq!(s.scan_result, ScanResult::Warning);
        assert!(s.scan_details.iter().any(|d| d.contains("cached-hallucination")));
    }

    // ── Block mode helpers ───────────────────────────────────────────

    #[test]
    fn response_has_tool_calls_detects_openai_tool_calls() {
        let body = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"edit"}}]}}]}"#;
        assert!(response_has_tool_calls(body));
    }

    #[test]
    fn response_has_tool_calls_detects_anthropic_tool_use() {
        let body = r#"{"content":[{"type":"tool_use","name":"edit"}]}"#;
        assert!(response_has_tool_calls(body));
    }

    #[test]
    fn response_has_tool_calls_negative_for_plain_text() {
        let body = r#"{"choices":[{"message":{"content":"hello"}}]}"#;
        assert!(!response_has_tool_calls(body));
    }

    #[test]
    fn summarize_tool_call_extracts_openai_function_name() {
        let body = r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"edit_file"}}]}}]}"#;
        assert_eq!(summarize_tool_call(body), "edit_file");
    }

    #[test]
    fn summarize_tool_call_extracts_anthropic_tool_name() {
        let body = r#"{"content":[{"type":"tool_use","name":"str_replace"}]}"#;
        assert_eq!(summarize_tool_call(body), "str_replace");
    }

    #[test]
    fn summarize_tool_call_fallback_for_unparseable_body() {
        assert_eq!(summarize_tool_call("not json"), "tool call");
    }

    #[test]
    fn summarize_tool_call_handles_multiple_calls() {
        let body = r#"{"choices":[{"message":{"tool_calls":[
            {"function":{"name":"edit_file"}},
            {"function":{"name":"str_replace"}}
        ]}}]}"#;
        assert_eq!(summarize_tool_call(body), "edit_file, str_replace");
    }

    #[test]
    fn build_block_message_includes_risk_score_and_warnings() {
        let msg = build_block_message(
            0.8,
            &["hallucinated-method: items.add — not a member of Array".to_string()],
            "edit_file",
        );
        assert!(msg.contains("edit_file"), "missing tool name: {}", msg);
        assert!(msg.contains("risk=8/10"), "missing risk: {}", msg);
        assert!(msg.contains("1 likely hallucination"), "missing count: {}", msg);
        assert!(msg.contains("items.add"), "missing warning text: {}", msg);
        assert!(msg.contains("re-examine"), "missing next-step guidance: {}", msg);
    }

    #[test]
    fn build_block_message_uses_plural_for_multiple_warnings() {
        let msg = build_block_message(
            0.9,
            &["a".to_string(), "b".to_string()],
            "edit_file",
        );
        assert!(msg.contains("2 likely hallucinations"), "plural form: {}", msg);
    }

    #[test]
    fn build_block_message_caps_at_eight_warnings() {
        let warnings: Vec<String> = (0..15).map(|i| format!("warn{}", i)).collect();
        let msg = build_block_message(1.0, &warnings, "edit_file");
        assert!(msg.contains("...and 7 more"), "missing overflow: {}", msg);
    }

    #[test]
    fn build_block_response_openai_has_correct_shape() {
        let resp = build_block_response_openai("reasoning", "gpt-4");
        assert_eq!(resp["object"], "chat.completion");
        assert_eq!(resp["choices"][0]["message"]["content"], "reasoning");
        assert_eq!(resp["choices"][0]["finish_reason"], "stop");
        assert_eq!(resp["x_anubis_blocked"], true);
    }

    #[test]
    fn build_block_response_anthropic_has_correct_shape() {
        let resp = build_block_response_anthropic("reasoning", "claude-3");
        assert_eq!(resp["type"], "message");
        assert_eq!(resp["role"], "assistant");
        assert_eq!(resp["content"][0]["type"], "text");
        assert_eq!(resp["content"][0]["text"], "reasoning");
        assert_eq!(resp["x_anubis_blocked"], true);
    }

    #[test]
    fn build_block_stream_openai_contains_done_marker() {
        let stream = build_block_stream_openai("reasoning", "gpt-4");
        assert!(stream.contains("data: {"));
        assert!(stream.contains("chat.completion.chunk"));
        assert!(stream.contains("reasoning"));
        assert!(stream.contains("data: [DONE]"));
    }

    #[test]
    fn build_block_stream_anthropic_contains_message_stop() {
        let stream = build_block_stream_anthropic("reasoning", "claude-3");
        assert!(stream.contains("event: message_start"));
        assert!(stream.contains("event: message_stop"));
        assert!(stream.contains("reasoning"));
        assert!(stream.contains("text_delta"));
    }

    /// OpenAI spec-legal block-form tool content
    /// [{"type":"text","text": ...}] must be accumulated too (verifier
    /// finding: only the plain-string form was handled).
    #[test]
    fn accumulate_openai_block_form_tool_content() {
        let root = format!("/test-fragvis-openai-block-{}", std::process::id());
        let body = serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": null},
                {"role": "tool", "tool_call_id": "t1", "content": [
                    {"type": "text", "text": "class BlockFormWidget:\n    pass\n"},
                    {"type": "text", "text": "from zlib import compressobj as Compress"}
                ]}
            ]
        });
        accumulate_request_tool_symbols(&body, &root);
        let session = crate::scanner::project_index::get_session_symbols(&root, "");
        assert!(
            session.contains("BlockFormWidget"),
            "block-form text must be accumulated, got: {session:?}"
        );
        assert!(
            session.contains("Compress"),
            "alias from block-form text must be accumulated, got: {session:?}"
        );
    }

    /// Anthropic block+retry: buffered tool_use chunks (content_block_start +
    /// input_json_delta) must be extracted into normalized tool calls.
    #[test]
    fn extract_tool_calls_from_chunks_anthropic_input_json_delta() {
        let chunks: Vec<bytes::Bytes> = vec![
            r#"event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_01","name":"str_replace_editor","input":{}}}

"#,
            r#"event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"a.py\","}}

"#,
            r#"event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"old_str\":\"x\"}"}}

"#,
        ]
        .into_iter()
        .map(bytes::Bytes::from)
        .collect();
        let tcs = extract_tool_calls_from_chunks(&chunks);
        assert_eq!(tcs.len(), 1, "one tool call expected, got: {tcs:?}");
        assert_eq!(tcs[0]["id"].as_str(), Some("toolu_01"));
        assert_eq!(tcs[0]["function"]["name"].as_str(), Some("str_replace_editor"));
        assert_eq!(
            tcs[0]["function"]["arguments"].as_str(),
            Some(r#"{"path":"a.py","old_str":"x"}"#)
        );
    }

    /// Anthropic corrected-tool-call stream must carry native tool_use events
    /// (content_block_start tool_use + input_json_delta + stop_reason
    /// "tool_use") so the agent executes the corrected calls (debt 2ecccf6).
    #[test]
    fn build_tool_call_stream_anthropic_forwards_tool_use() {
        let tcs = vec![serde_json::json!({
            "id": "toolu_02",
            "type": "function",
            "function": {"name": "edit", "arguments": "{\"path\":\"b.py\"}"}
        })];
        let s = build_tool_call_stream_anthropic("corrected", &tcs, "claude-3");
        assert!(s.contains(r#""type":"tool_use""#), "tool_use block missing: {s}");
        assert!(s.contains("toolu_02"));
        assert!(s.contains(r#""partial_json":"{\"path\":\"b.py\"}""#));
        assert!(s.contains(r#""stop_reason":"tool_use""#));
        assert!(s.contains("corrected"), "explanation text must ride along");
        assert!(s.contains("event: message_stop"));
    }
}
