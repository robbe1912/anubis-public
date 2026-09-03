//! Per-claim falsification L3 judge (one claim per call).
//!
//! Redesign per `.omo/plans/l3-prompt-redesign.md` (2026-08-15):
//! - **One claim per call, single JSON object** — the old batched path
//!   demanded an N-element JSON array in `1200 + 200·N` tokens; 8B-class
//!   judges truncated their reasoning and the array never closed (every
//!   parse failure landed as `uncertain` = lost recall).
//! - **Falsification framing** — "is this claim INCONSISTENT with the code?"
//!   replaces "verify if TRUE" (confirmation bias: models endorsed FALSE
//!   claims they didn't know under the old framing).
//! - **Quote-verification** — the model must copy the exact substring it
//!   judged into `quote`; the scanner mechanically rejects verdicts whose
//!   quote appears nowhere in the input (claim, code, or reference).
//! - **Exact-match doc gate** — a ≤100-token reference excerpt is injected
//!   ONLY when a doc section heading exactly matches a claim token. Bulk
//!   doc injection measured −4 to −8pp recall (lost-in-the-middle) and
//!   `[DOC_N]` citations never fired on sub-7B judges.
//! - **Greedy, single sample, 512 tokens** — verdict extraction is not
//!   creativity; self-consistency at N=3 previously HURT on 8B judges.
//!
//! Verdict labels stay `verified`/`hallucinated`/`uncertain` — downstream
//! `ClaimVerdict` consumers in mod.rs are unchanged.

use std::time::Duration;

use crate::error::AnubisError;
use crate::scanner::ClaimVerdict;
use crate::scanner::ScanContext;

// ============================================================
// CLAIM CLASSIFIER (CODE vs PROSE) — strategic pivot verdict
// ============================================================
// Per anubis-pivot-debate (2026-08-11): L3 LLM judge scopes to PROSE
// claims only. CODE claims (API existence, method signatures, type names)
// are handled by cheaper deterministic layers: FORGE pipeline (L2) +
// compiler FP gate (rustc/tsc/clangd) + LSP gate. L3 sits idle for code.
//
// Prose claim taxonomy (per pivot verdict):
//   - lifecycle:      "deprecated", "removed in", "will be removed"
//   - behavioral:     "thread-safe", "atomic", "lock-free", "blocking"
//   - performance:    "O(n)", "O(1)", "constant time", "amortized"
//   - idiom:          "idiomatic", "best practice", "recommended"
//   - conceptual:     "this works because", "this ensures", "invariant"
//   - error correctness: "raises X", "throws X", "panics when"
//   - docs accuracy:  prose statements about library behavior
//   - cross-module:   "always returns", "never fails"

/// Kind of claim, deciding whether L3 LLM judge runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    /// Code-shaped claim (API call, method signature, import path).
    /// Handled by FORGE + compiler gate + LSP gate. L3 skips.
    Code,
    /// Prose claim about behavior, lifecycle, performance, or idioms.
    /// Routes to L3 — only deterministic layers cannot verify these.
    Prose,
}

/// Lowercased trigger phrases that mark a claim as PROSE.
/// Matched as substring (case-insensitive).
static PROSE_TRIGGER_WORDS: &[&str] = &[
    // lifecycle
    "deprecated", "will be removed", "removed in", "obsolete", "legacy",
    // behavioral
    "thread-safe", "thread safe", "threadsafe",
    "atomic", "lock-free", "lockfree", "non-blocking", "nonblocking",
    "race condition", "data race", "deadlock", "use-after-free",
    // performance
    "o(n)", "o(1)", "o(log", "o(n^", "o(n*", "o(k)", "o(m", "o(1)",
    "constant time", "constant-time", "linear time", "logarithmic",
    "quadratic", "amortized", "worst-case",
    "fixed rate", "at a rate", "dependent on",
    // idiom
    "idiomatic", "best practice", "recommended", "conventional",
    "preferred way", "the rust way", "pythonic", "suitable for",
    // conceptual / invariant
    "this works because", "the reason is", "this ensures",
    "this guarantees", "this prevents", "invariant", "invariants",
    "always returns", "never fails", "never returns", "guaranteed to",
    // error correctness
    "raises ", "throws ", "panics when", "panics if", "returns an error",
    "fails when", "fails if", "emits a warning",
    // behavioral assertions (general — covers Godot, game engines, niche libs)
    "is called only once", "is called once", "is called every",
    "is called at", "called per ", "called on each",
    "does not delete immediately", "does not remove immediately",
    "immediately removes", "immediately deletes", "immediately frees",
    "end of the current frame", "end of frame", "deferred",
    "by default", "shallow copy", "deep copy",
    "controls whether", "controls if",
    "must be created via", "must be created using", "cannot be created",
    "safely reused", "can be safely", "cannot be safely",
    "stops", "prevents", "propagat",
    "local space", "global space", "parent space", "object space",
    "zero-length", "zero length", "unit length", "unit vector",
    "physics frame", "physics process", "rendering framerate",
    "not assigned during", "assigned before", "assigned after",
    // API description claims (factual statements about what code does)
    "reads a", "reads the", "writes a", "writes the",
    "returns the", "returns a", "returns an", "returns new",
    "parses the", "parses a", "parses an",
    "issues an http", "issues a request",
    "sorts the", "sorts in place", "sorts in-place",
    "flattens", "maps each", "filters the",
    "constructs an", "constructs a", "creates a", "creates an",
    "inserts the", "inserts a", "removes the", "removes a",
    "acquires the", "releases the",
    "converts each", "converts the",
    "waits for", "waits until",
    "prints the", "prints a",
    "stores the", "stores a",
    "sets the", "sets a",
    "spawns the", "spawns a",
    "clones the", "clones a",
    "wraps the", "wraps a",
    "updates the", "updates in place",
    "produces a", "produces the", "produces an",
    "yields the", "yields a", "yields only",
];

/// Classify a claim as CODE (skip L3) or PROSE (route to L3).
///
/// A claim is PROSE if its lowercase form contains any trigger phrase
/// from the prose taxonomy. Otherwise CODE.
///
/// Examples:
/// ```
/// # use anubis_daemon::scanner::l3_per_claim::{classify_claim, ClaimKind};
/// assert_eq!(classify_claim("pandas.read_csv('file.csv')"), ClaimKind::Code);
/// assert_eq!(classify_claim("This API is deprecated."), ClaimKind::Prose);
/// assert_eq!(classify_claim("This function is thread-safe."), ClaimKind::Prose);
/// assert_eq!(classify_claim("Runs in O(n) time."), ClaimKind::Prose);
/// ```
/// Words too generic to anchor gap-tolerant trigger matching.
const TRIGGER_GAP_STOPWORDS: &[&str] = &[
    "the", "a", "an", "in", "on", "of", "with", "and", "or", "to", "is", "it", "for", "into",
];

/// Lowercased, punctuation-stripped word tokens of a sentence (len >= 2).
fn sentence_word_tokens(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|w| w.len() >= 2)
        .collect()
}

pub fn classify_claim(claim: &str) -> ClaimKind {
    let lower = claim.to_lowercase();
    // Lazy: only tokenize when a multi-word trigger fails the substring
    // fast path (keeps the common exact-match case allocation-free).
    let mut tokens: Option<Vec<String>> = None;
    for trigger in PROSE_TRIGGER_WORDS.iter() {
        if lower.contains(trigger) {
            return ClaimKind::Prose;
        }
        // Gap-tolerant fallback: all meaningful trigger tokens present as
        // whole words, in any arrangement. Catches interposed words like
        // "Sorts xs in place" vs trigger "sorts in place" (word `xs`
        // breaks the contiguous substring). Recall-biased (AGENTS.md #7).
        let meaningful: Vec<&str> = trigger
            .split_whitespace()
            .filter(|t| t.len() >= 2 && !TRIGGER_GAP_STOPWORDS.contains(t))
            .collect();
        if meaningful.len() < 2 {
            continue; // single meaningful token → substring path already covered
        }
        let toks = tokens.get_or_insert_with(|| sentence_word_tokens(claim));
        if meaningful.iter().all(|m| toks.iter().any(|t| t == m)) {
            return ClaimKind::Prose;
        }
    }
    ClaimKind::Code
}

/// Max number of prose claims extracted per response. Bounds L3 prompt size.
const MAX_PROSE_CLAIMS_PER_RESPONSE: usize = 8;

/// Extract prose claims from LLM response content.
///
/// Walks markdown prose (skipping fenced code blocks) and emits sentences
/// containing trigger phrases from the prose taxonomy. Bounds the result
/// at [`MAX_PROSE_CLAIMS_PER_RESPONSE`] to keep the batched L3 prompt
/// within token budget.
///
/// Sentence splitting is intentionally simple (split on `.`, `;`, newline)
/// since the L3 LLM judge re-reads the full claim. Perfect boundaries are
/// not required — just enough to isolate the claim.
pub fn extract_prose_claims(content: &str) -> Vec<String> {
    let mut claims: Vec<String> = Vec::new();
    let mut in_fence = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        // Split on sentence boundaries; keep trimmed non-empty chunks.
        for raw_sentence in trimmed.split(['.', ';', '\n']) {
            let s = raw_sentence.trim();
            // Skip very short or very long chunks (avoid noise + bound tokens).
            if s.len() < 12 || s.len() > 280 {
                continue;
            }
            // Must contain at least one space (heuristic for natural-language).
            if !s.contains(' ') {
                continue;
            }
            if classify_claim(s) == ClaimKind::Prose {
                // Preserve trailing period for prompt clarity.
                claims.push(format!("{}.", s.trim_end_matches('.')));
                if claims.len() >= MAX_PROSE_CLAIMS_PER_RESPONSE {
                    return claims;
                }
            }
        }
    }
    claims
}

/// Extract prose sentences that reference identifiers from code blocks.
///
/// This is a STRUCTURAL, language-agnostic replacement for trigger-word
/// matching. Instead of looking for specific English phrases ("thread-safe",
/// "is called"), it:
/// 1. Collects all identifiers from fenced code blocks (function names,
///    variable names, class names, method calls)
/// 2. Walks prose (non-code) sentences
/// 3. For each sentence: if it references any code identifier → verifiable claim
///
/// Catches simple API claims like "Reads a CSV file using read_csv" (matches
/// `read_csv` from code) without needing trigger words.
///
/// Identifiers shorter than 4 chars are skipped (too generic: `df`, `pd`, `x`).
/// Common English words are filtered (the, this, with, etc.).
pub fn extract_identifier_anchored_claims(content: &str) -> Vec<String> {
    use regex::Regex;
    use std::sync::OnceLock;

    // Step 1: collect identifiers from code blocks.
    static IDENT_RE: OnceLock<Regex> = OnceLock::new();
    let ident_re = IDENT_RE.get_or_init(|| {
        // Match: function_name, ClassName, method_name, variable_name
        // Min 4 chars to avoid noise (df, pd, x, y, i, j)
        Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]{3,})\b").unwrap()
    });

    const COMMON_WORDS: &[&str] = &[
        "that", "this", "with", "from", "when", "while", "does", "have", "been",
        "will", "would", "could", "should", "their", "there", "then", "than",
        "into", "only", "same", "such", "here", "code", "function", "method",
        "value", "result", "returns", "false", "true", "null", "none", "type",
        "string", "number", "array", "object", "class", "const", "async", "await",
        "return", "import", "export", "default", "static", "public", "private",
        "print", "console", "error", "warn", "info", "data", "test", "case",
        "file", "line", "name", "args", "self", "super", "base", "core", "main",
        "read", "write", "open", "close", "start", "stop", "init", "load", "save",
        "create", "build", "make", "call", "send", "recv", "find", "search",
        "check", "valid", "empty", "size", "length", "count", "index", "first",
        "last", "next", "prev", "current", "local", "global", "inner", "outer",
        "left", "right", "item", "list", "dict", "tuple", "float", "double",
        "int", "long", "short", "char", "byte", "bool", "auto", "void", "struct",
        "enum", "union", "match", "loop", "each", "some", "more", "less", "most",
        "just", "also", "only", "very", "much", "many", "such", "which", "what",
        "where", "upon", "over", "under", "after", "before", "since", "until",
        "true", "false", "none", "null", "undefined", "void", "zero", "note",
        "false", "true",
    ];

    let mut identifiers: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut in_fence = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            continue;
        }
        for cap in ident_re.captures_iter(line) {
            let ident = cap[1].to_lowercase();
            if COMMON_WORDS.contains(&ident.as_str()) {
                continue;
            }
            identifiers.insert(ident);
        }
    }

    if identifiers.is_empty() {
        return Vec::new();
    }

    // Step 2: walk prose, find sentences referencing identifiers.
    let mut claims: Vec<String> = Vec::new();
    in_fence = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        for raw_sentence in trimmed.split(['.', ';', '\n']) {
            let s = raw_sentence.trim();
            if s.len() < 12 || s.len() > 280 || !s.contains(' ') {
                continue;
            }
            let lower = s.to_lowercase();
            // Check if any identifier appears as a whole word in this sentence.
            let matches = identifiers.iter().any(|id| {
                // Word-boundary check: identifier surrounded by non-alphanumeric
                let pattern = format!(r"\b{}\b", regex::escape(id));
                Regex::new(&pattern).unwrap().is_match(&lower)
            });
            if matches {
                claims.push(format!("{}.", s.trim_end_matches('.')));
                if claims.len() >= MAX_PROSE_CLAIMS_PER_RESPONSE {
                    return claims;
                }
            }
        }
    }
    claims
}

/// Whether to enable reasoning (thinking) for L3 calls.
/// Override via DELULU_THINKING env var: "1" or "enabled" = reasoning ON.
/// Default: disabled (fast, cheap, sufficient for existence checks).
fn thinking_enabled() -> bool {
    matches!(
        std::env::var("DELULU_THINKING").unwrap_or_default().as_str(),
        "1" | "enabled" | "on" | "true"
    )
}

/// Per-HTTP-call timeout. Per-claim calls are short, so 30s is generous.
const PER_CALL_TIMEOUT_SECS: u64 = 30;

/// Max retry attempts on HTTP 429 (rate limit).
const MAX_429_RETRIES: u32 = 5;

/// Base delay between 429 retries (exponential backoff: base * 2^attempt).
/// z.ai needs generous backoff — 2s base means 2s, 4s, 8s, 16s, 32s.
const RETRY_BASE_DELAY_MS: u64 = 2000;

/// Max concurrent per-claim L3 calls (§2). Independent claims fire in
/// parallel; the cap avoids 429 storms against rate-limited endpoints.
/// Max concurrent judge calls. ollama/GPU batch: 4-way concurrency measured
/// ~same wall as 1 call, so 8 slots keeps every judged claim + the behavioral
/// judge in one batched wave on small local models.
const MAX_INFLIGHT_L3: usize = 8;

/// Max prose claims judged (LLM calls) per response. Bounds worst-case L3
/// latency directly: ≤ MAX_JUDGED_CLAIMS × 2 calls spread over
/// MAX_INFLIGHT_L3 concurrent slots. Overflow keeps its risk ordering —
/// the caller queues warning-derived claims before prose.
const MAX_JUDGED_CLAIMS: usize = 6;

/// max_tokens for a per-claim judge call (§5): 3-sentence reasoning ≈ 100
/// tokens + JSON object ≈ 60 tokens. 512 removes the truncation class.
const JUDGE_MAX_TOKENS: u64 = 512;

/// Retry budget when finish_reason == "length" (§4.4). Still truncating at
/// this budget → forced `uncertain`, never a counted `verified`.
const JUDGE_RETRY_MAX_TOKENS: u64 = 768;

/// Verify a list of claims via the L3 falsification judge.
///
/// Per the l3-prompt-redesign spec:
/// 1. Each claim is classified as CODE or PROSE via [`classify_claim`].
/// 2. CODE claims skip L3 — the FORGE pipeline + compiler FP gate + LSP gate
///    already handle them deterministically. A `verdict: "skipped"` placeholder
///    is returned so the caller's count math (one verdict per input claim) works.
/// 3. Every PROSE claim gets its OWN L3 call (one claim, one JSON object —
///    §2), fired in parallel with [`MAX_INFLIGHT_L3`] in flight.
///
/// `prose_claim_count` is the number of trailing entries in `claims` that the
/// caller has already extracted as prose (via `extract_prose_claims` /
/// `extract_identifier_anchored_claims`). These bypass [`classify_claim`]: the
/// classifier is trigger-word-based and would re-filter identifier-anchored
/// prose claims ("reads a CSV using read_csv") as CODE, dropping them before
/// they reach the LLM. The caller already proved they are prose-shaped, so
/// we trust that signal and route them straight to L3.
///
/// `code_block` is the scanned response's code-only content (§2 priority-2
/// code source); when empty the judge falls back to the claim text itself.
///
/// Returns one `ClaimVerdict` per input claim, in input order.
///
/// Skips L3 entirely (returns empty Vec) when:
/// - `claims` is empty
/// - `ctx.llm_api_key` is empty (no L3 configured)
pub async fn verify_claims_per_claim(
    claims: &[String],
    prose_claim_count: usize,
    ctx: &ScanContext,
    docs_snippet: &str,
    code_block: &str,
    project_api: &str,
    scope_summary: &str,
) -> Vec<ClaimVerdict> {
    if claims.is_empty() || ctx.llm_api_key.is_empty() {
        return Vec::new();
    }

    // ── Partition claims by kind ────────────────────────────────────────
    // CODE → skipped placeholder. PROSE → per-claim L3 verification.
    //
    // Caller-flagged prose (trailing `prose_claim_count` entries) bypass
    // classify_claim — the extractor already proved they are prose, and the
    // trigger-word classifier would reject identifier-anchored claims.
    let prose_start = claims.len().saturating_sub(prose_claim_count);
    let mut results: Vec<ClaimVerdict> = Vec::with_capacity(claims.len());
    let mut prose_indices: Vec<usize> = Vec::new();
    let mut prose_claims: Vec<String> = Vec::new();
    for (idx, claim) in claims.iter().enumerate() {
        let kind = if idx >= prose_start {
            ClaimKind::Prose
        } else {
            classify_claim(claim)
        };
        match kind {
            ClaimKind::Code => results.push(ClaimVerdict {
                claim: claim.clone(),
                verdict: "skipped".to_string(),
                confidence: 0.0,
                reason: "code claim — handled by compiler gate, L3 skipped".to_string(),
            }),
            ClaimKind::Prose => {
                prose_indices.push(idx);
                prose_claims.push(claim.clone());
                // Placeholder until the per-claim verdict lands; overwritten below.
                results.push(ClaimVerdict {
                    claim: claim.clone(),
                    verdict: "uncertain".to_string(),
                    confidence: 0.0,
                    reason: "pending prose verification".to_string(),
                });
            }
        }
    }

    if prose_claims.is_empty() {
        // All claims were CODE — no LLM call needed.
        return results;
    }

    // ── Judged-claim cap (latency bound) ────────────────────────────────
    // Binds the L3 wall-clock worst case directly:
    // ≤ MAX_JUDGED_CLAIMS × 2 calls / MAX_INFLIGHT_L3 concurrent. The
    // caller order is already risk-ordered (warning-derived API claims
    // first, prose last), so keeping the first K keeps the risky ones;
    // overflow is marked "skipped" and logged.
    if prose_claims.len() > MAX_JUDGED_CLAIMS {
        let skipped = prose_claims.len() - MAX_JUDGED_CLAIMS;
        tracing::warn!(
            target: "validator",
            total_prose = prose_claims.len(),
            judged = MAX_JUDGED_CLAIMS,
            skipped,
            "L3 claim cap — judging first {} risk-ordered claims only",
            MAX_JUDGED_CLAIMS
        );
        for &idx in prose_indices[MAX_JUDGED_CLAIMS..].iter() {
            let claim = results[idx].claim.clone();
            results[idx] = ClaimVerdict {
                claim,
                verdict: "skipped".to_string(),
                confidence: 0.0,
                reason: format!(
                    "claim cap ({MAX_JUDGED_CLAIMS}) — not judged, L3 latency bound"
                ),
            };
        }
        prose_indices.truncate(MAX_JUDGED_CLAIMS);
        prose_claims.truncate(MAX_JUDGED_CLAIMS);
    }

    // ── Per-claim L3 verification (parallel, capped) ────────────────────
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(PER_CALL_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(target: "validator", error = %e, "per-claim L3 client build failed");
            // PROSE placeholders remain as "uncertain" — CODE verdicts preserved.
            return results;
        }
    };

    // Exact-match doc gate (§3): resolve each claim's reference excerpt BEFORE
    // fanning out — pure string work, no reason to do it inside the tasks.
    let matched_docs: Vec<Option<MatchedDoc>> = prose_claims
        .iter()
        .map(|claim| match_doc_excerpt(claim, docs_snippet))
        .collect();

    let cancel = ctx.cancel.clone();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_L3));
    let client = std::sync::Arc::new(client);
    let mut futs = Vec::with_capacity(prose_claims.len());
    for ((claim, doc), _) in prose_claims.iter().zip(matched_docs.into_iter()).zip(0..) {
        let sem = sem.clone();
        let client = client.clone();
        futs.push(async move {
            let _permit = sem
                .acquire_owned()
                .await
                .expect("L3 semaphore is never closed while tasks are pending");
            verify_claim_once(claim, code_block, doc.as_ref(), ctx, &client, project_api, scope_summary)
                .await
        });
    }

    let batch_verdicts = tokio::select! {
        r = futures::future::join_all(futs) => r,
        _ = cancel.cancelled() => prose_claims.iter().map(|c| ClaimVerdict {
            claim: c.clone(),
            verdict: "uncertain".to_string(),
            confidence: 0.0,
            reason: "cancelled: deep scan timed out".to_string(),
        }).collect(),
    };

    // Splice per-claim verdicts back into result Vec at PROSE positions.
    for (i, idx) in prose_indices.iter().enumerate() {
        if let Some(v) = batch_verdicts.get(i) {
            results[*idx] = v.clone();
        }
    }
    results
}

// ============================================================
// DOCS: EXACT-MATCH GATE (§3)
// ============================================================
// Bulk doc injection measured −4 to −8pp recall (lost-in-the-middle) and
// `[DOC_N]` citations never fired on sub-7B judges. The gate: inject a
// ≤100-token excerpt ONLY when a doc section heading exactly matches a token
// in the claim (case-insensitive, exact symbol match). Near-zero match rate
// in practice is the INTENDED outcome — docs were net-harmful.

/// A doc section whose heading exactly matched a claim token.
pub struct MatchedDoc {
    /// The matched heading text (e.g. `read_csv`).
    pub symbol: String,
    /// First ≤100 tokens of that section's body.
    pub excerpt: String,
}

/// Identifier regex for claim tokens. Min 4 chars — shorter tokens
/// (`df`, `pd`, `x`) are too generic to gate on.
static CLAIM_TOKEN_RE: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\b").unwrap()
    });

/// Light inflection stems for the doc-exact-match gate: identity plus
/// suffix-stripped forms (`sorts`→`sort`, `sorted`→`sort`, `replaces`→
/// `replace`). Min stem length 4 so short words (`gets`→`get`) are NOT
/// stemmed (too generic). Whole-symbol equality only — this is morphology,
/// not fuzzy matching.
fn stem_variants(word: &str) -> Vec<String> {
    let mut out = vec![word.to_string()];
    for suffix in ["s", "es", "ed", "ing"] {
        if let Some(stem) = word.strip_suffix(suffix) {
            if stem.len() >= 4 {
                out.push(stem.to_string());
                // doubled consonant: `sorted` handled above, but `mapping`
                // → `mapp` is wrong; also try stripping the doubled tail
                // (`stopping` → `stopp` → `stop`).
                if stem.len() >= 5 {
                    let bytes = stem.as_bytes();
                    let (a, b) = (bytes[stem.len() - 2], bytes[stem.len() - 1]);
                    if a == b && a.is_ascii_lowercase() {
                        out.push(stem[..stem.len() - 1].to_string());
                    }
                }
            }
        }
    }
    out
}

/// Exact-match doc gate (§3).
///
/// Returns `Some(MatchedDoc)` iff a markdown heading in `docs` exactly equals
/// (case-insensitive) an identifier token from `claim`. The excerpt is the
/// section body up to the next heading, capped at ~100 tokens.
fn match_doc_excerpt(claim: &str, docs: &str) -> Option<MatchedDoc> {
    if docs.trim().is_empty() {
        return None;
    }

    // Lowercased claim tokens + light inflection stems. Verb-form claims
    // ("Sorts xs in place…") must meet noun/signature-form doc headings
    // (`## sorted(iterable)`). Still whole-symbol equality — no fuzzy match.
    let mut tokens: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in CLAIM_TOKEN_RE.captures_iter(claim) {
        for v in stem_variants(&c[1].to_lowercase()) {
            tokens.insert(v);
        }
    }
    if tokens.is_empty() {
        return None;
    }

    // Walk headings; match on the full heading OR its API basename:
    // `sorted(iterable)` → `sorted`; `str.replace(old, new)` → `replace`;
    // `Array.prototype.sort()` → `sort` (signature stripped, last segment).
    let mut lines = docs.lines().fuse().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            continue;
        }
        let heading = trimmed.trim_start_matches('#').trim();
        if heading.is_empty() {
            continue;
        }
        let base_raw = heading.split('(').next().unwrap_or(heading).trim();
        let base = base_raw
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(base_raw)
            .trim()
            .to_lowercase();
        let full_match = tokens.contains(&heading.to_lowercase());
        let base_match = !base.is_empty()
            && stem_variants(&base).iter().any(|v| tokens.contains(v));
        if !full_match && !base_match {
            continue;
        }
        // Section body: lines until the next heading (any level).
        let mut excerpt = String::new();
        for body_line in lines.by_ref() {
            if body_line.trim_start().starts_with('#') {
                break;
            }
            if crate::scanner::estimate_tokens(&excerpt)
                + crate::scanner::estimate_tokens(body_line)
                > 100
            {
                if excerpt.trim().is_empty() {
                    // One monolithic line (minified/joined docs): slice a
                    // ~100-token prefix instead of dropping the section.
                    // ~400 ASCII chars ≈ 100 tokens at 0.25 tok/char.
                    excerpt.push_str(&crate::scanner::safe_slice_to(body_line.trim(), 400));
                    excerpt.push('\n');
                }
                break;
            }
            excerpt.push_str(body_line);
            excerpt.push('\n');
        }
        let excerpt = excerpt.trim().to_string();
        if excerpt.is_empty() {
            continue;
        }
        return Some(MatchedDoc {
            symbol: heading.to_string(),
            excerpt,
        });
    }
    None
}

/// Verify ONE claim with ONE L3 call (§2 of the l3-prompt-redesign spec).
///
/// Prompt: falsification system prompt (§1) + code-first / claim-last user
/// prompt. Parse (§4): `strip_code_fence` → split at `</reasoning>` → tail
/// through `extract_json_object` → mechanical [`quote_found`] check.
///
/// Retry policy:
/// - `finish_reason == "length"` → one retry at 768 tokens → still length →
///   forced `uncertain` with reason `[truncated]` (§4.4). A truncated
///   response is never counted as `verified`.
/// - quote not found verbatim → one retry with the correction appended →
///   still failing → forced `uncertain`, confidence 0.0, reason
///   `[quote-mismatch] {original}` (§4.3).
async fn verify_claim_once(
    claim: &str,
    code_block: &str,
    matched_doc: Option<&MatchedDoc>,
    ctx: &ScanContext,
    client: &reqwest::Client,
    project_api: &str,
    scope_summary: &str,
) -> ClaimVerdict {
    let uncertain = |reason: String| ClaimVerdict {
        claim: claim.to_string(),
        verdict: "uncertain".to_string(),
        confidence: 0.0,
        reason,
    };

    let system = build_judge_system_prompt(matched_doc, project_api, scope_summary);
    let user = build_judge_user_prompt(claim, code_block, &ctx.language);
    let doc_excerpt = matched_doc
        .map(|d| d.excerpt.as_str())
        .unwrap_or("");

    // Extract (message content, finish_reason) from an OpenAI-shaped body.
    let extract = |v: &serde_json::Value| -> (String, Option<String>) {
        let choice = v.get("choices").and_then(|c| c.get(0));
        let content = choice
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        let finish = choice
            .and_then(|c| c.get("finish_reason"))
            .and_then(|f| f.as_str())
            .map(|s| s.to_string());
        (content, finish)
    };

    let first = match send_judge_chat(ctx, client, &system, &user, judge_max_tokens()).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "validator",
                claim = %claim.chars().take(80).collect::<String>(),
                error = %e,
                "per-claim L3 call failed"
            );
            return uncertain(format!("L3 call failed: {e}"));
        }
    };
    let (content, finish_reason) = extract(&first);
    if content.is_empty() {
        tracing::warn!(
            target: "validator",
            claim = %claim.chars().take(80).collect::<String>(),
            raw_keys = ?first.as_object().map(|o| o.keys().collect::<Vec<_>>()),
            "per-claim L3 response missing choices[0].message.content"
        );
    }

    // ── Attempt budget: at most 2 HTTP calls per claim (latency bound) ─
    // The truncation retry consumes the budget; if that response then
    // fails the mechanical quote check, force uncertain without a third
    // call. Caps the worst case at 2 × judge latency per claim.
    let mut retries_left: u32 = 1;

    // ── Truncation guard (§4.4) ─────────────────────────────────────────
    let content = if finish_reason.as_deref() == Some("length") {
        tracing::warn!(
            target: "validator",
            claim = %claim.chars().take(80).collect::<String>(),
            "per-claim L3 truncated — retrying with larger token budget"
        );
        let retry_budget = if thinking_enabled() { 4096 } else { JUDGE_RETRY_MAX_TOKENS };
        retries_left = 0;
        match send_judge_chat(ctx, client, &system, &user, retry_budget).await {
            Ok(v) => {
                let (retry_content, retry_finish) = extract(&v);
                if retry_finish.as_deref() == Some("length") {
                    tracing::warn!(
                        target: "validator",
                        claim = %claim.chars().take(80).collect::<String>(),
                        "per-claim L3 truncated twice — forcing uncertain"
                    );
                    return uncertain(
                        "[truncated] response hit the token limit twice".to_string(),
                    );
                }
                retry_content
            }
            Err(e) => return uncertain(format!("L3 truncation retry failed: {e}")),
        }
    } else {
        content
    };

    // ── Parse (§4.1) ────────────────────────────────────────────────────
    let (reasoning, judge) = match parse_judge_response(&content) {
        Ok(parsed) => parsed,
        Err(reason) => return uncertain(reason),
    };

    // ── Mechanical quote check (§4.2/§4.3) ──────────────────────────────
    if quote_found(&judge.quote, claim, code_block, doc_excerpt) {
        return finalize_judgement(claim, &reasoning, judge);
    }
    if retries_left == 0 {
        // Attempt budget exhausted by the truncation retry (§ latency
        // bound: ≤2 calls per claim). Never spend a third call here.
        tracing::warn!(
            target: "validator",
            quote = %judge.quote,
            "per-claim L3 quote mismatch after truncation retry — budget exhausted, forcing uncertain"
        );
        return forced_uncertain(claim, &judge.reason);
    }
    tracing::warn!(
        target: "validator",
        quote = %judge.quote,
        "per-claim L3 quote not found verbatim — one retry with correction"
    );
    let corrected_user = format!(
        "{user}\n\nYour quote was not found verbatim in the input. Copy the exact substring, or return \"uncertain\"."
    );
    match send_judge_chat(ctx, client, &system, &corrected_user, judge_max_tokens()).await {
        Ok(v) => {
            let (retry_content, _) = extract(&v);
            match parse_judge_response(&retry_content) {
                Ok((retry_reasoning, retry_judge))
                    if quote_found(&retry_judge.quote, claim, code_block, doc_excerpt) =>
                {
                    finalize_judgement(claim, &retry_reasoning, retry_judge)
                }
                Ok((_, retry_judge)) => forced_uncertain(claim, &retry_judge.reason),
                Err(_) => forced_uncertain(claim, &judge.reason),
            }
        }
        Err(_) => forced_uncertain(claim, &judge.reason),
    }
}

/// max_tokens for a judge call (§5): 512 default; the opt-in thinking path
/// needs headroom for the reasoning tokens before the visible content.
fn judge_max_tokens() -> u64 {
    if thinking_enabled() { 4096 } else { JUDGE_MAX_TOKENS }
}

/// Send one judge chat-completion and return the parsed response body.
///
/// Handles 429 backoff (exponential, [`MAX_429_RETRIES`] attempts) and
/// non-2xx statuses. A 200 body that is not valid JSON yields `Value::Null`
/// — the caller's content extraction sees empty content and falls back to
/// `uncertain` (§4.5: missing/malformed → current fallback behavior).
async fn send_judge_chat(
    ctx: &ScanContext,
    client: &reqwest::Client,
    system: &str,
    user: &str,
    max_tokens: u64,
) -> Result<serde_json::Value, AnubisError> {
    let url = format!(
        "{}/chat/completions",
        ctx.llm_base_url.trim_end_matches('/')
    );
    let mut body = serde_json::json!({
        "model": ctx.logic_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        // §5: greedy. The verdict pass is extraction, not creativity.
        "temperature": 0.0,
        "max_tokens": max_tokens,
        // Two vendor shapes for the same intent; each endpoint honors its
        // own and ignores the other:
        //   `thinking` — z.ai/GLM shape (production judge).
        //   `think`    — ollama shape. CRITICAL for thinking models served
        //                by ollama (gemma4, qwen3, ...): without it the
        //                model spends the entire max_tokens budget on hidden
        //                reasoning and returns finish_reason=length with an
        //                EMPTY message.content — the claim then eats a
        //                pointless 768-token truncation retry and lands as
        //                uncertain (measured: 8s call, 512/512 tokens
        //                burned, zero visible output; with think:false the
        //                same call is ~4-6s and returns a real verdict).
        "think": false,
        "thinking": if thinking_enabled() {
            serde_json::json!({"type": "enabled"})
        } else {
            serde_json::json!({"type": "disabled"})
        },
    });
    // ollama ≥0.10 honors `reasoning_effort` on /v1 and it is the ONLY knob
    // that fully suppresses hidden reasoning there: `think:false` alone still
    // burns ~350 hidden tokens before visible output (measured 415 tok for a
    // 60-token answer, ~13s). With reasoning_effort:"none" the same judge
    // call emits 87 tokens in ~3.6s. Only sent when thinking is disabled so
    // it never contradicts the z.ai `thinking:{enabled}` mode.
    if !thinking_enabled() {
        body["reasoning_effort"] = serde_json::json!("none");
    }

    let build_req = || {
        let mut req = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", ctx.llm_api_key))
            .header("x-anubis-internal", "scanner-per-claim-judge")
            .header("Content-Type", "application/json")
            .json(&body);
        for (key, val) in &ctx.llm_extra_headers {
            req = req.header(key, val);
        }
        req
    };

    let mut res = build_req().send().await?;

    // 429 backoff (same retry semantics as the legacy per-claim path).
    let mut attempt = 0;
    while res.status().as_u16() == 429 && attempt < MAX_429_RETRIES {
        let delay = RETRY_BASE_DELAY_MS * (1 << attempt);
        tracing::warn!(
            target: "validator",
            attempt,
            delay_ms = delay,
            "per-claim L3 429, retrying"
        );
        tokio::time::sleep(Duration::from_millis(delay)).await;
        res = build_req().send().await?;
        attempt += 1;
    }

    if !res.status().is_success() {
        let status = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        return Err(AnubisError::ValidatorHttp { status, body });
    }

    let raw = res.text().await?;
    match serde_json::from_str(&raw) {
        Ok(v) => Ok(v),
        Err(e) => {
            tracing::warn!(
                target: "validator",
                error = %e,
                raw_len = raw.len(),
                raw_head = %raw.chars().take(200).collect::<String>(),
                "per-claim L3 response body is not valid JSON"
            );
            Ok(serde_json::Value::Null)
        }
    }
}

// ============================================================
// JUDGE RESPONSE PARSING + MECHANICAL QUOTE CHECK (§4)
// ============================================================

/// Parsed judge payload (§1 output contract: `<reasoning>` then ONE JSON
/// object). The `quote` field is mechanically verified against the input by
/// [`quote_found`] before the verdict is accepted.
#[derive(Debug, serde::Deserialize)]
struct JudgeVerdict {
    #[serde(default)]
    quote: String,
    verdict: String,
    #[serde(default)]
    confidence: f64,
    #[serde(default)]
    reason: String,
}

/// Parse a judge response (§4.1): `strip_code_fence` → split at
/// `</reasoning>` → extract the single JSON object after it.
///
/// Returns `(reasoning_body, verdict)`. On missing/malformed JSON the error
/// string becomes the `uncertain` fallback reason (§4.5 — no change from the
/// previous fallback behavior).
fn parse_judge_response(content: &str) -> Result<(String, JudgeVerdict), String> {
    let cleaned = strip_code_fence(content);
    let (reasoning, tail) = match cleaned.split_once("</reasoning>") {
        Some((before, after)) => (before.to_string(), after),
        None => (String::new(), cleaned.as_str()),
    };
    let extracted = extract_json_object(tail);
    let judge: JudgeVerdict = serde_json::from_str(&extracted).map_err(|e| {
        tracing::warn!(
            target: "validator",
            error = %e,
            extracted_len = extracted.len(),
            extracted_head = %extracted.chars().take(200).collect::<String>(),
            "per-claim L3 verdict JSON parse failed — falling back to uncertain"
        );
        format!(
            "parse failed: {} (raw: {})",
            e,
            cleaned.chars().take(120).collect::<String>()
        )
    })?;
    Ok((reasoning, judge))
}

/// Mechanical quote check (§4.2, exact spec): the judge's `quote` must
/// appear verbatim in the claim, the code block, or the doc excerpt.
/// Quotes shorter than 4 chars are rejected (no evidence).
fn quote_found(quote: &str, claim: &str, code_block: &str, doc_excerpt: &str) -> bool {
    let q = quote.trim().trim_matches('"').trim();
    if q.len() < 4 {
        return false;
    }
    claim.contains(q) || code_block.contains(q) || doc_excerpt.contains(q)
}

/// Forced `uncertain` for quote-mismatch (§4.3): confidence 0.0, original
/// reason kept under the `[quote-mismatch]` audit prefix.
fn forced_uncertain(claim: &str, original_reason: &str) -> ClaimVerdict {
    ClaimVerdict {
        claim: claim.to_string(),
        verdict: "uncertain".to_string(),
        confidence: 0.0,
        reason: format!("[quote-mismatch] {original_reason}"),
    }
}

/// Finalize an accepted judge verdict: force the claim field, sanitize the
/// verdict label, apply VERDI calibration over the reasoning trace (§4.1).
fn finalize_judgement(claim: &str, reasoning: &str, judge: JudgeVerdict) -> ClaimVerdict {
    let verdict = judge.verdict;
    match verdict.as_str() {
        "verified" | "hallucinated" | "uncertain" => {}
        other => {
            tracing::warn!(
                target: "validator",
                raw_verdict = %other,
                "per-claim L3 returned unknown verdict string — coercing to uncertain"
            );
            // Malformed label: the judge output is untrustworthy, so VERDI
            // calibration on it would be noise. Hard uncertain at 0.0.
            return ClaimVerdict {
                claim: claim.to_string(),
                verdict: "uncertain".to_string(),
                confidence: 0.0,
                reason: judge.reason,
            };
        }
    }
    // VERDI calibration (arXiv:2605.11334): structural signals from the
    // reasoning trace adjust confidence. Zero additional API calls.
    let trace = format!("{reasoning}\n{}", judge.reason);
    let confidence =
        crate::scanner::l3_verdi::calibrate_confidence(&verdict, &trace, judge.confidence);
    ClaimVerdict {
        claim: claim.to_string(),
        verdict,
        confidence,
        reason: judge.reason,
    }
}

// ============================================================
// JUDGE PROMPTS (§1/§2 — falsification framing, one claim per call)
// ============================================================

/// Build the falsification-judge system prompt (§1 exact text).
///
/// Replaces BOTH the old prose-batch prompt and the existence-check prompt
/// for the L3 path. One prompt, one claim per call: falsification framing,
/// 2 few-shots (1 true / 1 false), quote-verification, `<reasoning>`-then-
/// single-JSON-object, one-sentence reasoning cap (completion tokens
/// dominate judge latency on small local models).
///
/// The confidence-anchor ladder and SV-CoT block from the old prompts are
/// intentionally DROPPED — definition/taxonomy bloat measurably hurts small
/// judges, and the anchors taught confidence saturation. Verdict label
/// strings stay `verified`/`hallucinated`/`uncertain` (downstream consumers
/// unchanged). `scope_summary` / `project_api` blocks stay APPENDED at the
/// end of the system prompt as today (short, AST-derived, high-confidence).
fn build_judge_system_prompt(
    matched_doc: Option<&MatchedDoc>,
    project_api: &str,
    scope_summary: &str,
) -> String {
    let mut s = String::with_capacity(3072);

    // §3 placement: reference excerpt at the TOP of the system prompt, only
    // when the exact-match gate fired (default is NO docs block at all).
    if let Some(doc) = matched_doc {
        s.push_str(&format!(
            "REFERENCE excerpt for \"{}\" (may be incomplete):\n{}\n",
            doc.symbol, doc.excerpt
        ));
        s.push_str(
            "If this excerpt addresses the claim, quote from it; otherwise judge from code and training knowledge.\n\n",
        );
    }

    s.push_str(
        r#"You are a code-claim auditor. You get ONE code context and ONE claim about it.
Your job: try to prove the claim WRONG. Assume it may be fabricated.

QUESTION: is this claim INCONSISTENT with the code, the reference excerpt, or your training knowledge?

QUOTE RULE (mechanically checked — the scanner rejects verdicts it cannot verify):
- Before judging, copy the exact line or symbol you are judging into the "quote" field, character-for-character from the CODE, the CLAIM, or the REFERENCE excerpt.
- No paraphrase. If you cannot copy an exact substring, you have no evidence: return "uncertain".

OUTPUT FORMAT (mandatory):
1. <reasoning> ... </reasoning>  — ONE short sentence (max 20 words).
2. Then exactly ONE JSON object and nothing after it:
{"quote": "<exact copied substring>", "verdict": "verified" | "hallucinated" | "uncertain", "confidence": <0.0-1.0>, "reason": "<max 8 words>"}

VERDICT RULES:
- "hallucinated" = you found a concrete inconsistency: wrong name, wrong argument, wrong return type, wrong behavioral direction.
- "verified"    = you tried to break the claim and failed; the code and evidence affirmatively support it.
- "uncertain"   = no evidence either way. Use this freely — it is never a failure.

CRITICAL:
- Judge the claim only, never style, naming taste, or code quality.
- Absence from the REFERENCE excerpt is NOT evidence of hallucination.
- Standard-library and widely known APIs are verified.

EXAMPLE 1 — claim is TRUE:
CODE:
import pandas as pd
df = pd.read_csv('data.csv')
CLAIM: pd.read_csv('data.csv') loads a CSV file into a DataFrame.
<reasoning>
The claim matches the code line and read_csv is pandas' canonical CSV loader.
</reasoning>
{"quote": "df = pd.read_csv('data.csv')", "verdict": "verified", "confidence": 0.95, "reason": "read_csv is the standard pandas CSV loader."}

EXAMPLE 2 — claim is FALSE:
CODE:
cfg = parse_config('app.ini')
CLAIM: parse_config is a function in Python's standard library.
<reasoning>
No Python stdlib module exports parse_config; it is a project-local call.
</reasoning>
{"quote": "cfg = parse_config('app.ini')", "verdict": "hallucinated", "confidence": 0.85, "reason": "parse_config is not in the Python stdlib."}

"#,
    );

    if !scope_summary.is_empty() {
        s.push_str("## Variable types from scope analysis (confidence: HIGH — inferred from AST)\n\n");
        s.push_str(scope_summary);
        s.push_str("\n\n");
    }
    if !project_api.is_empty() {
        s.push_str("## PROJECT API (defined locally — VERIFIED)\n\n");
        let project_capped = if project_api.len() > 1500 {
            format!(
                "{}...(truncated)",
                crate::scanner::safe_slice_to(project_api, 1500)
            )
        } else {
            project_api.to_string()
        };
        s.push_str(&project_capped);
        s.push_str("\n\n");
    }
    s
}

/// Cap on the code block sent per judge call. The same block goes out with
/// every claim of a response (§2 priority-2 source), so the cap bounds the
/// N× fan-out cost without trimming DELULU-sized snippets.
const JUDGE_CODE_BLOCK_CAP: usize = 6000;

/// Build the falsification-judge user prompt (§2 exact text).
///
/// Position engineering: code first, claim LAST (recency + query-aware
/// contextualization), instruction after the claim.
///
/// `{code_block}` source, in priority order (§2):
/// 1. The snippet the claim was extracted from — not yet wired through
///    `ScanContext` (see spec Risks/open items).
/// 2. Else the scanned response's code block (caller-supplied).
/// 3. Else the claim text itself (behavioral claims like "Go map is safe
///    for concurrent reads" — the quote rule still applies: the model
///    copies the API symbol from the claim).
fn build_judge_user_prompt(claim: &str, code_block: &str, language: &str) -> String {
    let lang_label = if language.is_empty() { "code" } else { language };
    let code_source = if code_block.trim().is_empty() {
        claim.to_string()
    } else if code_block.len() > JUDGE_CODE_BLOCK_CAP {
        format!(
            "{}\n...(truncated)",
            crate::scanner::safe_slice_to(code_block, JUDGE_CODE_BLOCK_CAP)
        )
    } else {
        code_block.to_string()
    };
    format!(
        "CODE ({lang_label}):\n```\n{code_source}\n```\n\nCLAIM: {claim}\n\nFind evidence that this claim is wrong. Copy the exact line you judged into \"quote\", then answer. End with ONE JSON object."
    )
}
// ─── Small helpers (duplicated from mod.rs to keep module self-contained) ───

/// Strip ```...``` code fences from LLM output.
fn strip_code_fence(s: &str) -> String {
    let trimmed = s.trim();
    if !trimmed.starts_with("```") {
        return trimmed.to_string();
    }
    // Drop opening fence (with optional language tag like ```json).
    let after_open = trimmed.trim_start_matches("```");
    // Skip optional language tag on same line + the newline.
    let after_open = if let Some(nl_pos) = after_open.find('\n') {
        // Only treat as language tag if everything before newline is whitespace/alphanumeric.
        let tag = &after_open[..nl_pos];
        if tag.chars().all(|c| c.is_alphanumeric() || c.is_whitespace()) {
            &after_open[nl_pos + 1..]
        } else {
            after_open
        }
    } else {
        after_open
    };
    // Drop closing fence.
    let after_close = after_open.trim_end_matches("```");
    after_close.trim().to_string()
}

/// Extract the first `{...}` JSON object from a string. Useful when LLM
/// wraps JSON in prose.
fn extract_json_object(s: &str) -> String {
    let start = match s.find('{') {
        Some(i) => i,
        None => return s.to_string(),
    };
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    let bytes = s.as_bytes();
    let mut end = start;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        let c = b as char;
        if escape {
            escape = false;
            end = i;
            continue;
        }
        if c == '\\' && in_string {
            escape = true;
            continue;
        }
        if c == '"' {
            in_string = !in_string;
            end = i;
            continue;
        }
        if in_string {
            end = i;
            continue;
        }
        match c {
            '{' => {
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
        end = i;
    }
    let end_byte = end + 1;
    if end_byte > s.len() {
        s.to_string()
    } else {
        s[start..end_byte].to_string()
    }
}

// ============================================================
// BEHAVIORAL CORRECTNESS VERIFICATION (L3 extension)
// ============================================================
// Per-claim L3 checks API existence. This extension catches semantic bugs
// that don't manifest as API hallucinations: async scope errors, missing
// base cases, lifetime panics, race conditions, off-by-one errors.
//
// Triggered ONLY when detect_behavioral_signals() returns non-empty —
// gates the cost and FP risk. Bias toward UNCERTAIN over HALLUCINATED.

#[derive(Debug, Clone)]
pub struct BehavioralSignal {
    pub kind: String,      // "async-scope", "recursion", etc.
    pub evidence: String,  // snippet showing the pattern
    pub concern: String,   // what could go wrong
}

/// Detect code patterns warranting behavioral review.
/// Pure heuristic — no LLM call, no AST. Fast.
/// Returns empty Vec for trivial code (no async/loops/recursion/concurrency).
pub fn detect_behavioral_signals(content: &str, language: &str) -> Vec<BehavioralSignal> {
    let mut signals = Vec::new();
    let lang = language.to_lowercase();

    // ---- Async / await scope -----------------------------------------------
    let has_async = match lang.as_str() {
        "rust" => content.contains("async fn") || content.contains(".await"),
        "python" => content.contains("async def") || content.contains("await ")
            || content.contains("asyncio"),
        "typescript" | "javascript" | "tsx" => content.contains("async ")
            || content.contains("await "),
        "go" => content.contains("go func"),
        _ => false,
    };
    if has_async {
        signals.push(BehavioralSignal {
            kind: "async-scope".into(),
            evidence: "async/await pattern".into(),
            concern: "Async code may have scope/event-loop issues (blocking call in async, missing await).".into(),
        });
    }

    // ---- Recursion (heuristic) ---------------------------------------------
    // Find `fn name(` definitions and check if name appears again in body.
    if let Some(name) = detect_self_recursion(content, &lang) {
        signals.push(BehavioralSignal {
            kind: "recursion".into(),
            evidence: name.clone(),
            concern: format!("Function `{name}` calls itself — verify base case exists."),
        });
    }

    // ---- Off-by-one suspicious ranges --------------------------------------
    if content.contains("..=")
        || content.contains("..n-1")
        || content.contains("range(0, ")
        || content.contains("for i in 0..")
    {
        signals.push(BehavioralSignal {
            kind: "off-by-one".into(),
            evidence: "range bound".into(),
            concern: "Range bounds may be off by one (inclusive vs exclusive).".into(),
        });
    }

    // ---- Rust lifetime / ownership / drop order ---------------------------
    if lang == "rust" {
        if content.contains("'static") || content.contains("&'a")
            || content.contains("Rc::new") || content.contains("Arc::new")
        {
            signals.push(BehavioralSignal {
                kind: "lifetime".into(),
                evidence: "lifetime/ownership".into(),
                concern: "Lifetime/ownership patterns may cause use-after-free or panic.".into(),
            });
        }
        // Interior mutability types — borrow rules are subtle.
        // RefCell panics at runtime on double-borrow; Cell restricts to Copy types;
        // Mutex/RwLock can deadlock. LLMs frequently hallucinate borrow patterns.
        if content.contains("RefCell") || content.contains("RefMut")
            || content.contains("Ref<") || content.contains(".borrow()")
            || content.contains(".borrow_mut()")
        {
            signals.push(BehavioralSignal {
                kind: "borrow-check".into(),
                evidence: "RefCell/borrow pattern".into(),
                concern: "RefCell borrow may panic at runtime (double borrow, borrow-then-modify).".into(),
            });
        }
        if content.contains("impl Drop") || content.contains("impl drop for") {
            signals.push(BehavioralSignal {
                kind: "drop-order".into(),
                evidence: "impl Drop".into(),
                concern: "Drop implementation may have field-order or use-after-free issues.".into(),
            });
        }
        if content.contains("unsafe ") || content.contains("unsafe{") {
            signals.push(BehavioralSignal {
                kind: "unsafe".into(),
                evidence: "unsafe block".into(),
                concern: "Unsafe block may have memory unsafety.".into(),
            });
        }
    }

    // ---- TypeScript/JavaScript Promise / event-loop -----------------------
    if matches!(lang.as_str(), "typescript" | "javascript" | "tsx") {
        if content.contains("Promise") && !content.contains("await") {
            signals.push(BehavioralSignal {
                kind: "unhandled-promise".into(),
                evidence: "Promise without await".into(),
                concern: "Promise may be unhandled (missing await/catch).".into(),
            });
        }
        if (content.contains("async ") || content.contains("await "))
            && (content.contains("fs.read") || content.contains("readFileSync")
                || content.contains("writeFileSync") || content.contains("execSync")
                || content.contains(".read(") || content.contains("time.Sleep")
                || content.contains("requests.get") || content.contains("requests.post"))
        {
            signals.push(BehavioralSignal {
                kind: "event-loop-blocking".into(),
                evidence: "sync I/O in async context".into(),
                concern: "Blocking call inside async function may stall event loop.".into(),
            });
        }
    }

    // ---- Python event-loop blocking ---------------------------------------
    if lang == "python" && (content.contains("async def") || content.contains("await ")) {
        if content.contains("requests.get") || content.contains("requests.post")
            || content.contains("time.sleep") || content.contains("open(")
            || content.contains("urllib.request")
        {
            signals.push(BehavioralSignal {
                kind: "event-loop-blocking".into(),
                evidence: "sync I/O in async function".into(),
                concern: "Blocking call inside async function may stall event loop.".into(),
            });
        }
    }

    // ---- Concurrency primitives --------------------------------------------
    if content.contains("tokio::spawn") || content.contains("thread::spawn")
        || content.contains("go func") || content.contains("asyncio.gather")
        || content.contains("Promise.all") || content.contains("sync.WaitGroup")
        || content.contains("sync.Mutex")
    {
        signals.push(BehavioralSignal {
            kind: "concurrency".into(),
            evidence: "spawn/concurrent".into(),
            concern: "Spawned task may have race/deadlock issues.".into(),
        });
    }

    // ---- C# / TS: async-sync mismatch --------------------------------------
    // `await obj.Method()` where Method lacks `Async` suffix — likely a
    // blocking sync call in an async context (e.g. SaveChanges vs SaveChangesAsync).
    if matches!(lang.as_str(), "csharp" | "typescript" | "javascript" | "tsx") {
        let await_re = regex::Regex::new(
            r"(?m)await\s+[\w.]+\.(\w+)\s*\("
        ).unwrap();
        let mismatches: Vec<&str> = await_re
            .captures_iter(content)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .filter(|name| name.len() >= 3 && !name.ends_with("Async"))
            .collect();
        if !mismatches.is_empty() {
            signals.push(BehavioralSignal {
                kind: "async-sync-mismatch".into(),
                evidence: format!("{:?}", mismatches.iter().take(5).collect::<Vec<_>>()),
                concern: "await on method without Async suffix — may be blocking sync call (SaveChanges vs SaveChangesAsync).".into(),
            });
        }
    }

    // ---- C / C++: memory leak (malloc without free) -------------------------
    if matches!(lang.as_str(), "c" | "cpp" | "c++") {
        let alloc_count = content.matches("malloc(").count()
            + content.matches("calloc(").count()
            + content.matches("realloc(").count();
        let free_count = content.matches("free(").count();
        if alloc_count > free_count {
            signals.push(BehavioralSignal {
                kind: "memory-leak".into(),
                evidence: format!("{} alloc(s) vs {} free(s)", alloc_count, free_count),
                concern: "More allocations than frees — possible memory leak.".into(),
            });
        }
    }

    // ---- C++: double-lock deadlock -----------------------------------------
    // `mtx.lock()` after `unique_lock`/`lock_guard` on the same mutex.
    if lang == "cpp" || lang == "c++" {
        let lock_guard_re = regex::Regex::new(
            r"(?:std::)?(?:unique_lock|lock_guard)\s*<[\w:]+>\s+(\w+)\s*\((\w+)\)"
        ).unwrap();
        for caps in lock_guard_re.captures_iter(content) {
            let mutex_name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if !mutex_name.is_empty()
                && content.contains(&format!("{}.lock()", mutex_name))
            {
                signals.push(BehavioralSignal {
                    kind: "double-lock".into(),
                    evidence: format!("{} already locked via RAII, explicit .lock() follows", mutex_name),
                    concern: "Mutex locked twice — RAII guard + explicit lock() causes deadlock.".into(),
                });
            }
        }
    }

    // ---- C++ only: C-style cast (in C, casts are the only option) ----------
    if matches!(lang.as_str(), "cpp" | "c++") {
        let cast_re = regex::Regex::new(
            r"\(\s*(?:int|float|double|char|long|short|void)\s*\*?\s*\)\s*\w"
        ).unwrap();
        if cast_re.is_match(content) {
            signals.push(BehavioralSignal {
                kind: "c-style-cast".into(),
                evidence: "C-style cast (int)expr".into(),
                concern: "C-style cast bypasses type safety — prefer static_cast/reinterpret_cast in C++.".into(),
            });
        }
    }

    signals
}

/// Heuristic: detect if a function definition calls itself.
/// Returns function name if found, None otherwise.
fn detect_self_recursion(content: &str, lang: &str) -> Option<String> {
    let fn_prefix = match lang {
        "rust" => "fn ",
        "python" => "def ",
        "typescript" | "javascript" | "tsx" => "function ",
        "go" => "func ",
        _ => return None,
    };
    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(fn_prefix) {
            // Skip generic params (Rust): fn foo<T>(...) → take foo
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.len() < 2 {
                continue;
            }
            // Look for `name(` later in code (not the def line).
            let needle = format!("{}(", name);
            let mut hits = 0;
            for probe in content.lines() {
                if probe.contains(&needle) {
                    hits += 1;
                    if hits >= 2 {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

/// Single LLM call asking: "given these signals, is the code behaviorally correct?"
/// Returns warnings (empty if no issues found).
/// Bias toward UNCERTAIN — only emit warnings when model is confident bug exists.
/// Creates its own HTTP client (matches verify_claims_per_claim pattern).
pub async fn verify_behavioral_correctness(
    code: &str,
    signals: &[BehavioralSignal],
    ctx: &ScanContext,
) -> Vec<String> {
    if ctx.llm_api_key.is_empty() || code.is_empty() || signals.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(PER_CALL_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(target: "validator", error = %e, "behavioral client build failed");
            return Vec::new();
        }
    };

    let system = build_behavioral_system_prompt(signals);
    let user = build_behavioral_user_prompt(code, &ctx.language);

    let url = format!(
        "{}/chat/completions",
        ctx.llm_base_url.trim_end_matches('/')
    );
    let mut body = serde_json::json!({
        "model": ctx.logic_model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.0, // deterministic — judgment, not creativity
        // Reasoning-first format requires headroom for the <reasoning> block.
        "max_tokens": if thinking_enabled() { 4096 } else { 800 },
        // ollama thinking models: see send_judge_chat — without this the
        // entire budget burns on hidden reasoning and content comes back
        // empty (silent total loss of the behavioral pass on ollama).
        "think": false,
        "thinking": if thinking_enabled() {
            serde_json::json!({"type": "enabled"})
        } else {
            serde_json::json!({"type": "disabled"})
        },
    });
    // ollama ≥0.10 /v1: fully suppresses hidden reasoning (see
    // send_judge_chat for measurements). Only when thinking is disabled.
    if !thinking_enabled() {
        body["reasoning_effort"] = serde_json::json!("none");
    }

    let mut req = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", ctx.llm_api_key))
        .header("x-anubis-internal", "scanner-behavioral")
        .header("Content-Type", "application/json")
        .json(&body);
    for (key, val) in &ctx.llm_extra_headers {
        req = req.header(key, val);
    }

    let res = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "validator", error = %e, "behavioral verify network error");
            return Vec::new();
        }
    };

    // 429 retry (single attempt — behavioral is best-effort)
    let mut res = res;
    if res.status().as_u16() == 429 {
        tokio::time::sleep(Duration::from_millis(RETRY_BASE_DELAY_MS)).await;
        let mut retry_req = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", ctx.llm_api_key))
            .header("x-anubis-internal", "scanner-behavioral")
            .header("Content-Type", "application/json")
            .json(&body);
        for (key, val) in &ctx.llm_extra_headers {
            retry_req = retry_req.header(key, val);
        }
        res = match retry_req.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(target: "validator", error = %e, "behavioral retry failed");
                return Vec::new();
            }
        };
    }

    if !res.status().is_success() {
        let status = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        tracing::warn!(target: "validator", status, body = %body.chars().take(200).collect::<String>(), "behavioral verify HTTP error");
        return Vec::new();
    }

    let raw = res.text().await.unwrap_or_default();
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target: "validator", error = %e, raw_head = %raw.chars().take(200).collect::<String>(), "behavioral response not JSON");
            return Vec::new();
        }
    };
    let content_str = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    let cleaned = strip_code_fence(content_str);
    let extracted = extract_json_object(&cleaned);
    parse_behavioral_response(&extracted)
}

fn build_behavioral_system_prompt(signals: &[BehavioralSignal]) -> String {
    let mut s = String::with_capacity(1500);
    s.push_str("You are a code reviewer focused on BEHAVIORAL bugs (not API existence).\n\n");
    s.push_str("Active concerns detected in this code:\n");
    for sig in signals {
        s.push_str(&format!("- [{}] {}\n", sig.kind, sig.concern));
    }
    // Saturation fix: reasoning-first format. GLM-4.7-Flash JSON-mode
    // saturates bug severity when forced into pure-JSON output. Reasoning
    // first debias.
    s.push_str("\nOUTPUT FORMAT (mandatory):\n");
    s.push_str("1. Start with <reasoning> ... </reasoning> — brief analysis of each concern.\n");
    s.push_str("2. End with JSON: {\"bugs\": [{\"severity\": \"high\"|\"medium\"|\"low\", \"description\": \"...\", \"line_hint\": \"...\"}]}\n");
    s.push_str("3. NEVER output JSON only. Reasoning first, JSON last.\n\n");
    s.push_str("RULES (FP-avoidance first):\n");
    s.push_str("- Only flag OBVIOUS bugs you are confident about.\n");
    s.push_str("- If unsure → don't include in bugs array.\n");
    s.push_str("- Don't flag style, naming, or API existence (other layers handle those).\n");
    s.push_str("- Don't flag valid patterns — async/await alone is NOT a bug.\n");
    s.push_str("- BUT: `await` outside an `async` function IS a bug (Python SyntaxError, Rust compile error). Flag as high severity.\n");
    s.push_str("- BUT: recursion without a base case IS a bug (infinite loop / stack overflow). Flag as high severity.\n");
    s.push_str("- Don't flag missing error handling unless obviously wrong.\n");
    s.push_str("- Empty bugs array if code looks correct.\n");
    s.push_str("- Severity guide: high = runtime crash/data corruption/wrong result; medium = likely bug with workaround; low = don't include.\n");
    s
}

fn build_behavioral_user_prompt(code: &str, language: &str) -> String {
    let label = if language.is_empty() { "code" } else { language };
    // Note: <reasoning> block goes first, JSON verdict last (saturation fix).
    format!("Review this {label} code for behavioral bugs:\n\n```\n{code}\n```\n\nStart with <reasoning>, then JSON.")
}

fn parse_behavioral_response(extracted: &str) -> Vec<String> {
    let v: serde_json::Value = match serde_json::from_str(extracted) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let bugs = v.get("bugs").and_then(|b| b.as_array());
    let mut warnings = Vec::new();
    if let Some(arr) = bugs {
        for bug in arr {
            let severity = bug.get("severity").and_then(|s| s.as_str()).unwrap_or("low");
            // Only emit warnings for high+medium severity. Low suppressed (FP guard).
            if severity != "high" && severity != "medium" {
                continue;
            }
            let desc = bug.get("description").and_then(|d| d.as_str()).unwrap_or("unknown issue");
            let line = bug.get("line_hint").and_then(|l| l.as_str()).unwrap_or("");
            let prefix = if severity == "high" { "behavioral-concern" } else { "behavioral-warning" };
            if line.is_empty() {
                warnings.push(format!("{prefix}: {desc}"));
            } else {
                warnings.push(format!("{prefix} ({line}): {desc}"));
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Claim extraction / classification (unchanged behavior) ──

    #[test]
    fn diag_identifier_anchored_claims_works() {
        let content = "```python\nimport pandas as pd\ndf = pd.read_csv(\"file.csv\", sep=\",\")\nprint(df.shape)\n```\n\nReads a CSV file using pandas read_csv function with the comma character as the column separator.";
        let claims = extract_identifier_anchored_claims(content);
        eprintln!("DIAG: {} identifier-anchored claims", claims.len());
        for c in &claims { eprintln!("  {}", c); }
        assert!(!claims.is_empty(), "must find prose referencing code identifiers");
    }

    #[test]
    fn classify_api_call_as_code() {
        assert_eq!(classify_claim("pandas.read_csv('file.csv')"), ClaimKind::Code);
        assert_eq!(classify_claim("MyClass.foo()"), ClaimKind::Code);
        assert_eq!(classify_claim("from 'pkg'"), ClaimKind::Code);
        assert_eq!(classify_claim("std::vector<int>::push_back"), ClaimKind::Code);
    }

    #[test]
    fn classify_lifecycle_claim_as_prose() {
        assert_eq!(classify_claim("This API is deprecated."), ClaimKind::Prose);
        assert_eq!(classify_claim("Will be removed in v2.0."), ClaimKind::Prose);
        assert_eq!(classify_claim("Use of this function is obsolete."), ClaimKind::Prose);
    }

    #[test]
    fn classify_behavioral_claim_as_prose() {
        assert_eq!(classify_claim("This function is thread-safe."), ClaimKind::Prose);
        assert_eq!(classify_claim("The operation is atomic."), ClaimKind::Prose);
        assert_eq!(classify_claim("Lock-free queue."), ClaimKind::Prose);
        assert_eq!(classify_claim("Avoids race conditions."), ClaimKind::Prose);
    }

    #[test]
    fn classify_performance_claim_as_prose() {
        assert_eq!(classify_claim("Runs in O(n) time."), ClaimKind::Prose);
        assert_eq!(classify_claim("O(1) lookup."), ClaimKind::Prose);
        assert_eq!(classify_claim("Constant time operation."), ClaimKind::Prose);
        assert_eq!(classify_claim("Amortized cost."), ClaimKind::Prose);
    }

    #[test]
    fn classify_idiom_claim_as_prose() {
        assert_eq!(classify_claim("This is the idiomatic way."), ClaimKind::Prose);
        assert_eq!(classify_claim("Recommended best practice."), ClaimKind::Prose);
    }

    #[test]
    fn classify_error_correctness_claim_as_prose() {
        assert_eq!(classify_claim("Raises ValueError on bad input."), ClaimKind::Prose);
        assert_eq!(classify_claim("Panics when the argument is None."), ClaimKind::Prose);
        assert_eq!(classify_claim("Throws IOException on failure."), ClaimKind::Prose);
    }

    #[test]
    fn extract_prose_claims_skips_code_fences() {
        let content = "\
This function is thread-safe.

```rust
fn foo() {
    println!(\"not a claim\");
}
```

The API is deprecated; use `new_func` instead.
";
        let claims = extract_prose_claims(content);
        assert_eq!(claims.len(), 2, "should extract 2 prose claims, got: {:?}", claims);
        assert!(claims.iter().any(|c| c.contains("thread-safe")));
        assert!(claims.iter().any(|c| c.contains("deprecated")));
        assert!(!claims.iter().any(|c| c.contains("not a claim")));
    }

    #[test]
    fn extract_prose_claims_caps_at_max() {
        let mut lines: Vec<String> = Vec::new();
        for i in 0..50 {
            lines.push(format!("Function {} is thread-safe.", i));
        }
        let content = lines.join("\n");
        let claims = extract_prose_claims(&content);
        assert!(claims.len() <= MAX_PROSE_CLAIMS_PER_RESPONSE,
            "expected cap at {}, got {}", MAX_PROSE_CLAIMS_PER_RESPONSE, claims.len());
    }

    #[test]
    fn extract_prose_claims_empty_for_pure_code() {
        let content = "```\npandas.read_csv('f.csv')\n```";
        let claims = extract_prose_claims(content);
        assert!(claims.is_empty(), "pure code should yield no prose claims, got {:?}", claims);
    }

    #[test]
    fn extract_prose_claims_skips_single_word_lines() {
        let content = "deprecated\nthreadsafe";
        let claims = extract_prose_claims(content);
        assert!(claims.is_empty(), "single-word lines should be skipped");
    }

    // ── Shared response-parsing helpers (unchanged behavior) ──

    #[test]
    fn strip_code_fence_handles_plain_json() {
        assert_eq!(strip_code_fence(r#"{"a":1}"#), r#"{"a":1}"#);
    }

    #[test]
    fn strip_code_fence_handles_fenced_json() {
        let input = "```json\n{\"a\":1}\n```";
        assert_eq!(strip_code_fence(input), r#"{"a":1}"#);
    }

    #[test]
    fn extract_json_object_finds_balanced_braces() {
        let input = "Prose text {\"a\":{\"b\":2}} more prose";
        assert_eq!(extract_json_object(input), r#"{"a":{"b":2}}"#);
    }

    #[test]
    fn extract_json_object_handles_strings_with_braces() {
        let input = r#"{"reason": "has } char"}"#;
        assert_eq!(extract_json_object(input), r#"{"reason": "has } char"}"#);
    }

    #[test]
    fn extract_json_object_returns_input_when_no_brace() {
        assert_eq!(extract_json_object("plain text"), "plain text");
    }

    // ── §7: falsification system prompt (§1) ──

    #[test]
    fn judge_system_prompt_carries_falsification_contract() {
        let prompt = build_judge_system_prompt(None, "", "");
        // Falsification framing.
        assert!(prompt.contains("prove the claim WRONG"),
            "falsification framing missing");
        assert!(prompt.contains("INCONSISTENT with the code"),
            "inconsistency question missing");
        // Quote rule (mechanically checked).
        assert!(prompt.contains("QUOTE RULE"),
            "quote rule missing");
        assert!(prompt.contains("character-for-character"),
            "exact-copy requirement missing");
        // Single-JSON-object output contract (both system and user side).
        assert!(prompt.contains("exactly ONE JSON object"),
            "single-JSON contract missing");
        assert!(!prompt.contains("JSON array"),
            "array contract from the old batch prompt must be gone");
        // Reasoning-first, ONE-sentence cap (latency: completion tokens
        // dominate judge wall time on small local models).
        assert!(prompt.contains("<reasoning>"));
        assert!(prompt.contains("</reasoning>"));
        assert!(prompt.contains("ONE short sentence (max 20 words)"));
        // Exactly 2 examples with OPPOSITE verdicts.
        assert_eq!(prompt.matches("EXAMPLE ").count(), 2,
            "must carry exactly 2 few-shots, got {}", prompt.matches("EXAMPLE ").count());
        assert!(prompt.contains(r#""verdict": "verified""#), "need one verified few-shot");
        assert!(prompt.contains(r#""verdict": "hallucinated""#), "need one hallucinated few-shot");
        // Dropped machinery from the old prompts.
        assert!(!prompt.contains("[DOC_"), "citation tagging is dead code on this path");
        assert!(!prompt.contains("CITATION"), "citation rules are dead code on this path");
        assert!(!prompt.contains("CONFIDENCE CALIBRATION"),
            "confidence-anchor ladder is intentionally dropped (saturation)");
        assert!(!prompt.contains("SELF-VERIFICATION"),
            "SV-CoT block is intentionally dropped (bloat hurts small judges)");
        // Default: NO docs block. The base prompt does mention "the
        // REFERENCE excerpt" generically in the quote rule — what must NOT
        // appear without a gate match is the labeled excerpt header (§3).
        assert!(!prompt.contains("REFERENCE excerpt for \""),
            "no-docs default must not emit a labeled reference block");
    }

    #[test]
    fn judge_system_prompt_reference_excerpt_gates_and_leads() {
        let doc = MatchedDoc {
            symbol: "read_csv".to_string(),
            excerpt: "pandas.read_csv(filepath_or_buffer, sep=',') -> DataFrame".to_string(),
        };
        let prompt = build_judge_system_prompt(Some(&doc), "", "");
        let ref_pos = prompt.find("REFERENCE excerpt for \"read_csv\"")
            .expect("matched doc must emit the labeled reference block");
        let base_pos = prompt.find("You are a code-claim auditor")
            .expect("base prompt must be present");
        assert!(ref_pos < base_pos,
            "reference excerpt must sit at the TOP of the system prompt (§3)");
        assert!(prompt.contains(doc.excerpt.as_str()));
        assert!(prompt.contains("If this excerpt addresses the claim"),
            "excerpt must carry the judge-from-elsewhere directive");
    }

    #[test]
    fn judge_system_prompt_appends_scope_and_project_api() {
        let prompt = build_judge_system_prompt(None, "MyApi::thing()", "x: DataFrame");
        assert!(prompt.contains("## Variable types"));
        assert!(prompt.contains("x: DataFrame"));
        assert!(prompt.contains("## PROJECT API"));
        assert!(prompt.contains("MyApi::thing()"));
    }

    // ── §7: judge user prompt (§2) ──

    #[test]
    fn judge_user_prompt_positions_code_first_claim_last() {
        let prompt = build_judge_user_prompt(
            "The flatten method returns a copy.",
            "flat = nested.flatten()",
            "python",
        );
        let code_pos = prompt.find("flat = nested.flatten()").expect("code must be present");
        let lang_pos = prompt.find("CODE (python):").expect("language label must be present");
        let claim_pos = prompt.find("CLAIM: The flatten method returns a copy.")
            .expect("claim must be present");
        let instr_pos = prompt.find("Find evidence that this claim is wrong")
            .expect("falsification instruction must be present");
        assert!(lang_pos < code_pos, "code block comes first");
        assert!(code_pos < claim_pos, "claim comes after code (recency positioning)");
        assert!(claim_pos < instr_pos, "instruction comes after the claim");
    }

    #[test]
    fn judge_user_prompt_falls_back_to_claim_text_as_code() {
        // Behavioral claims with no code context: the claim itself is the
        // code source (§2 priority 3) — the quote rule still applies.
        let prompt = build_judge_user_prompt("Go map is safe for concurrent reads", "", "go");
        assert!(prompt.contains("```\nGo map is safe for concurrent reads\n```"),
            "empty code block must fall back to the claim text");
    }

    #[test]
    fn judge_user_prompt_caps_oversized_code_block() {
        let huge = "x".repeat(JUDGE_CODE_BLOCK_CAP + 500);
        let prompt = build_judge_user_prompt("claim about code", &huge, "rust");
        assert!(prompt.contains("...(truncated)"), "oversized code block must be capped");
        assert!(prompt.len() < JUDGE_CODE_BLOCK_CAP + 1000,
            "prompt must stay near the cap, got {}", prompt.len());
    }

    // ── §7: quote_found positive/negative/short-quote ──

    #[test]
    fn quote_found_positive_in_all_three_sources() {
        let claim = "The flatten method returns a copy.";
        let code = "flat = nested.flatten()";
        let doc = "list.flatten is not a real method";
        assert!(quote_found("flatten method", claim, code, doc), "quote in claim");
        assert!(quote_found("nested.flatten()", claim, code, doc), "quote in code");
        assert!(quote_found("not a real method", claim, code, doc), "quote in doc excerpt");
        // Surrounding double-quotes are stripped before matching.
        assert!(quote_found("\"nested.flatten()\"", claim, code, doc),
            "quoted strings must be trimmed then matched");
    }

    #[test]
    fn quote_found_negative_on_paraphrase() {
        assert!(!quote_found(
            "the method which flattens lists",
            "The flatten method returns a copy.",
            "flat = nested.flatten()",
            "",
        ), "paraphrase must fail the mechanical check");
    }

    #[test]
    fn quote_found_rejects_short_quotes() {
        assert!(!quote_found("ab", "ab cd", "ab cd", ""), "sub-4-char quotes carry no evidence");
        assert!(!quote_found("   ", "anything", "anything", ""), "whitespace quotes fail");
        assert!(!quote_found("", "anything", "anything", ""), "empty quote fails");
    }

    // ── §7: judge response parsing (§4.1) ──

    #[test]
    fn parse_judge_response_reasoning_then_single_object() {
        let content = "<reasoning>One. Two. Three.</reasoning>\n\
            {\"quote\": \"nested.flatten()\", \"verdict\": \"hallucinated\", \
             \"confidence\": 0.85, \"reason\": \"no such method\"}";
        let (reasoning, judge) = parse_judge_response(content).expect("must parse");
        assert!(reasoning.contains("One. Two. Three."));
        assert_eq!(judge.verdict, "hallucinated");
        assert_eq!(judge.quote, "nested.flatten()");
        assert!((judge.confidence - 0.85).abs() < 1e-9);
    }

    #[test]
    fn parse_judge_response_tolerates_fence_and_missing_reasoning() {
        let content = "```json\n{\"quote\": \"flatten\", \"verdict\": \"uncertain\", \
             \"confidence\": 0.3, \"reason\": \"no docs\"}\n```";
        let (reasoning, judge) = parse_judge_response(content).expect("must parse fenced JSON");
        assert!(reasoning.is_empty(), "no reasoning tag → empty reasoning body");
        assert_eq!(judge.verdict, "uncertain");
    }

    #[test]
    fn parse_judge_response_garbage_is_error() {
        let err = parse_judge_response("no json here at all").expect_err("must fail");
        assert!(err.contains("parse failed"), "error string becomes the uncertain reason");
    }

    // ── §7: forced_uncertain + finalize_judgement ──

    #[test]
    fn forced_uncertain_carries_audit_prefix() {
        let v = forced_uncertain("some claim", "original reasoning");
        assert_eq!(v.verdict, "uncertain");
        assert_eq!(v.confidence, 0.0);
        assert_eq!(v.reason, "[quote-mismatch] original reasoning");
        assert_eq!(v.claim, "some claim");
    }

    #[test]
    fn finalize_judgement_coerces_unknown_verdict() {
        let judge = JudgeVerdict {
            quote: "flatten".into(),
            verdict: "definitely-wrong".into(),
            confidence: 0.99,
            reason: "bogus label".into(),
        };
        let v = finalize_judgement("claim", "", judge);
        assert_eq!(v.verdict, "uncertain");
        assert_eq!(v.confidence, 0.0);
        assert_eq!(v.claim, "claim", "claim field is forced, never trusted from the LLM");
    }

    #[test]
    fn finalize_judgement_accepts_known_labels_and_forces_claim() {
        for label in ["verified", "hallucinated", "uncertain"] {
            let judge = JudgeVerdict {
                quote: "flatten".into(),
                verdict: label.into(),
                confidence: 0.7,
                reason: "ok".into(),
            };
            let v = finalize_judgement("the claim", "reasoning body", judge);
            assert_eq!(v.verdict, label);
            assert_eq!(v.claim, "the claim");
        }
    }

    // ── §7: exact-match doc gate (§3) ──

    #[test]
    fn match_doc_excerpt_exact_heading_match() {
        let docs = "# pandas\n\npandas is a data library.\n\n## read_csv\n\n\
                    Signature: read_csv(filepath, sep)\nReturns a DataFrame.\n\n\
                    ## to_csv\n\nWrites a CSV.";
        let claim = "pd.read_csv('f.csv') parses the file";
        let matched = match_doc_excerpt(claim, docs).expect("read_csv heading must match");
        assert_eq!(matched.symbol, "read_csv");
        assert!(matched.excerpt.contains("Signature: read_csv"));
        assert!(!matched.excerpt.contains("Writes a CSV"),
            "excerpt must stop at the next heading — wrong section leaked in");
    }

    #[test]
    fn match_doc_excerpt_is_case_insensitive() {
        let docs = "## Read_Csv\n\nloads csv files";
        let claim = "uses read_csv here";
        let matched = match_doc_excerpt(claim, docs).expect("case-insensitive exact match");
        assert_eq!(matched.symbol, "Read_Csv");
    }

    #[test]
    fn match_doc_excerpt_rejects_partial_and_absent_symbols() {
        // Heading is a PREFIX of the claim token, not an exact match → no gate.
        let docs = "## read_cs\n\npartial heading";
        assert!(match_doc_excerpt("pd.read_csv('f')", docs).is_none(),
            "prefix similarity must NOT open the gate (exact symbol match only)");
        // No matching heading at all.
        let docs2 = "## merge\n\njoins frames";
        assert!(match_doc_excerpt("pd.read_csv('f')", docs2).is_none());
        // Empty docs.
        assert!(match_doc_excerpt("pd.read_csv('f')", "").is_none());
        assert!(match_doc_excerpt("pd.read_csv('f')", "   ").is_none());
    }

    #[test]
    fn match_doc_excerpt_caps_excerpt_near_100_tokens() {
        let long_body = "word ".repeat(400);
        let docs = format!("## read_csv\n\n{long_body}");
        let matched = match_doc_excerpt("uses read_csv", &docs).expect("must match");
        assert!(crate::scanner::estimate_tokens(&matched.excerpt) <= 100,
            "excerpt must stay within the ~100-token cap, got {}",
            crate::scanner::estimate_tokens(&matched.excerpt));
    }

    // ── §7: judge HTTP path (wiremock) ──

    mod judge_http {
        use super::super::*;
        use crate::scanner::ScanContext;
        use tokio_util::sync::CancellationToken;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn make_ctx(base_url: String) -> ScanContext {
            ScanContext {
                project_root: std::env::temp_dir().to_string_lossy().to_string(),
                logic_model: "test-mock-model".to_string(),
                llm_base_url: base_url,
                llm_api_key: "test-key".to_string(),
                llm_extra_headers: vec![],
                request_class: "agent".to_string(),
                language: "python".to_string(),
                cancel: CancellationToken::new(),
            }
        }

        fn completion_body(content: &str, finish_reason: Option<&str>) -> serde_json::Value {
            let mut choice = serde_json::json!({ "message": { "content": content } });
            if let Some(fr) = finish_reason {
                choice["finish_reason"] = serde_json::json!(fr);
            }
            serde_json::json!({ "choices": [choice] })
        }

        const CLAIM: &str = "The flatten method returns a copy of the nested elements.";
        const CODE: &str = "nested = [[1, 2], [3, 4]]\nflat = nested.flatten()";

        #[tokio::test]
        async fn happy_path_hallucinated_with_verbatim_quote() {
            std::env::remove_var("DELULU_THINKING");
            let content = "<reasoning>Lists have no flatten method.</reasoning>\n\
                {\"quote\": \"nested.flatten()\", \"verdict\": \"hallucinated\", \
                 \"confidence\": 0.9, \"reason\": \"Python list has no flatten\"}";
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .respond_with(ResponseTemplate::new(200)
                    .set_body_json(completion_body(content, Some("stop"))))
                .mount(&server)
                .await;

            let ctx = make_ctx(server.uri());
            let client = reqwest::Client::new();
            let v = verify_claim_once(CLAIM, CODE, None, &ctx, &client, "", "").await;
            assert_eq!(v.verdict, "hallucinated");
            assert_eq!(v.claim, CLAIM);
            assert!(v.confidence > 0.5, "high-conf hallucination must survive VERDI blend");

            // §5 sampling contract on the wire: greedy, 512 tokens.
            let received = server.received_requests().await.expect("recording enabled");
            assert_eq!(received.len(), 1, "happy path is exactly ONE call");
            let body: serde_json::Value = serde_json::from_slice(&received[0].body)
                .expect("request body is JSON");
            assert_eq!(body["temperature"].as_f64(), Some(0.0), "greedy decoding (§5)");
            assert_eq!(body["max_tokens"].as_u64(), Some(JUDGE_MAX_TOKENS), "512-token budget (§5)");
            assert_eq!(body["think"].as_bool(), Some(false),
                "ollama thinking models must be told not to think, else max_tokens burns on hidden reasoning");
        }

        #[tokio::test]
        async fn quote_mismatch_retries_once_then_accepts_corrected_quote() {
            std::env::remove_var("DELULU_THINKING");
            let bad = "<reasoning>guess</reasoning>\n\
                {\"quote\": \"the flattening operation\", \"verdict\": \"hallucinated\", \
                 \"confidence\": 0.9, \"reason\": \"made up\"}";
            let good = "<reasoning>Corrected.</reasoning>\n\
                {\"quote\": \"nested.flatten()\", \"verdict\": \"hallucinated\", \
                 \"confidence\": 0.88, \"reason\": \"no such method\"}";
            let server = MockServer::start().await;
            // Bad (exhausts after 1 hit) mounted FIRST — wiremock matches
            // the earliest-mounted mock, so call 1 gets the paraphrased
            // quote; calls 2+ fall through to the good fallback.
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .respond_with(ResponseTemplate::new(200)
                    .set_body_json(completion_body(bad, Some("stop"))))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .respond_with(ResponseTemplate::new(200)
                    .set_body_json(completion_body(good, Some("stop"))))
                .mount(&server)
                .await;

            let ctx = make_ctx(server.uri());
            let client = reqwest::Client::new();
            let v = verify_claim_once(CLAIM, CODE, None, &ctx, &client, "", "").await;
            assert_eq!(v.verdict, "hallucinated",
                "corrected quote on retry must be accepted; got {:?} ({})",
                v.verdict, v.reason);

            let received = server.received_requests().await.expect("recording enabled");
            assert_eq!(received.len(), 2, "exactly one retry");
            let retry_body: serde_json::Value = serde_json::from_slice(&received[1].body)
                .expect("retry body is JSON");
            let user = retry_body["messages"][1]["content"].as_str().unwrap_or("");
            assert!(user.contains("Your quote was not found verbatim"),
                "retry must append the correction instruction");
        }

        #[tokio::test]
        async fn quote_mismatch_twice_forces_uncertain() {
            std::env::remove_var("DELULU_THINKING");
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(completion_body(
                    "<reasoning>guess</reasoning>\n\
                     {\"quote\": \"paraphrased words\", \"verdict\": \"hallucinated\", \
                      \"confidence\": 0.95, \"reason\": \"original reason\"}",
                    Some("stop"),
                )))
                .mount(&server)
                .await;

            let ctx = make_ctx(server.uri());
            let client = reqwest::Client::new();
            let v = verify_claim_once(CLAIM, CODE, None, &ctx, &client, "", "").await;
            assert_eq!(v.verdict, "uncertain",
                "unverifiable quote after retry must force uncertain");
            assert_eq!(v.confidence, 0.0);
            assert!(v.reason.starts_with("[quote-mismatch]"),
                "audit prefix required; got: {}", v.reason);
            assert!(v.reason.contains("original reason"),
                "original reason preserved under the prefix");

            let received = server.received_requests().await.expect("recording enabled");
            assert_eq!(received.len(), 2, "exactly one quote retry, then forced uncertain");
        }

        #[tokio::test]
        async fn truncation_twice_forces_uncertain_with_reason() {
            std::env::remove_var("DELULU_THINKING");
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/chat/completions"))
                .respond_with(ResponseTemplate::new(200)
                    .set_body_json(completion_body(
                        "<reasoning>trunc mid-sent",
                        Some("length"),
                    )))
                .mount(&server)
                .await;

            let ctx = make_ctx(server.uri());
            let client = reqwest::Client::new();
            let v = verify_claim_once(CLAIM, CODE, None, &ctx, &client, "", "").await;
            assert_eq!(v.verdict, "uncertain",
                "double-truncated response must never count as verified");
            assert!(v.reason.contains("[truncated]"), "reason: {}", v.reason);
            assert_eq!(v.confidence, 0.0);

            let received = server.received_requests().await.expect("recording enabled");
            assert_eq!(received.len(), 2, "one truncation retry");
            let retry_body: serde_json::Value = serde_json::from_slice(&received[1].body)
                .expect("retry body is JSON");
            assert_eq!(retry_body["max_tokens"].as_u64(), Some(JUDGE_RETRY_MAX_TOKENS),
                "retry must use the 768-token budget");
        }
    }

    // ── Behavioral signal detection (unchanged behavior) ──

    #[test]
    fn test_async_sync_mismatch_csharp() {
        let code = "await _context.SaveChangesAsync();\nawait _context.SaveChanges();\n";
        let signals = detect_behavioral_signals(code, "csharp");
        assert!(signals.iter().any(|s| s.kind == "async-sync-mismatch"),
            "should detect await on non-Async method");
    }

    #[test]
    fn test_async_sync_mismatch_not_flagged_when_all_async() {
        let code = "await _context.SaveChangesAsync();\nawait _context.FindAsync(id);\n";
        let signals = detect_behavioral_signals(code, "csharp");
        assert!(!signals.iter().any(|s| s.kind == "async-sync-mismatch"),
            "should NOT flag when all methods end in Async");
    }

    #[test]
    fn test_memory_leak_c() {
        let code = "char *buf = malloc(100);\nstrcpy(buf, \"hello\");\n";
        let signals = detect_behavioral_signals(code, "c");
        assert!(signals.iter().any(|s| s.kind == "memory-leak"),
            "should detect malloc without free");
    }

    #[test]
    fn test_memory_leak_not_flagged_when_balanced() {
        let code = "char *buf = malloc(100);\nfree(buf);\n";
        let signals = detect_behavioral_signals(code, "c");
        assert!(!signals.iter().any(|s| s.kind == "memory-leak"),
            "should NOT flag when alloc == free");
    }

    #[test]
    fn test_double_lock_cpp() {
        let code = "std::unique_lock<std::mutex> lock(mtx);\nmtx.lock();\nmtx.unlock();\n";
        let signals = detect_behavioral_signals(code, "cpp");
        assert!(signals.iter().any(|s| s.kind == "double-lock"),
            "should detect explicit .lock() after unique_lock");
    }

    #[test]
    fn test_c_style_cast_cpp() {
        let code = "double d = 3.14;\nint i = (int)d;\n";
        let signals = detect_behavioral_signals(code, "cpp");
        assert!(signals.iter().any(|s| s.kind == "c-style-cast"),
            "should detect C-style cast");
    }

    #[test]
    fn build_behavioral_system_prompt_requires_reasoning_first() {
        let signals = vec![BehavioralSignal {
            kind: "async-scope".into(),
            evidence: "async/await".into(),
            concern: "may have scope issue".into(),
        }];
        let prompt = build_behavioral_system_prompt(&signals);
        assert!(prompt.contains("<reasoning>"), "behavioral prompt must require <reasoning>");
        assert!(prompt.contains("</reasoning>"));
    }
}
