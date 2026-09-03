// Scanner pipeline — extracts API claims, validates via LLM, classifies results.
// Full feature parity with TypeScript scanner.ts.

/// Create a Command with console window hidden on Windows.
/// Drop-in replacement for `std::process::Command::new`.
pub fn command_hidden(program: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    hide_window(&mut cmd);
    cmd
}

/// Create a tokio Command with console window hidden on Windows.
pub fn command_hidden_tokio(program: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    hide_window_tokio(&mut cmd);
    cmd
}

/// Hide console window on Windows. Call after Command::new, before spawn.
#[cfg(target_os = "windows")]
pub fn hide_window(cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
}

#[cfg(target_os = "windows")]
pub fn hide_window_tokio(cmd: &mut tokio::process::Command) {
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x08000000);
}

#[cfg(not(target_os = "windows"))]
pub fn hide_window(_cmd: &mut std::process::Command) {}

#[cfg(not(target_os = "windows"))]
pub fn hide_window_tokio(_cmd: &mut tokio::process::Command) {}

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;
use parking_lot::Mutex;
use std::time::{Duration, Instant};


/// Safe string slice from `start` to end. Snaps to char boundary.
pub(crate) fn safe_slice_from(s: &str, start: usize) -> &str {
    if start >= s.len() {
        return "";
    }
    let mut ss = start;
    while ss > 0 && !s.is_char_boundary(ss) {
        ss -= 1;
    }
    &s[ss..]
}

/// Safe string slice from 0 to `end`. Snaps to char boundary.
pub(crate) fn safe_slice_to(s: &str, end: usize) -> &str {
    let end = end.min(s.len());
    let mut ee = end;
    while ee > 0 && !s.is_char_boundary(ee) {
        ee -= 1;
    }
    &s[..ee]
}


/// Context for a scan operation.
#[derive(Clone)]
pub struct ScanContext {
    pub project_root: String,
    pub logic_model: String,
    pub llm_base_url: String,
    pub llm_api_key: String,
    pub llm_extra_headers: Vec<(String, String)>,
    pub request_class: String,
    /// Explicit language hint (e.g., "python", "go", "java"). When non-empty,
    /// scan_response uses this directly instead of guessing from content.
    /// Set by callers that know the language (DELULU benchmark, file extension).
    pub language: String,
    /// Cancellation token for cooperative shutdown of detached sub-tasks.
    /// When the deep scan times out (proxy.rs DEEP_SCAN_TIMEOUT), this is
    /// cancelled — spawned children that select on `.cancelled()` exit
    /// promptly instead of writing to cache/logs after the parent task dies.
    /// Only ever cancelled by the deep-scan timeout path; normal scans run
    /// to completion (the token never fires).
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Result of a scan operation.
pub struct ScanResultData {
    pub clean: bool,
    pub warnings: Vec<String>,
    pub blocks: Vec<String>,
    pub details: Vec<String>,
    pub validator_response: String,
    pub scan_failed: bool,
    pub docs_assisted: bool,
    /// Token usage from validator LLM call (0 if validator not called).
    pub validator_tokens: u64,
    /// Continuous risk score in `[0.0, 1.0]`.
    ///
    /// 0.0 = provably clean (no signals fired).
    /// 1.0 = provably hallucinated (explicit block or saturated signals).
    ///
    /// Derived deterministically from the other fields via
    /// [`compute_risk_score`] at the end of [`scan_response`]. Lets clients
    /// pick their own threshold instead of being locked into ALLOW/ESCALATE/BLOCK.
    pub risk_score: f64,
    /// Scan-level confidence in `[0.0, 1.0]` — how sure the deterministic
    /// layers (L1.5 + FORGE) are about the verdict.
    ///
    /// 1.0 = every claim resolved with strong deterministic evidence
    ///       (exact cache hit, AST introspection, runtime require()).
    /// 0.5 = mixed — some claims resolved, some fuzzy or unmatched.
    /// 0.0 = no claims resolved (everything is unknown).
    ///
    /// Drives the L3 cascade: scans with high confidence skip L3 entirely;
    /// low-confidence scans escalate uncertain claims to L3.
    /// See `scan_response` for the cascade decision logic.
    pub confidence: f64,
}

impl Default for ScanResultData {
    fn default() -> Self {
        Self {
            clean: true,
            warnings: vec![],
            blocks: vec![],
            details: vec![],
            validator_response: String::new(),
            scan_failed: false,
            docs_assisted: false,
            validator_tokens: 0,
            risk_score: 0.0,
            confidence: 1.0, // vacuously confident when there's nothing to check
        }
    }
}

impl ScanResultData {
    /// Recompute derived fields (risk_score, clean, confidence) from current
    /// warnings/blocks. Call this after any mutation to warnings or blocks —
    /// each scan layer (FORGE, L3, behavioral, compiler) must call this after
    /// adding its warnings so risk/conf are always consistent with result.
    /// This prevents "scan_result=warning but risk_score=0" mismatches when
    /// scan_response returns early or a timeout truncates the pipeline.
    pub fn recompute(&mut self) {
        self.clean = !self.scan_failed && self.warnings.is_empty() && self.blocks.is_empty();
        self.risk_score = compute_risk_score(self);
        // When warnings exist, confidence must drop — proportional to risk.
        // No warnings → confidence stays at whatever the deterministic layers set.
        if !self.warnings.is_empty() || !self.blocks.is_empty() {
            let max_conf = 1.0 - self.risk_score.min(0.9);
            self.confidence = self.confidence.min(max_conf);
        }
    }

    /// Push a warning and immediately recompute derived fields.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
        self.recompute();
    }
}

/// Compute a continuous risk score in `[0.0, 1.0]` from a `ScanResultData`.
///
/// Signals (in order of severity):
///
/// | Signal | Weight | Cap |
/// |---|---|---|
/// | `blocks` non-empty | → 1.0 (hard floor) | 1.0 |
/// | `cached-hallucination:` warning | +0.40 each | 1.0 |
/// | `scope-hallucination:` warning | +0.40 each | 1.0 |
/// | `forge:` deterministic warning | +0.40 each | 1.0 |
/// | `Hallucinated API:` fuzzy warning | +0.10 each | 0.30 |
/// | `Unverified API:` warning | +0.08 each | 0.6 |
/// | `logic:` detail (L3 issue) | +0.15 each | 0.9 |
/// | `logic (uncertain):` detail | +0.10 each | 0.7 |
/// | `scan_failed` (validator errored) | floor at 0.4 | 0.4 |
///
/// Capped at 1.0. The score intentionally weights deterministic signals
/// (L1.5 cached-hallucination, FORGE, scope) above heuristic ones (L1
/// fuzzy match, L3 issues). L1 fuzzy is capped at 0.30 — a single spurious
/// Estimate BPE token count for content (council A13).
///
/// `len() / 4` assumed 4 bytes/token which is accurate for ASCII English
/// but underestimated CJK content ~3x (1 CJK char = ~3 UTF-8 bytes but
/// ~1 BPE token). Mixed-language content (Korean/Chinese/Japanese code
/// with English identifiers) would falsely trip the "too few tokens"
/// scan gate.
///
/// Heuristic: ASCII/Latin chars ~0.25 tokens, CJK and other multibyte
/// chars ~1 token. Closer to actual cl100k_base/GLM tokenizer behaviour
/// without requiring a tokenizer dependency.
pub fn estimate_tokens(content: &str) -> usize {
    let mut tokens = 0.0f64;
    for c in content.chars() {
        if (c as u32) < 0x80 {
            tokens += 0.25;
        } else {
            // CJK ranges (Hiragana/Katakana/CJK Unified/Hangul) plus other
            // multibyte scripts (Cyrillic, Arabic, etc.) — BPE typically
            // allocates ~1 token per char for these.
            tokens += 1.0;
        }
    }
    tokens.ceil() as usize
}

/// match cannot drive block-mode intervention (threshold 0.3), but 3+
/// independent fuzzy suggestions still surface as advisor warnings.
pub fn compute_risk_score(result: &ScanResultData) -> f64 {
    // Hard block → 1.0 unconditionally.
    if !result.blocks.is_empty() {
        return 1.0;
    }

    use crate::scanner::forge_pipeline::{classify_warning, is_forge_hallucination, WarningKind};
    let mut score: f64 = 0.0;

    // Deterministic hallucinations from L1.5 symbol cache.
    let cached_hallu = result
        .warnings
        .iter()
        .filter(|w| classify_warning(w) == WarningKind::CachedHallucination)
        .count();
    score += (cached_hallu as f64) * 0.40;

    // Deterministic hallucinations from L1.5 scope analysis.
    // check_instance_calls walks var.method() patterns and verifies the
    // method exists on the variable's declared/inferred type. Same authority
    // as cached-hallucination — both use the SymbolCache as ground truth.
    let scope_hallu = result
        .warnings
        .iter()
        .filter(|w| classify_warning(w) == WarningKind::ScopeHallucination)
        .count();
    score += (scope_hallu as f64) * 0.40;

    // Deterministic hallucinations from L1.7 FORGE pipeline.
    // FORGE warnings are emitted by AST + runtime introspection (Python dir(),
    // Node.js require(), docs.rs, javadoc.io, NuGet, Go proxy). They use the
    // actual library API surface as ground truth — higher precision than L1.5
    // fuzzy cache matches. Treat with the same weight as cached-hallucination.
    //
    // FORGE warnings are added to result.warnings with `forge: ` prefix (see
    // mod.rs:1474). classify_warning strips the prefix automatically and
    // is_forge_hallucination covers every Hallucinated* variant plus
    // BareCriticalCall / ChainBroken / ChainPhantomMember.
    let forge_hallu = result
        .warnings
        .iter()
        .filter(|w| is_forge_hallucination(w))
        .count();
    score += (forge_hallu as f64) * 0.40;

    // Heuristic fuzzy match from L1 — `Hallucinated API: X() (did you mean Y?)`
    // emitted when a claim's edit-distance to an indexed symbol is small.
    //
    // LOWER WEIGHT than deterministic checks above. L1 fuzzy has known FP
    // patterns that cached-hallucination/FORGE/scope do not:
    //   1. User-defined functions not present in project index
    //   2. Identifiers parsed from non-code regions (command output, prose,
    //      log lines) — the matcher has no code-region awareness
    //   3. Symbols from freshly-read files not yet re-indexed
    //
    // Single fuzzy match contributing 0.40 risk was enough to trip block
    // mode (threshold 0.3) on FPs. At 0.10 per match (cap 0.30), it takes
    // 3+ independent fuzzy suggestions to even reach advisor threshold —
    // a single spurious match can no longer drive intervention.
    let l1_hallu = result
        .warnings
        .iter()
        .filter(|w| classify_warning(w) == WarningKind::HallucinatedApi)
        .count();
    score += ((l1_hallu as f64) * 0.10).min(0.30);

    // Unverified API calls from L1 (cap contribution at 0.6 — at some point
    // more unverified calls don't add real signal).
    let unverified = result
        .warnings
        .iter()
        .filter(|w| classify_warning(w) == WarningKind::UnverifiedApi)
        .count();
    let unverified_contrib = ((unverified as f64) * 0.08).min(0.6);
    score += unverified_contrib;

    // L3 validator issues. Two flavors: confirmed and uncertain.
    let mut logic_confirmed = 0usize;
    let mut logic_uncertain = 0usize;
    for d in &result.details {
        if d.starts_with("logic (uncertain):") {
            logic_uncertain += 1;
        } else if d.starts_with("logic:") {
            logic_confirmed += 1;
        }
    }
    score += ((logic_confirmed as f64) * 0.15).min(0.6);
    score += ((logic_uncertain as f64) * 0.10).min(0.4);

    // Compiler verifier warnings (pyright/py_compile/gofmt/etc). Syntax errors
    // in extracted code are a hallucination signal — hallucinated API calls
    // often produce code that doesn't parse. Weight matches logic issues.
    use crate::scanner::forge_pipeline::prefix as p;
    let compiler_errors = result
        .warnings
        .iter()
        .filter(|w| {
            let stripped = w.strip_prefix(p::FORGE).unwrap_or(w);
            stripped.starts_with(p::COMPILER)
        })
        .count();
    score += ((compiler_errors as f64) * 0.35).min(0.70);

    // Validator error floor — we can't say it's clean if we couldn't validate.
    if result.scan_failed && (!result.warnings.is_empty() || !result.blocks.is_empty()) {
        score = score.max(0.4);
    }

    score.min(1.0)
}

/// Debug helper — categorize warnings by prefix for log inspection.
/// Returns (cached, scope, forge, unverified, other).
#[allow(dead_code)]
fn categorize_warnings(warnings: &[String]) -> (usize, usize, usize, usize, usize) {
    use crate::scanner::forge_pipeline::{classify_warning, is_forge_hallucination, WarningKind};    let mut cached = 0usize;
    let mut scope = 0usize;
    let mut forge = 0usize;
    let mut unverified = 0usize;
    let mut other = 0usize;
    for w in warnings {
        match classify_warning(w) {
            WarningKind::CachedHallucination => cached += 1,
            WarningKind::ScopeHallucination => scope += 1,
            WarningKind::HallucinatedApi => {
                // L1 fuzzy match — counted as `other` here because the tuple
                // (cached, scope, forge, unverified, other) does not have an
                // l1 slot. Original impl subtracted l1 from total via the
                // `other = total - cached - scope - l1 - forge - unverified`
                // formula, so l1 ended up in `other` too.
                other += 1;
            }
            WarningKind::UnverifiedApi => unverified += 1,
            WarningKind::Other => other += 1,
            _ => {
                // All remaining kinds are FORGE-prefixed hallucinations.
                // Sanity: must be a forge hallucination.
                debug_assert!(is_forge_hallucination(w));
                forge += 1;
            }
        }
    }
    (cached, scope, forge, unverified, other)
}

// ---------------------------------------------------------------------------
// Verdict cache — content-hash → ScanResultData, 24h TTL, 500 cap

mod verdict_cache;
pub use verdict_cache::*;


// ---------------------------------------------------------------------------
// SKIP_NAMES — full set matching TypeScript scanner
pub mod claims;
use claims::*;

// ---------------------------------------------------------------------------
// Extract API claims from content

/// Extract only content inside markdown fenced code blocks (```...```).
///
/// Used by extract_api_claims to avoid false positives — when an agent
/// writes "cargo test()" in prose, that's a description, not an API call.
/// Only code inside fenced blocks should be checked for API claims.
///
/// Extraction strategies, in priority order:
/// 1. Markdown fenced code blocks (```lang ... ```)
/// 2. Tool-call JSON arguments (`"content":"..."`, `"command":"..."`)
/// 3. Raw code with prose lines filtered out
///
/// Returns empty string if no code found.

/// Per-block code validator for fenced content. More permissive than
/// [`looks_like_code`] because being inside a fence is already a strong code
/// signal — we only need to reject blocks that are CLEARLY English prose.
///
/// A block passes when ANY of:
///   - It's very short (≤2 non-empty lines) — single expressions, calls
///   - It passes [`looks_like_code`] (has imports, fn defs, operators)
///   - ≥50% of its non-empty lines survive [`filter_prose_lines`]
fn block_looks_like_code(block: &str) -> bool {
    let non_empty: Vec<&str> = block.lines().filter(|l| !l.trim().is_empty()).collect();
    if non_empty.is_empty() {
        return false;
    }
    // Short blocks are accepted — a single `foo.bar()` is valid code even
    // without imports or fn defs. Avoids over-filtering short snippets.
    if non_empty.len() <= 2 {
        return true;
    }
    // Strong code signal — accept immediately.
    if looks_like_code(block) {
        return true;
    }
    // Ratio gate: accept if at least half the lines survive prose filtering.
    let filtered = filter_prose_lines(block);
    let filtered_lines: usize = filtered.lines().filter(|l| !l.trim().is_empty()).count();
    filtered_lines * 2 >= non_empty.len()
}

fn extract_code_blocks_only(content: &str) -> String {
    // Strategy 1: extract fenced code blocks, validating each block.
    // The agent often emits ```text or ```markdown blocks containing English
    // prose (analysis, explanations, verdicts). Without per-block filtering,
    // that prose gets concatenated and sent to the FORGE Python AST parser,
    // which happily parses English sentences as valid Python (each capitalized
    // word becomes an `ast.Name` → flagged as undefined variable → hundreds
    // of false positives from a single verbose sub-agent response).
    //
    // Two gates per block:
    //   1. Language tag: skip blocks explicitly tagged as non-code
    //      (`text`, `markdown`, `plaintext`, `plain`, `diff`, `log`).
    //   2. Content check: remaining blocks must pass `looks_like_code`.
    //      Catches untagged prose blocks and mistagged content.
    let mut result = String::with_capacity(content.len());
    let mut saw_fence = false;
    let mut current_block = String::new();
    let mut current_lang: Option<&str> = None;
    let mut in_block = false;

    /// Language tags that signal NON-code content (prose, logs, diffs).
    /// Blocks tagged with these are skipped entirely.
    const PROSE_LANG_TAGS: &[&str] = &[
        "text", "plaintext", "plain", "markdown", "md",
        "diff", "log", "patch", "csv", "tsv",
    ];

    /// Language tags for languages our scanner actually supports.
    /// Blocks tagged with a language NOT in this set AND NOT in
    /// PROSE_LANG_TAGS are auxiliary content (schema, config, data)
    /// and must be skipped to prevent cross-language contamination.
    ///
    /// Root cause of 28/45 E2E FPs: ```prisma blocks with DSL keywords
    /// (Int, autoincrement) scanned as TS variables; ```proto blocks
    /// with message names (Task, CreateTaskRequest) scanned as Go
    /// undefined variables.
    const SUPPORTED_CODE_LANG_TAGS: &[&str] = &[
        "python", "py",
        "rust", "rs",
        "typescript", "ts", "tsx", "javascript", "js", "jsx",
        "go", "golang",
        "java",
        "csharp", "c#", "cs",
        "cpp", "c++", "c",
        "gdscript", "gd",
    ];

    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            saw_fence = true;
            if in_block {
                // Closing fence — validate and maybe flush current block.
                let lang = current_lang.unwrap_or("");
                let is_prose_tagged = PROSE_LANG_TAGS.contains(&lang);
                let is_unsupported_lang = !lang.is_empty()
                    && !SUPPORTED_CODE_LANG_TAGS.contains(&lang);
                if !is_prose_tagged
                    && !is_unsupported_lang
                    && block_looks_like_code(&current_block)
                {
                    result.push_str(&current_block);
                    if !result.ends_with('\n') {
                        result.push('\n');
                    }
                }
                current_block.clear();
                current_lang = None;
                in_block = false;
            } else {
                // Opening fence — extract language tag.
                let tag = trimmed
                    .trim_start_matches("```")
                    .trim()
                    .split(|c: char| c.is_whitespace() || c == ',')
                    .next()
                    .unwrap_or("")
                    .trim();
                current_lang = if tag.is_empty() { None } else { Some(tag) };
                current_block.clear();
                in_block = true;
            }
            continue;
        }
        if in_block {
            current_block.push_str(line);
            current_block.push('\n');
        }
    }

    // Strategy 1 succeeded: at least one code block passed validation.
    if !result.is_empty() {
        return result;
    }

    // Strategy 2: extract code from tool-call JSON arguments.
    //
    // The proxy concatenates delta.content (prose) + tool_calls.arguments
    // (JSON fragments) into one string. When the agent uses tool calls to
    // write files (the common pattern for opencode/cursor/etc.), the actual
    // code is inside JSON fields like "content" or "command", surrounded by
    // prose preamble. Extracting just the field values strips the prose.
    //
    // GUARD: only run on content that looks like it contains tool-call JSON.
    // Without this, the regex matches patterns inside Python/Rust string
    // literals (e.g. `input := :data;` inside a triple-quoted SQL string)
    // and extracts garbage that FORGE can't parse — killing recall on the
    // DELULU benchmark (0% Python recall before this guard).
    // Detect both OpenAI tool_calls format AND Anthropic tool_use format.
    // Anthropic Update commands wrap file diffs in tool_use blocks with
    // input fields like newString/oldString — without these patterns the
    // hallucinated code inside edit commands slips past FORGE entirely.
    let has_tool_call_json = detect_tool_call_marker(content);
    let tool_code = if has_tool_call_json {
        extract_tool_call_code(content)
    } else {
        String::new()
    };
    if !tool_code.is_empty() {
        return tool_code;
    }

    // Strategy 3: raw code fallback with prose line filtering.
    //
    // Content looks like code (FIM completions, raw paste dumps) but has
    // mixed prose. Filter out lines that are clearly English sentences.
    // Without this, the DELULU benchmark showed 0% recall on raw FIM
    // samples vs nonzero on fenced samples.
    //
        // PROSE RATIO GATE: Only proceed if the content is predominantly code.
        // Short prose responses that mention "import" or "class" in passing
        // must not trigger the scanner. We check: after filtering, at least
        // 50% of original non-empty lines must survive (minimum 3 lines),
        // OR 100% of lines survive (all-code short content).
        //
        // NOTE: the >1000-char raw-content shortcut was removed because it
        // caused 134 FPs on the Rust benchmark (regex scope checker flagged
        // every English word in prose). Python gets raw content via a
        // language-aware path in scan_response instead (AST handles prose
        // naturally, regex can't).
        if looks_like_code(content) {
            let original_lines: usize = content.lines().filter(|l| !l.trim().is_empty()).count();
            // Short content bypass: if ≤5 non-empty lines AND looks_like_code,
            // return directly without line-by-line filtering. Short code
            // snippets like "import pandas\npandas.read_cvs()" have method
            // calls that don't start with code keywords — filter_prose_lines
            // would incorrectly remove them.
            if original_lines <= 5 {
                return content.to_string();
            }
            let filtered = filter_prose_lines(content);
            let filtered_lines: usize = filtered.lines().filter(|l| !l.trim().is_empty()).count();
            // Accept if all lines survive (short pure code) OR ≥50% survival with ≥3 lines,
            // OR short code (≤4 lines) with ≥2 surviving and ≥50% ratio,
            // OR large code file (≥50 surviving lines) — handles files with
            // large const/string arrays where data entries are legitimately
            // filtered but structural code remains (root cause of Rust DELULU
            // miss: 280-line file with 200 string-literal entries dropped to
            // 80 code lines, failing the 50% ratio gate).
            if (filtered_lines == original_lines && filtered_lines > 0)
                || (filtered_lines >= 3 && filtered_lines * 2 >= original_lines)
                || (original_lines <= 4 && filtered_lines >= 2 && filtered_lines * 2 >= original_lines)
                || (filtered_lines >= 50)
            {
                return filtered;
            }
        }

    result
}

/// Cheap predicate used by scan_response to decide whether to invoke
/// `extract_tool_call_code` on the raw scan_content path. Mirrors the
/// detection in `extract_code_blocks_only` (line 510) so the two paths
/// agree on what counts as a tool-call bearing payload.
fn detect_tool_call_marker(content: &str) -> bool {
    content.contains("\"function\"")
        || content.contains("\"tool_calls\"")
        || content.contains("\"arguments\"")
        || content.contains("\"type\":\"function\"")
        || content.contains("\"type\":\"tool_use\"")
        || content.contains("\"tool_use\"")
        || content.contains("[TOOL_USE:")
        || (content.contains("\"newString\"") && content.contains("\"oldString\""))
        || (content.contains("\"new_string\"") && content.contains("\"old_string\""))
}

/// Extract code from tool-call JSON argument fragments.
///
/// The proxy accumulates streaming tool-call arguments as raw JSON string
/// fragments in `full_content`. When the agent writes files via tool calls
/// (bash heredocs, file_write, edit tools), the actual code is inside JSON
/// string values for fields like:
///   - "content": file content being written
///   - "command": bash/shell command
///   - "input": generic tool input
///
/// This function finds these fields and returns their unescaped values.
/// Returns empty string if no tool-call code found or if extracted code
/// is too short (< 3 lines — likely a config snippet, not real code).
pub fn extract_tool_call_code(content: &str) -> String {
    // Previous regex approach failed on JSON string values containing
    // docstrings (`"""..."""`) or any inner unescaped `"`: the regex
    // stopped at the first quote, truncating the capture mid-value.
    // Replaced with byte-scanner that tracks escape state to find the
    // true closing quote, then delegates unescape to serde_json.
    let target_fields: &[&str] = &[
        "content", "command", "input", "code", "source", "body",
        "file_content", "new_content",
        // Anthropic Update tool (camelCase)
        "newString", "oldString",
        // OpenAI str_replace_editor / Edit tool (snake_case)
        "new_string", "old_string",
        "text", "args",
    ];

    let mut result = String::new();
    let bytes = content.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some((field, after_field)) = parse_json_string_value(content, i) {
                if target_fields.contains(&field.as_str()) {
                    let mut j = after_field;
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < bytes.len() && bytes[j] == b':' {
                        j += 1;
                        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if j < bytes.len() && bytes[j] == b'"' {
                            if let Some((value, after_value)) = parse_json_string_value(content, j) {
                                result.push_str(&value);
                                result.push('\n');
                                i = after_value;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        i += 1;
    }

    let non_empty: Vec<&str> = result.lines().filter(|l| !l.trim().is_empty()).collect();
    if non_empty.len() < 3 {
        return String::new();
    }
    // If extracted content looks like code, return directly.
    if looks_like_code(&result) {
        return result;
    }
    // Otherwise filter prose and apply ratio gate (same as strategy 3).
    let filtered = filter_prose_lines(&result);
    let filtered_lines: usize = filtered.lines().filter(|l| !l.trim().is_empty()).count();
    if filtered_lines >= 3 && filtered_lines * 2 >= non_empty.len() {
        return filtered;
    }
    String::new()
}

/// Parse a JSON string literal starting at `start` (must point to `"`).
/// Tracks escape state byte-by-byte to find the true closing quote, then
/// delegates to `serde_json` for proper unescape (handles `\n`, `\"`, `\\`,
/// `\uXXXX`, multi-byte UTF-8). Returns (unescaped_value, position_after
/// closing_quote). Returns None if no closing quote found or unescape fails.
fn parse_json_string_value(content: &str, start: usize) -> Option<(String, usize)> {
    let bytes = content.as_bytes();
    if start >= bytes.len() || bytes[start] != b'"' {
        return None;
    }
    let mut i = start + 1;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escape {
            escape = false;
        } else if b == b'\\' {
            escape = true;
        } else if b == b'"' {
            // Found end of string. Slice raw literal (with surrounding quotes)
            // and let serde_json handle the unescape — robust against every
            // valid JSON escape sequence including multi-byte UTF-8.
            let raw = &content[start..=i];
            if let Ok(s) = serde_json::from_str::<String>(raw) {
                return Some((s, i + 1));
            }
            return None;
        }
        i += 1;
    }
    None
}

/// Filter out lines that are clearly English prose, keeping only code-like lines.
///
/// Used as a last-resort fallback when content has no markdown fences AND
/// no tool-call JSON. A line is kept if it contains ANY code-specific token.
/// Lines that look like natural language sentences are dropped.
fn filter_prose_lines(content: &str) -> String {
    // Pattern: check if a trimmed line starts with a code keyword/phrase.
    // Using starts_with is critical — these keywords appear in prose
    // mid-sentence ("the class name", "from the database") but code lines
    // ALWAYS start with the keyword (after optional whitespace).
    fn starts_with_any(s: &str, prefixes: &[&str]) -> bool {
        prefixes.iter().any(|p| s.starts_with(p))
    }

    content
        .lines()
        .filter(|line| {
            let t = line.trim();
            if t.is_empty() {
                return true; // preserve structure (blank lines between code blocks)
            }

            // ── KEYWORD CHECKS (line-start only) ───────────────────────
            // These keywords almost always appear at the START of a code
            // line. Mid-sentence usage ("from the database", "class name")
            // is prose, NOT code.
            starts_with_any(t, &[
                "fn ", "def ", "func ", "function ",
                "pub ", "private ", "protected ", "internal ",
                "let mut ", "let ", "var ", "const ",
                "use ", "import ", "from ",
                "#include",
                "require(", "require (",
                "struct ", "class ", "impl ",
                "interface ", "trait ", "enum ",
                "match ", "switch ", "case ",
                "mod ", "package ", "namespace ",
                "return ", "async ", "await ",
                "unsafe ", "extern ",
                "type ", "typealias ", "using ",
                // Control flow — WITHOUT these, filter_prose_lines removes
                // `if TYPE_CHECKING:` etc. from Python code, leaving orphaned
                // indented blocks that cause AST parse failures (zero recall).
                // Case-sensitive: code uses lowercase `if ` / `for ` / `while `;
                // prose typically uses `If ` / `For ` / `While ` (capitalized).
                "if ", "elif ", "else:", "else :",
                "for ", "while ",
                "try:", "try :", "except", "finally:", "finally :",
                "with ",
                "raise ", "yield ",
                "pass", "assert ",
                "global ", "nonlocal ",
                "del ",
                "break", "continue",
                // GDScript — `signal name(args)`, `extends Node`, `class_name X`
                // are declarations that always start a code line. Without these,
                // filter_prose_lines drops the signal declaration, then the
                // GDScript undefined-variable check flags the signal name when
                // it's later referenced via `.connect()` / `.emit()`.
                "signal ", "extends ", "class_name ",
            ])
            // ── OPERATORS (contains — rare in prose) ──────────────────
            || t.contains("::") || t.contains("=>") || t.contains("->")
            || t.contains("&&") || t.contains("||")
            || t.contains("== ") || t.contains("!= ")
            || t.contains(" += ") || t.contains(" -= ")
            || t.contains(" *= ") || t.contains(" /= ")
            // ── ATTRIBUTE / DECORATOR markers ────────────────────────
            || t.starts_with("#[")
            || t.starts_with("@")
            || t.starts_with("///") || t.starts_with("//!")
            || t.starts_with("//") || t.starts_with("/*") || t.starts_with("*")
            || t.starts_with("#")  // Python / Ruby / Shell comments (code, not prose)
            // ── STRUCTURAL lines ─────────────────────────────────────
            || t == "{" || t == "}" || t == "(" || t == ")"
            || t == ");" || t == "});" || t == "};" || t == "},"
            || t.ends_with(';') || t.ends_with('{') || t.ends_with('}')
            || t.ends_with(");") || t.ends_with("}),") || t.ends_with("},")
            // ── VARIABLE ASSIGNMENT (line-start var = ...) ───────────
            // Must start with an identifier, contain " = ", and not end
            // with a period (which would be a prose sentence).
            || (is_word_start(t) && t.contains(" = ") && !t.ends_with('.'))
            // ── JSON / tool-call fragments ─────────────────────────────
            || t.starts_with("{") || t.starts_with("}")
            || (t.starts_with("\"") && t.contains(":"))
            // ── EXPORT statements (TS/JS) ────────────────────────────
            // `export default`, `export const`, `export function`, etc.
            // Bare `export` at line start is virtually always code.
            || t.starts_with("export ") || t == "export"
            // ── BARE FUNCTION CALLS ──────────────────────────────────
            // Lines like `route("/path", "module.tsx"),` or `index(foo)`
            // or `MyClass.method(args)`. Rare in prose; common in TS/JS
            // array-of-routes configs, builder chains, test setups.
            || is_bare_call_line(t)
            // ── DOT-PREFIXED METHOD CHAINS ───────────────────────────
            // FIM completions often start with `.method(args).method2(args)`
            // — continuation of a receiver expression from the previous line.
            // Without this, filter_prose_lines strips the entire completion,
            // and chain verification never fires (root cause of Rust DELULU
            // miss on map.entry(...).or_insert_default()).
            || (t.starts_with('.') && t.chars().nth(1).map_or(false, |c| c.is_ascii_alphabetic() || c == '_'))
            // ── STRING-LITERAL ARRAY ENTRIES ─────────────────────────
            // Lines like `"AIActiveCommandList",` or `"status": 404,` — array
            // or map entries inside a sequence literal. Without this, large
            // const arrays (`const NAMES: &[&str] = &["A", "B", ...];`) get
            // every entry stripped, dropping the survival ratio below 50% and
            // causing extract_code_blocks_only Strategy 3 to return EMPTY —
            // stripping the actual code on neighbouring lines along with them.
            // Discriminator: no whitespace between the quotes — that filters
            // out dialogue-like prose (`"Hello world,"`) while keeping every
            // realistic identifier/path/number literal entry.
            || is_string_literal_entry(t)
            // ── IMPORT SPECIFIER (inside `import { ... }` block) ─────
            // Bare identifier with trailing comma: `index,` `Foo,` `type Bar,`
            // These only appear inside import statements, never in prose.
            || is_import_specifier(t)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Does the trimmed line start with what looks like an identifier or keyword?
/// Minimally: starts with a letter, underscore, or hash (for #! shebangs).
fn is_word_start(s: &str) -> bool {
    s.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_' || c == '#')
}

/// Does this trimmed line look like a bare function/method call?
/// Matches: `route(...)`, `index(foo)`, `MyClass.method(args)`, `obj.x.y(...)`.
/// Rejects: prose sentences (start with capital + contain space + period at end).
/// Rejects: keywords like `if (`, `for (`, `while (` (handled separately above).
fn is_bare_call_line(t: &str) -> bool {
    // Must start with identifier char
    if !is_word_start(t) {
        return false;
    }
    // Reject obvious prose: starts uppercase + ends with period
    // (e.g. "The function returns.")
    if t.chars().next().map_or(false, |c| c.is_ascii_uppercase())
        && t.ends_with('.')
        && t.split_whitespace().count() > 3
    {
        return false;
    }
    // Quick check: must contain `(` somewhere
    let paren_pos = match t.find('(') {
        Some(p) => p,
        None => return false,
    };
    // Prefix before `(` must be identifier-like (word chars, dots, optional type args)
    let prefix = &t[..paren_pos];
    if prefix.is_empty() {
        return false;
    }
    // Reject control-flow keywords (already handled above, but be safe)
    let kw = prefix.split('.').next().unwrap_or(prefix);
    matches!(kw, "if" | "for" | "while" | "switch" | "catch" | "return" | "print" | "println" | "echo")
        .then(|| false)
        .unwrap_or(true)
        && prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Does this trimmed line look like an import specifier inside `import { ... }`?
/// Matches: `index,`, `route,`, `type RouteConfig,`, `Foo as Bar,`.
/// These patterns essentially never appear in prose.
fn is_import_specifier(t: &str) -> bool {
    // Strip optional `type ` prefix
    let s = t.strip_prefix("type ").unwrap_or(t);
    // Must end with `,` (trailing import specifier)
    if !s.ends_with(',') {
        return false;
    }
    let inner = s.trim_end_matches(',');
    // `Foo`, `Foo as Bar` — single or aliased identifier, no spaces other than `as`
    if let Some(idx) = inner.find(" as ") {
        let (left, right) = inner.split_at(idx);
        let right = right.trim_start_matches(" as ");
        return is_pure_identifier(left) && is_pure_identifier(right);
    }
    is_pure_identifier(inner)
}

fn is_pure_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
}

/// Does this trimmed line look like a string-literal sequence entry?
/// Matches: `"foo",`, `"foo/bar",`, `"404",`, `"foo": "bar",` (map entries too).
/// Rejects: dialogue-like prose (`"Hello world,"`) by requiring no whitespace
/// between the first opening quote and the last closing quote on the line.
/// Rejects: lines that contain prose commentary after the literal (e.g.
/// `"foo", // this is the foo entry`).
fn is_string_literal_entry(t: &str) -> bool {
    if !t.starts_with('"') {
        return false;
    }
    // Strip a single trailing `,` or `;` (sequence / statement terminator).
    let body = t.trim_end_matches(',').trim_end_matches(';');
    if body.len() < 2 || !body.ends_with('"') {
        return false;
    }
    // No whitespace between the outer quotes — filters out dialogue while
    // keeping identifiers, paths, numbers, URLs, etc. Also rejects `"foo":`
    // map entries with a value containing spaces (rare in real code).
    let inner = &body[1..body.len() - 1];
    !inner.chars().any(|c| c == ' ' || c == '\t')
}

/// Heuristic: does this content look enough like code that we should scan
/// it even without markdown fences? Triggers on common code shapes:
///   - import / from / require / #include statements
///   - function definitions (fn, function, def, func)
///   - balanced `()` calls with arguments
///   - common operators (=, =>, ::, ->)
///
/// Conservative — prose with one or two code-ish tokens still won't trip
/// it. The goal is to catch raw FIM completions and unfenced paste dumps.
fn looks_like_code(content: &str) -> bool {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE_IMPORT: OnceLock<Regex> = OnceLock::new();
    static RE_FN_DEF: OnceLock<Regex> = OnceLock::new();
    static RE_SHADER_SCENE: OnceLock<Regex> = OnceLock::new();
    let re_import = RE_IMPORT.get_or_init(|| {
        // Line-anchored import-like statements. Avoids prose false-positives
        // like "import this" inside a paragraph — requires real import syntax.
        Regex::new(concat!(
            r#"(?m)^\s*(?:"#,
            r#"import\s+[\w*{]"#,
            r#"|from\s+[\w.]+\s+import\s+"#,
            r#"|const\s+\w+\s*=\s*require\s*\(\s*['\"]"#,
            r#"|use\s+[\w:]+"#,
            r#"|#include\s+[<\"]"#,
            r#")"#,
        )).unwrap()
    });
    let re_fn_def = RE_FN_DEF.get_or_init(|| {
        // Function / class / struct definitions: keyword + name + paren/brace.
        Regex::new(
            r"\b(?:function|fn|def|func|class|struct|interface|impl|package)\s+\w+[\s(<{]",
        ).unwrap()
    });
    let re_shader_scene = RE_SHADER_SCENE.get_or_init(|| {
        // GDShader and Godot scene file markers — these formats are always
        // code but lack import/func keywords that the other regexes check.
        // tscn uses [gd_scene], [ext_resource], [node] — square bracket prefix.
        Regex::new(
            r#"(?m)^\s*\[?(?:shader_type|render_mode|uniform\s+\w|gd_scene|ext_resource|sub_resource|node\s)"#,
        ).unwrap()
    });
    let mut score = 0usize;

    // Imports + function definitions are the strongest signals — both
    // almost never appear in prose, so each alone is sufficient evidence.
    if re_import.is_match(content) {
        score += 3;
    }
    if re_fn_def.is_match(content) {
        score += 3;
    }
    // GDShader / tscn markers — always code, never prose.
    if re_shader_scene.is_match(content) {
        score += 3;
    }

    // Common operators that almost never appear in prose, weighted by rarity.
    if content.contains("=>") { score += 1; }
    if content.contains("::") { score += 1; }
    if content.contains("->") { score += 1; }

    // Method-call shape: `name.method(` — strong but common in prose too,
    // so require at least 2 distinct calls.
    let method_calls: usize = content
        .lines()
        .filter(|l| {
            let bs = l.as_bytes();
            bs.iter().position(|&b| b == b'.')
                .map(|i| i + 1 < bs.len() && bs[i + 1].is_ascii_alphabetic())
                .unwrap_or(false)
        })
        .count();
    if method_calls >= 2 { score += 1; }

    // Code-y punctuation: many semicolons OR many braces.
    let semi = content.matches(';').count();
    if semi >= 3 { score += 1; }
    let braces = content.matches('{').count() + content.matches('}').count();
    if braces >= 4 { score += 1; }

    score >= 3
}
pub fn extract_api_claims(content: &str) -> Vec<String> {
    let skip = skip_names();
    let patterns = claim_patterns();
    let mut claims = Vec::new();
    let mut seen = HashSet::new();

    // Only scan code blocks for API claims — prose mentions of function
    // names (e.g. "cargo test()", "from_str()") are NOT API calls.
    // If no code blocks found, return empty (no claims to verify).
    let code_content = extract_code_blocks_only(content);
    if code_content.is_empty() {
        return claims;
    }
    let local_vars = extract_local_variables(&code_content);

    for ClaimPattern { re, kind } in &patterns {
        for caps in re.captures_iter(&code_content) {
            match kind.as_ref() {
                "class_method" => {
                    // Capital.method( — likely a class/library API.
                    // Only skip by object name, NOT by method name.
                    // (axios.get should be checked even though 'get' is common)
                    let obj = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                    if skip.contains(obj) {
                        continue;
                    }

                    let claim = format!("{}.{}(", obj, method);
                    if seen.insert(claim.clone()) {
                        claims.push(claim);
                    }
                }
                "obj_method" => {
                    // lowercase.method( — likely local var or stdlib.
                    // Skip aggressively by both object AND method name.
                    let mut obj = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let method = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                    // Fix \n escape artifact: \nrouter.patch → nrouter.patch
                    if obj.starts_with('n') && obj.len() > 4 {
                        let rest = &obj[1..];
                        if skip.contains(rest) || local_vars.contains(rest) {
                            obj = rest.to_string();
                        }
                    }

                    if skip.contains(&obj.as_str()) {
                        continue;
                    }

                    if skip.contains(method) {
                        continue;
                    }

                    // Skip common Rust stdlib boolean getters (is_*, has_*).
                    if method.starts_with("is_") || method.starts_with("has_") {
                        continue;
                    }

                    // Skip if object is a local variable (not a library API)
                    if local_vars.contains(obj.as_str()) {
                        continue;
                    }

                    let claim = format!("{}.{}(", obj, method);
                    if seen.insert(claim.clone()) {
                        claims.push(claim);
                    }
                }
                "bare_call" => {
                    let mut name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();

                    // Fix \n escape sequence artifacts: \nbeforeEach → nbeforeEach
                    // The backslash separator matches [^a-zA-Z0-9_.], and 'n'
                    // becomes part of the captured identifier. If removing the
                    // leading 'n' produces a known framework/skip name, use that.
                    if name.starts_with('n') && name.len() > 4 {
                        let rest = &name[1..];
                        if skip.contains(rest) {
                            name = rest.to_string();
                        }
                    }

                    if skip.contains(&name.as_str()) {
                        continue;
                    }

                    // Word boundary: skip if preceded by '.'
                    if let Some(m) = caps.get(1) {
                        if m.start() > 0 {
                            let prev = content.as_bytes()[m.start() - 1];
                            if prev == b'.' {
                                continue;
                            }
                        }
                    }

                    let claim = format!("{}(", name);
                    if seen.insert(claim.clone()) {
                        claims.push(claim);
                    }
                }
                "import" => {
                    // All import patterns have the module/package name in
                    // capture group 1. Emit a claim shaped `from 'pkg'` so
                    // downstream lookup can resolve it.
                    let pkg = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    if pkg.is_empty() {
                        continue;
                    }
                    // Skip relative imports (./, ../) — local, not resolvable
                    // via symbol cache.
                    if pkg.starts_with('.') || pkg.starts_with('/') {
                        continue;
                    }
                    let claim = format!("from '{pkg}'");
                    if seen.insert(claim.clone()) {
                        claims.push(claim);
                    }
                }
                _ => {}
            }
        }
    }

    claims
}

// ---------------------------------------------------------------------------
// Extract local variable names from content (scope-aware Check A)

pub(crate) fn extract_local_variables(content: &str) -> HashSet<String> {
    let mut vars = HashSet::new();
    let _bytes = content.as_bytes();

    use std::sync::OnceLock;
    static DECL_RE: OnceLock<regex::Regex> = OnceLock::new();
    static PARAM_RE: OnceLock<regex::Regex> = OnceLock::new();
    static DESTR_RE: OnceLock<regex::Regex> = OnceLock::new();
    static PY_ASSIGN_RE: OnceLock<regex::Regex> = OnceLock::new();
    static PY_DECORATOR_ARG_RE: OnceLock<regex::Regex> = OnceLock::new();
    static PY_SELF_RE: OnceLock<regex::Regex> = OnceLock::new();
    let decl_re = DECL_RE.get_or_init(|| regex::Regex::new(
        r"\b(?:const|let|var|for\s*\(\s*(?:const|let|var)?)\s+([a-z_][a-zA-Z0-9_]*)\b",
    ).unwrap());
    let param_re = PARAM_RE.get_or_init(|| regex::Regex::new(r"\(([^)]{0,200})\)\s*(?:=>|\{)").unwrap());
    let destr_re = DESTR_RE.get_or_init(|| regex::Regex::new(r"\b(?:const|let|var)\s+\{([^}]+)\}").unwrap());
    // Python/Ruby/GDScript-style bare assignment: `NAME = value` at line start
    // (no preceding `.`/`=`/comparison ops). Defines the name for scope purposes
    // (e.g. `_SessionLocal = sessionmaker(...)`, `runner = CliRunner()`).
    let py_assign_re = PY_ASSIGN_RE.get_or_init(|| regex::Regex::new(
        r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?:=|\+=|-=|\*=|/=)\s*[^=]",
    ).unwrap());
    // Decorator-injected parameters: `@click.argument("query")` /
    // `@app.query(name)` bind the string arg as a function parameter at runtime.
    // Only fires on decorator lines (leading @), never inside call bodies.
    let py_dec_arg_re = PY_DECORATOR_ARG_RE.get_or_init(|| regex::Regex::new(
        r#"(?m)^\s*@\w[\w.]*\.(?:argument|option)\s*\(\s*["']([A-Za-z_][A-Za-z0-9_\-]*)["']"#,
    ).unwrap());
    // Python method receivers: `def method(self, ...)` / `def method(cls, ...)`
    // bind self/cls inside the method body. Referencing self.ndim inside a
    // quoted method fragment is NOT a hallucinated variable.
    let py_self_re = PY_SELF_RE.get_or_init(|| regex::Regex::new(
        r"\bdef\s+\w+\s*\(\s*(self|cls)\s*[,)]",
    ).unwrap());
    for caps in py_self_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            vars.insert(m.as_str().to_string());
        }
    }
    for caps in decl_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            vars.insert(m.as_str().to_string());
        }
    }

    // Python-style bare assignments
    for caps in py_assign_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            vars.insert(m.as_str().to_string());
        }
    }

    // Decorator-injected params (click.argument/option and similar)
    for caps in py_dec_arg_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            // click normalizes `-` to `_` in parameter names
            vars.insert(m.as_str().replace('-', "_"));
        }
    }

    // Function params: function name(a, b,  or (a, b) =>
    for caps in param_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            for param in m.as_str().split(',') {
                let trimmed = param
                    .trim()
                    .trim_start_matches("const ")
                    .trim_start_matches("let ");
                // Handle destructuring: { a, b } or [a, b]
                for ident in trimmed
                    .split(|c: char| c == ',' || c == '{' || c == '}' || c == '[' || c == ']')
                {
                    let clean = ident.trim().trim_start_matches("...").trim();
                    if clean.len() >= 1 && clean.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        if !clean
                            .chars()
                            .next()
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(true)
                        {
                            vars.insert(clean.to_string());
                        }
                    }
                }
            }
        }
    }

    // Destructuring: const { a, b } = ...
    for caps in destr_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            for part in m.as_str().split(',') {
                let clean = part.trim().split(':').next().unwrap_or("").trim();
                if clean.len() >= 1 && clean.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    vars.insert(clean.to_string());
                }
            }
        }
    }

    vars
}

// ---------------------------------------------------------------------------
// Strip tool outputs from content before scanning

fn strip_tool_outputs(content: &str) -> String {
    use std::sync::OnceLock;
    static TOOL_RE: OnceLock<regex::Regex> = OnceLock::new();
    static FENCE_RE: OnceLock<regex::Regex> = OnceLock::new();
    static METADATA_RE: OnceLock<regex::Regex> = OnceLock::new();

    let tool_re = TOOL_RE.get_or_init(|| {
        regex::Regex::new(r"(?s)<tool_(?:result|response)>.*?</tool_(?:result|response)>").unwrap()
    });
    let fence_re = FENCE_RE.get_or_init(|| {
        regex::Regex::new(r"(?s)```(?:json|xml)\n(.{500,}?)```").unwrap()
    });
    let metadata_re = METADATA_RE.get_or_init(|| {
        regex::Regex::new(
            r#""(?:prompt_tokens|completion_tokens|total_tokens|reasoning_tokens|cached_tokens|prompt_tokens_details|completion_tokens_details|system_fingerprint|finish_reason)":\s*[\d"a-z_]+"#
        ).unwrap()
    });

    let mut result = tool_re.replace_all(content, "[tool output stripped]").to_string();
    result = fence_re.replace_all(&result, "[large code block stripped]").to_string();
    result = metadata_re.replace_all(&result, "").to_string();
    result
}

// ---------------------------------------------------------------------------
// Project index — walk source files, extract declarations

pub mod project_index;
pub mod scope_analysis;
pub mod package_index;
pub mod ast_extractor;
pub mod local_introspect;
pub mod rust_introspect;
pub mod rust_ast_extractor;
pub mod ts_ast_extractor;
pub mod go_ast_extractor;
pub mod go_introspect;
pub mod java_introspect;
pub mod cpp_introspect;
pub mod c_introspect;
pub mod csharp_introspect;
pub mod csharp_ast_extractor; // tree-sitter AST scope extractor (replaces regex)
pub mod tscn_introspect;
pub mod gdshader_introspect;
pub mod ts_introspect;
pub mod ts_method_checker;
pub mod forge_pipeline;
pub mod forge_types; // M1: extracted from forge_pipeline.rs — ForgeResult struct + impl
pub mod forge_c; // M1: extracted from forge_pipeline.rs — C language FORGE runner
pub mod compiler_verifier;
pub mod surface_gate_ts; // v3: installed-package API-surface gate (TS/JS)
pub mod surface_gate_py; // v3: installed-package API-surface gate (Python)
pub mod lsp_gate; // LSP FP gate — suppresses FORGE false positives via rust-analyzer
pub mod lsp_config; // FOUND-002: per-language LspSpawnConfig + detect_workspace_root
pub mod lsp_registry; // FOUND-005: DashMap registry, cap 8, idle reaper
pub mod compiler_cache; // Phase 2: content-hash cache for compiler FP-gate output
pub mod lsp; // COLD-001: unified LSP subsystem façade (config + prewarm + reaper + cap + fallback + sidecar)
pub mod forge_cpp; // M1: extracted from forge_pipeline.rs — C++ FORGE runner
pub mod forge_csharp; // M1: extracted from forge_pipeline.rs — C# FORGE runner
pub mod forge_gdscript; // M1: extracted from forge_pipeline.rs — Godot/GDScript FORGE runner
pub mod forge_go; // M1: extracted from forge_pipeline.rs — Go FORGE runner
pub mod forge_java; // M1: extracted from forge_pipeline.rs — Java FORGE runner
pub mod forge_rust; // M1: extracted from forge_pipeline.rs — Rust FORGE runner
pub mod forge_ts; // M1: extracted from forge_pipeline.rs — TypeScript/JavaScript FORGE runner
pub mod forge_python; // M1: extracted from forge_pipeline.rs — Python FORGE runner
pub mod scope_extractor; // M1: generic undefined-variable extractor (council #3, #9)
pub mod language_detection; // M1: extracted from forge_pipeline.rs — detect_language heuristic
pub mod language; // FOUND-003: type-safe Language enum + lsp_config/lsp_language_id accessors
pub mod forge_scene; // M1: extracted from forge_pipeline.rs — Godot tscn+gdshader runners
pub mod arity; // M1: extracted from forge_pipeline.rs — arity checker helpers
pub mod levenshtein; // M1: extracted from forge_pipeline.rs — Levenshtein helpers
pub mod string_filters; // M1: extracted from forge_pipeline.rs — string-literal + function-call filters

pub mod l3_per_claim;
pub mod l3_verdi; // VERDI single-call confidence calibration (arXiv:2605.11334)
use project_index::*;
// `LAST_VERIFIED` is a per-project-root map of the last-seen content per
// project. Used by `compute_diff` so that follow-up scans only re-validate
// the new tail of a streaming response. Without a cap, every distinct
// project the user ever opened would accumulate forever — bounded LRU
// of 50 projects × 8KB per entry = 400KB hard ceiling, plenty for daily use.
//
// Council B8+C7: pair the HashMap with a VecDeque<String> tracking
// insertion order so eviction can pick the actual oldest entry instead
// of `map.keys().next()` (which is unspecified HashMap iteration order
// and was reported as MED by the council reviewer). FIFO semantics —
// existing-key updates don't reorder, since touching reorders only
// matter for true LRU and the practical impact here is bounded.
static LAST_VERIFIED: Mutex<Option<(HashMap<String, String>, std::collections::VecDeque<String>)>> = Mutex::new(None);
const MAX_LAST_CONTENT: usize = 8000;
const LAST_VERIFIED_MAX_PROJECTS: usize = 50;

/// Compute diff: if new content starts with old content (prefix overlap), return only the suffix.
/// If >60% prefix overlap, return tail. Otherwise return full content.
fn compute_diff(new_content: &str, old_content: &str) -> String {
    if old_content.is_empty() {
        return new_content.to_string();
    }

    // Exact prefix match: new starts with old → return suffix
    if new_content.starts_with(old_content) {
        return new_content
            .get(old_content.len()..)
            .unwrap_or(new_content)
            .to_string();
    }

    // Find longest common prefix
    let min_len = new_content.len().min(old_content.len());
    let mut common = 0;
    for i in 0..min_len {
        if new_content.as_bytes()[i] == old_content.as_bytes()[i] {
            common = i + 1;
        } else {
            break;
        }
    }

    // If >60% overlap, return the tail
    if common > min_len * 6 / 10 {
        return new_content.get(common..).unwrap_or(new_content).to_string();
    }

    new_content.to_string()
}

/// Track verified content for diff scanning. Returns the diff (new content to scan).
///
/// Bounded FIFO: when the project map exceeds `LAST_VERIFIED_MAX_PROJECTS`,
/// the oldest-inserted project is dropped (tracked via the parallel
/// VecDeque). Rationale: a daemon running for weeks across dozens of
/// projects would otherwise grow this map without bound.
fn get_diff_and_update(project_root: &str, content: &str) -> String {
    let mut guard = LAST_VERIFIED.lock();
    let (map, order) = guard.get_or_insert_with(|| (HashMap::new(), std::collections::VecDeque::new()));

    let old = map.get(project_root).cloned().unwrap_or_default();
    let diff = compute_diff(content, &old);

    // Update with new content (capped)
    let capped = if content.len() > MAX_LAST_CONTENT {
        content
            .get(..MAX_LAST_CONTENT)
            .unwrap_or(content)
            .to_string()
    } else {
        content.to_string()
    };
    let is_new_key = !map.contains_key(project_root);
    map.insert(project_root.to_string(), capped);
    if is_new_key {
        order.push_back(project_root.to_string());
    }

    // FIFO prune — drop oldest-inserted entries when over cap. True LRU
    // would reorder on access, but the practical difference here is
    // bounded: a "wrong" eviction just means a future scan pays the
    // full-content cost instead of the diff cost — recoverable, not buggy.
    while map.len() > LAST_VERIFIED_MAX_PROJECTS {
        let key_to_drop = order.pop_front();
        if let Some(k) = key_to_drop {
            map.remove(&k);
        } else {
            break;
        }
    }

    diff
}

// ---------------------------------------------------------------------------
// Manifest deps — read package.json/Cargo.toml/go.mod/etc

static MANIFEST_CACHE: Mutex<Option<(String, String, u64)>> = Mutex::new(None); // (root, text, built_at)
const MANIFEST_TTL_MS: u64 = 30_000;

fn read_project_manifests(project_root: &str) -> String {
    let now = current_time_ms();
    {
        let guard = MANIFEST_CACHE.lock();
        if let Some((root, text, built)) = &*guard {
            if root == project_root && now - built < MANIFEST_TTL_MS {
                return text.clone();
            }
        }
    }

    let manifest_files = [
        "package.json",
        "Cargo.toml",
        "go.mod",
        "pyproject.toml",
        "requirements.txt",
        "Pipfile",
        "Gemfile",
        "pom.xml",
        "build.gradle",
        "project.godot",
    ];

    let mut deps = Vec::new();

    for manifest in &manifest_files {
        let path = Path::new(project_root).join(manifest);
        if let Ok(content) = fs::read_to_string(&path) {
            let name = manifest;
            deps.push(format!("=== {} ===", name));

            match *manifest {
                "package.json" => {
                    // Extract just dependency names from dependencies/devDependencies
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                        for key in ["dependencies", "devDependencies"] {
                            if let Some(deps_obj) = v.get(key).and_then(|d| d.as_object()) {
                                for dep_name in deps_obj.keys() {
                                    deps.push(format!("  {}", dep_name));
                                }
                            }
                        }
                    }
                }
                "Cargo.toml" => {
                    // Extract [dependencies] section
                    let mut in_deps = false;
                    for line in content.lines() {
                        if line.starts_with("[dependencies]")
                            || line.starts_with("[dev-dependencies]")
                        {
                            in_deps = true;
                            continue;
                        }
                        if line.starts_with('[') {
                            in_deps = false;
                        }
                        if in_deps {
                            if let Some(name) = line.split('=').next() {
                                let name = name.trim();
                                if !name.is_empty() {
                                    deps.push(format!("  {}", name));
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Generic: first 20 non-empty lines
                    for line in content.lines().filter(|l| !l.trim().is_empty()).take(20) {
                        deps.push(format!("  {}", line.trim()));
                    }
                }
            }
        }
    }

    // Check for *.csproj (glob)
    if let Ok(entries) = fs::read_dir(project_root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".csproj") {
                deps.push(format!("=== {} ===", name));
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    let pkg_re =
                        regex::Regex::new(r#"<PackageReference\s+Include="([^"]*)""#).unwrap();
                    for caps in pkg_re.captures_iter(&content) {
                        if let Some(m) = caps.get(1) {
                            deps.push(format!("  {}", m.as_str()));
                        }
                    }
                }
            }
        }
    }

    let text = deps.join("\n");
    {
        let mut guard = MANIFEST_CACHE.lock();
        *guard = Some((project_root.to_string(), text.clone(), now));
    }
    text
}

// ---------------------------------------------------------------------------
// Local docs search — ~/.anubis/docs/

static DOCS_CACHE: Mutex<Option<(u64, HashMap<String, String>)>> = Mutex::new(None); // (built_at, filename→content)
const DOCS_TTL_MS: u64 = 30_000;
const MAX_DOCS_RESULT: usize = 3000;

fn home_dir() -> String {
    env::var("USERPROFILE").unwrap_or_else(|_| env::var("HOME").unwrap_or_default())
}

/// Force a rebuild of the local docs index on the next `search_docs` call.
/// Used by docs_fetcher after writing new doc sets so the scanner sees them
/// immediately instead of waiting up to `DOCS_TTL_MS` (30s).
pub fn invalidate_docs_cache() {
    {
        let mut guard = DOCS_CACHE.lock();
        *guard = None;
    }
}

/// Extract lookup terms from content — API claims (`ClassName.method(`)
/// and import paths (`from 'pkg'` / `import 'pkg'` / `require('pkg')`).
///
/// Pure function: no I/O, no locks. Shared by remote and local doc paths
/// so they agree on what to look up. Returns lowercased terms.
pub fn extract_lookup_terms(content: &str) -> HashSet<String> {
    let mut terms = HashSet::new();

    // API claims: ClassName from ClassName.method(
    let class_re = regex::Regex::new(r"\b([A-Z][a-zA-Z_]+)\.[a-zA-Z_]").unwrap();
    for caps in class_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            terms.insert(m.as_str().to_lowercase());
        }
    }

    // Import patterns: from 'pkg'
    let import_re =
        regex::Regex::new(r#"(?:from\s+|import\s+|require\s*\(\s*)['"]([^'"./]+)"#).unwrap();
    for caps in import_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            terms.insert(m.as_str().to_lowercase());
        }
    }

    // Rust use patterns: use crate_name::module
    let rust_use_re = regex::Regex::new(r"\buse\s+([a-z_][a-z0-9_-]*)::").unwrap();
    for caps in rust_use_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            terms.insert(m.as_str().to_lowercase());
        }
    }

    // Rust extern crate: extern crate crate_name;
    let extern_re = regex::Regex::new(r"\bextern\s+crate\s+([a-z_][a-z0-9_-]*)").unwrap();
    for caps in extern_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            terms.insert(m.as_str().to_lowercase());
        }
    }

    // Python `from X.Y import Z` — capture full dotted path AND top-level package.
    let py_from_re = regex::Regex::new(r"\bfrom\s+([a-zA-Z_][\w.]*)\s+import\b").unwrap();
    for caps in py_from_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            terms.insert(path.to_lowercase());
            if let Some(top) = path.split('.').next() {
                terms.insert(top.to_lowercase());
            }
        }
    }

    // C# using patterns: using MediatR; using Microsoft.Extensions.DependencyInjection;
    let csharp_using_re = regex::Regex::new(r"\busing\s+([A-Za-z][\w.]*)\s*;").unwrap();
    for caps in csharp_using_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let ns = m.as_str().to_lowercase();
            terms.insert(ns.clone());
            // Also insert first segment for simple package names (mediatr, serilog, polly)
            if let Some(top) = ns.split('.').next() {
                terms.insert(top.to_string());
            }
        }
    }

    // Python `import X.Y` (no quotes — character class excludes the JS `import 'X'` form).
    let py_import_re = regex::Regex::new(r"\bimport\s+([a-zA-Z_][\w.]*)").unwrap();
    for caps in py_import_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            terms.insert(path.to_lowercase());
            if let Some(top) = path.split('.').next() {
                terms.insert(top.to_lowercase());
            }
        }
    }

    // Go import block: `import (\n "fmt"\n "io"\n)`
    let go_block_re = regex::Regex::new(r#"(?s)\bimport\s*\(\s*([^)]+?)\s*\)"#).unwrap();
    let go_line_re = regex::Regex::new(r#""([^"]+)""#).unwrap();
    for caps in go_block_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            for line_cap in go_line_re.captures_iter(m.as_str()) {
                if let Some(lm) = line_cap.get(1) {
                    let path = lm.as_str();
                    terms.insert(path.to_lowercase());
                    // For "github.com/X/Y" or "google.golang.org/X/Y", also take last segment
                    if let Some(top) = path.rsplit('/').next() {
                        terms.insert(top.to_lowercase());
                    }
                }
            }
        }
    }

    // Go single import: `import "X"`
    let go_single_re = regex::Regex::new(r#"\bimport\s+"([^"]+)""#).unwrap();
    for caps in go_single_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            terms.insert(path.to_lowercase());
            if let Some(top) = path.rsplit('/').next() {
                terms.insert(top.to_lowercase());
            }
        }
    }

    // Java `import X.Y.Z;` (also `import static X.Y.Z;`) — capture top 2 segments.
    let java_re = regex::Regex::new(r"\bimport\s+(?:static\s+)?([\w.]+)\s*;").unwrap();
    for caps in java_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            let top: String = path.split('.').take(2).collect::<Vec<_>>().join(".");
            terms.insert(top.to_lowercase());
            terms.insert(path.to_lowercase());
        }
    }

    // C# `using X.Y.Z;` — capture top 2 segments.
    let csharp_re = regex::Regex::new(r"\busing\s+(?:static\s+)?([\w.]+)\s*;").unwrap();
    for caps in csharp_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            let top: String = path.split('.').take(2).collect::<Vec<_>>().join(".");
            terms.insert(top.to_lowercase());
            terms.insert(path.to_lowercase());
        }
    }

    // C++ `#include <X>` or `#include "X"` — capture dir/file name.
    let cpp_re = regex::Regex::new(r#"#include\s+[<"]([^>"]+)[>"]"#).unwrap();
    for caps in cpp_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let path = m.as_str();
            // boost/asio.hpp -> boost; armadillo -> armadillo
            let top = path.split('/').next().unwrap_or(path);
            let stem = top.split('.').next().unwrap_or(top);
            terms.insert(stem.to_lowercase());
        }
    }

    terms
}

/// Cap a joined docs result at `MAX_DOCS_RESULT` bytes. Used by both the
/// remote and local paths so they observe the same size bound.
fn truncate_docs_result(s: &str) -> String {
    if s.len() > MAX_DOCS_RESULT {
        s.get(..MAX_DOCS_RESULT).unwrap_or(s).to_string()
    } else {
        s.to_string()
    }
}

/// Local-only docs lookup against `~/.anubis/docs/`.
///
/// Behavior preserved exactly from the original `search_docs`. The async
/// `search_docs` below calls this as its local fallback.
fn search_docs_local(content: &str) -> String {
    let now = current_time_ms();
    let docs_dir = format!("{}/.anubis/docs", home_dir());

    // Build/update docs index
    {
        let mut guard = DOCS_CACHE.lock();
        let needs_rebuild = match &*guard {
            None => true,
            Some((built, _)) => now - built > DOCS_TTL_MS,
        };
        if needs_rebuild {
            let mut index: HashMap<String, String> = HashMap::new();
            build_docs_index(Path::new(&docs_dir), &mut index);
            *guard = Some((now, index));
        }
    }

    let guard = DOCS_CACHE.lock();
    let index = match &*guard {
        Some((_, idx)) => idx,
        None => return String::new(),
    };

    if index.is_empty() {
        return String::new();
    }

    let terms = extract_lookup_terms(content);
    if terms.is_empty() {
        return String::new();
    }

    // Match terms against docs filenames
    let mut results = Vec::new();
    for (filename, file_content) in index.iter() {
        let fname_lower = filename.to_lowercase();
        for term in &terms {
            if fname_lower.contains(term) {
                // Extract relevant section from file content
                let snippet = extract_docs_section(file_content, term);
                if !snippet.is_empty() {
                    results.push(format!("### {}\n{}", filename, snippet));
                }
                break;
            }
        }
    }

    if results.is_empty() {
        return String::new();
    }

    let joined = results.join("\n\n---\n\n");
    truncate_docs_result(&joined)
}

/// Look up docs for the content's terms: remote-first, local-fallback.
///
/// 1. Extract lookup terms (API claims + imports).
/// 2. For each term (sequential, capped at 5 successful hits) call the
///    anubis-docs Worker via `remote_docs::fetch_remote_docs`. Any error
///    — network, non-200, empty body — returns `None` and the loop simply
///    moves on; if no term yields a hit, we fall through.
/// 3. On any remote miss, fall back to `search_docs_local`.
///
/// No `DOCS_CACHE` `MutexGuard` is held across `.await` — the local index
/// lock is confined to `search_docs_local`.
async fn search_docs(content: &str) -> String {
    let terms = extract_lookup_terms(content);
    if terms.is_empty() {
        return String::new();
    }

    // 1. Try remote docs (per-term, sequential to avoid hammering Worker).
    let mut remote_hits: Vec<String> = Vec::new();
    for term in &terms {
        if let Some(md) = crate::remote_docs::fetch_remote_docs(term, "latest").await {
            let snippet = extract_docs_section(&md, term);
            if !snippet.is_empty() {
                remote_hits.push(format!("### {} (remote)\n{}", term, snippet));
            }
        }
        // Cap at 5 remote lookups per scan to bound latency.
        if remote_hits.len() >= 5 {
            break;
        }
    }

    if !remote_hits.is_empty() {
        let joined = remote_hits.join("\n\n---\n\n");
        return truncate_docs_result(&joined);
    }

    // 2. Fallback to local index on remote miss.
    search_docs_local(content)
}

/// Library-driven docs fallback for the L3 path.
///
/// [`search_docs`] returns empty when [`extract_lookup_terms`] finds no
/// lookup terms (no `ClassName.method(` patterns or imports in content)
/// AND the docs Worker has no markdown for any term it does find. For
/// prose claims (lifecycle / behavioral / performance statements) this
/// leaves L3 with `## REFERENCE DOCUMENTATION: NONE AVAILABLE`, which
/// biases the judge toward "uncertain" verdicts (confidence ~0.44).
///
/// This fallback repairs that by:
/// 1. [`injection::detect_libraries`] — extracts library mentions from
///    import statements across all supported languages.
/// 2. For each detected library, pulls symbols from the local
///    [`SymbolCache`] via [`injection::build_doc_snippets`] — fast,
///    no network, already-populated by `docs add` and auto-fetch.
/// 3. For libraries not in the cache, falls back to
///    [`remote_docs::fetch_remote_docs`] (capped at 3 remote calls to
///    bound latency; each call has a 24h disk-cache fast path).
///
/// Returns a combined markdown string capped at [`MAX_DOCS_RESULT`].
/// Empty when no libraries are detected or all sources miss.
async fn build_library_docs_fallback(content: &str) -> String {
    // A/B kill switch: when ANUBIS_L3_DOCS_IN_PROMPT=0 or =false
    // (case-insensitive), skip all doc retrieval — both the snippet
    // returned here and the downstream `docs_assisted` flag. Used by
    // doc_injection_bench to measure the effect of doc injection into
    // the L3 verification prompt. Default (unset or any other value)
    // preserves normal behavior.
    if std::env::var("ANUBIS_L3_DOCS_IN_PROMPT")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        return String::new();
    }

    let libs = crate::injection::detect_libraries(content);
    if libs.is_empty() {
        return String::new();
    }

    // 1. Symbol cache (local SQLite — fast, no network).
    //    Tracks which libraries got cached snippets so we skip them in
    //    the remote fallback below.
    let (cached_text, cached_libs) = match crate::symbols::cache::SymbolCache::open() {
        Ok(cache) => build_library_docs_from_cache(&libs, &cache),
        Err(_) => (String::new(), HashSet::new()),
    };

    // 2. Remote docs Worker for libraries not covered by the cache.
    //    Cap at 3 remote calls per scan to bound latency (each call has a
    //    24h disk-cache fast path so repeat scans for the same library
    //    are instant).
    let mut remote_hits: Vec<String> = Vec::new();
    let mut remote_count = 0usize;
    for lib in &libs {
        if cached_libs.contains(&lib.name) {
            continue;
        }
        if remote_count >= 3 {
            break;
        }
        if let Some(md) = crate::remote_docs::fetch_remote_docs(&lib.name, "latest").await {
            let snippet = extract_docs_section(&md, &lib.name);
            if snippet.is_empty() {
                continue;
            }
            remote_hits.push(format!("### {} (remote)\n{}", lib.name, snippet));
            remote_count += 1;
        }
    }

    if cached_text.is_empty() && remote_hits.is_empty() {
        return String::new();
    }

    let mut out = cached_text;
    for hit in &remote_hits {
        if !out.is_empty() {
            out.push_str("\n\n---\n\n");
        }
        out.push_str(hit);
    }
    if !out.is_empty() {
        tracing::info!(
            target: "scanner::docs",
            chars = out.len(),
            libs = libs.len(),
            "docs injected into L3 prompt"
        );
    }
    truncate_docs_result(&out)
}

/// Build doc snippets from the symbol cache for the given libraries.
///
/// Returns `(combined_markdown, set_of_library_names_covered)`. The
/// second element lets the caller skip those libraries when falling
/// back to remote docs. Extracted from [`build_library_docs_fallback`]
/// so tests can drive it with an in-memory cache.
fn build_library_docs_from_cache(
    libs: &[crate::injection::DetectedLibrary],
    cache: &crate::symbols::cache::SymbolCache,
) -> (String, HashSet<String>) {
    // 2000 token budget, 20 symbols per library — keeps prompt focused.
    let snippets = crate::injection::build_doc_snippets(libs, cache, 2000, 20);
    let mut out = String::new();
    let mut covered: HashSet<String> = HashSet::new();
    for snip in &snippets {
        if !out.is_empty() {
            out.push_str("\n\n---\n\n");
        }
        out.push_str(&snip.text);
        covered.insert(snip.library.clone());
    }
    (out, covered)
}


fn build_docs_index(dir: &Path, index: &mut HashMap<String, String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip hidden directories (e.g. `.remote-cache`) so cache contents
            // do not pollute the local docs index.
            let is_hidden = entry
                .file_name()
                .to_str()
                .map(|s| s.starts_with('.'))
                .unwrap_or(false);
            if is_hidden {
                continue;
            }
            build_docs_index(&path, index);
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".md") || name.ends_with(".txt") {
            if let Ok(content) = fs::read_to_string(&path) {
                // Cap file content to 10KB to avoid memory bloat
                let capped = if content.len() > 10_000 {
                    content.get(..10_000).unwrap_or(&content).to_string()
                } else {
                    content.to_string()
                };
                index.insert(name, capped);
            }
        }
    }
}

fn extract_docs_section(content: &str, term: &str) -> String {
    // Find a heading matching the term and extract the section
    let heading_re =
        regex::Regex::new(&format!(r"(?im)^#{{1,6}}\s*{}[\s_]", regex::escape(term))).unwrap();
    if let Some(m) = heading_re.find(content) {
        let start = m.start();
        // Find next heading of same or higher level
        let rest = safe_slice_from(content, start);
        let level = rest.chars().take_while(|c| *c == '#').count();
        let next_re = regex::Regex::new(&format!(r"\n#{{1,{}}}\s", level)).unwrap();
        let end = next_re
            .find(rest)
            .map(|m| m.start())
            .unwrap_or(rest.len().min(2000));
        return rest[..end.min(2000)].to_string();
    }
    // Fallback: return first 500 chars
    content.chars().take(500).collect()
}

// ---------------------------------------------------------------------------
// Package API — read node_modules .d.ts for packages mentioned in content

fn extract_imports(content: &str) -> Vec<String> {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();

    // ES imports: from 'pkg' or from '@scope/pkg'
    let re = regex::Regex::new(r#"(?:from\s+|import\s+)['"]([^'"]+)['"]"#).unwrap();
    for caps in re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let pkg = m.as_str();
            // Skip relative imports
            if pkg.starts_with('.') || pkg.starts_with('/') {
                continue;
            }
            // Normalize: @scope/pkg/sub → @scope/pkg (keep scope)
            let normalized = if pkg.starts_with('@') {
                pkg.split('/').take(2).collect::<Vec<_>>().join("/")
            } else {
                pkg.split('/').next().unwrap_or(pkg).to_string()
            };
            if seen.insert(normalized.clone()) {
                packages.push(normalized);
            }
        }
    }

    // require('pkg')
    let req_re = regex::Regex::new(r#"require\s*\(\s*['"]([^'"]+)['"]"#).unwrap();
    for caps in req_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let pkg = m.as_str();
            if pkg.starts_with('.') || pkg.starts_with('/') {
                continue;
            }
            let normalized = if pkg.starts_with('@') {
                pkg.split('/').take(2).collect::<Vec<_>>().join("/")
            } else {
                pkg.split('/').next().unwrap_or(pkg).to_string()
            };
            if seen.insert(normalized.clone()) {
                packages.push(normalized);
            }
        }
    }

    packages
}

fn build_package_api(content: &str, project_root: &str) -> String {
    let packages = extract_imports(content);
    if packages.is_empty() {
        // Phase 2: try manifest deps as fallback
        return build_package_api_from_manifests(content, project_root);
    }

    let mut result = Vec::new();
    for pkg in packages.iter().take(5) {
        if let Some(dts) = read_package_dts(pkg, project_root) {
            let methods = extract_method_calls(content, pkg);
            let filtered = filter_dts_exports(&dts, &methods);
            if !filtered.is_empty() {
                result.push(format!("--- {} ---\n{}", pkg, filtered));
            }
        }
    }

    result.join("\n\n")
}

fn build_package_api_from_manifests(content: &str, project_root: &str) -> String {
    // Phase 3: check all manifest deps against content
    let manifests = read_project_manifests(project_root);
    if manifests.is_empty() {
        return String::new();
    }

    let content_lower = content.to_lowercase();
    let mut result = Vec::new();

    // Extract package names from manifest text
    let pkg_re = regex::Regex::new(r"^\s+(.+)$").unwrap();
    let mut deps_checked = 0;
    for line in manifests.lines() {
        if let Some(caps) = pkg_re.captures(line) {
            if deps_checked >= 15 {
                break;
            }
            let pkg = caps.get(1).unwrap().as_str().trim();
            // Skip if package name not mentioned in content
            let pkg_short = pkg.split('/').last().unwrap_or(pkg);
            if !content_lower.contains(&pkg.to_lowercase())
                && !content_lower.contains(&pkg_short.to_lowercase())
            {
                continue;
            }
            deps_checked += 1;
            if let Some(dts) = read_package_dts(pkg, project_root) {
                let filtered = filter_dts_exports(&dts, &[]);
                if !filtered.is_empty() {
                    result.push(format!("--- {} ---\n{}", pkg, filtered));
                }
            }
        }
    }

    result.join("\n\n")
}

fn extract_method_calls(content: &str, pkg: &str) -> Vec<String> {
    let mut methods = Vec::new();
    let mut seen = HashSet::new();

    // Find pkg.method( or pkg_alias.method(
    let pkg_short = pkg.split('/').last().unwrap_or(pkg);
    let aliases = [pkg, pkg_short];

    for alias in &aliases {
        let re = regex::Regex::new(&format!(
            r"\b{}\.([a-zA-Z_][a-zA-Z0-9_]*)",
            regex::escape(alias)
        ))
        .unwrap();
        for caps in re.captures_iter(content) {
            if let Some(m) = caps.get(1) {
                let method = m.as_str().to_string();
                if seen.insert(method.clone()) {
                    methods.push(method);
                }
            }
        }
    }

    methods
}

fn read_package_dts(pkg: &str, project_root: &str) -> Option<String> {
    // Try multiple node_modules locations (monorepo hoist)
    let locations = [
        format!("{}/node_modules/{}", project_root, pkg),
        format!(
            "{}/node_modules/@{}/node_modules/{}",
            project_root,
            pkg.split('/').next().unwrap_or("").trim_start_matches('@'),
            pkg
        ),
    ];

    for loc in &locations {
        let pkg_path = Path::new(loc);
        if !pkg_path.exists() {
            continue;
        }

        // Try common .d.ts file patterns
        let dts_candidates = [
            format!("{}/dist/index.d.ts", loc),
            format!("{}/index.d.ts", loc),
            format!("{}/types/index.d.ts", loc),
            format!("{}/build/index.d.ts", loc),
        ];

        for dts_path in &dts_candidates {
            if let Ok(content) = fs::read_to_string(dts_path) {
                return Some(content);
            }
        }

        // Try reading package.json for "types" field
        if let Ok(pkg_json) = fs::read_to_string(format!("{}/package.json", loc)) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&pkg_json) {
                if let Some(types) = v.get("types").and_then(|t| t.as_str()) {
                    let dts_path = format!("{}/{}", loc, types);
                    if let Ok(content) = fs::read_to_string(&dts_path) {
                        return Some(content);
                    }
                }
                if let Some(types) = v.get("typings").and_then(|t| t.as_str()) {
                    let dts_path = format!("{}/{}", loc, types);
                    if let Ok(content) = fs::read_to_string(&dts_path) {
                        return Some(content);
                    }
                }
            }
        }
    }

    None
}

fn filter_dts_exports(dts: &str, methods: &[String]) -> String {
    let _export_re = regex::Regex::new(
        r"(?:export\s+)?(?:declare\s+)?(?:function|class|interface|type|const|enum|abstract\s+class)\s+([A-Za-z_][A-Za-z0-9_]*)"
    ).unwrap();

    let mut lines = Vec::new();
    let mut chars = 0;

    for line in dts.lines() {
        let is_export = line.contains("export ") || line.contains("declare ");
        let is_relevant = if methods.is_empty() {
            is_export
        } else {
            // Check if any method name appears in this line
            is_export || methods.iter().any(|m| line.contains(m))
        };

        if is_relevant {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let entry_str: String = trimmed.chars().take(120).collect();
                if chars + entry_str.len() > 1500 {
                    break;
                }
                chars += entry_str.len() + 1;
                lines.push(entry_str);
            }
        }
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------

/// Fast scan — L0+L1+L1.5 only, NO LLM call. Returns in <100ms.
/// Used for synchronous intervention (warning footer) before response
/// returns to the agent. L3 (validator LLM) runs separately in background.
///
/// Streaming role: this is the midstream scan in the checkstream-style
/// ingress/midstream/egress split. The streaming proxy calls it inside
/// the per-chunk stream transformer (triggered when content crosses 500
/// chars or usage arrives) so a warning delta can be injected before the
/// stream terminator. The full cascade (L1+L1.5+L2+L3) runs in the
/// egress task via scan_response.
///
/// Reuses scan_response with empty llm_api_key (existing gate at line ~2018
/// skips L3 when key is empty). Result has deterministic warnings only —
/// probabilistic L3 issues arrive later via scan_deep_async.
pub async fn scan_fast(content: &str, ctx: &ScanContext) -> ScanResultData {
    let mut fast_ctx = ScanContext {
        llm_api_key: String::new(), // empty → skips L3
        ..(*ctx).clone()
    };
    fast_ctx.llm_extra_headers = ctx.llm_extra_headers.clone();
    let result = scan_response(content, &fast_ctx).await;
    tracing::warn!(
        target: "scanner",
        content_len = content.len(),
        warnings = result.warnings.len(),
        risk_score = format!("{:.3}", result.risk_score),
        confidence = format!("{:.3}", result.confidence),
        clean = result.clean,
        first_warning = result.warnings.first().cloned().unwrap_or_default(),
        "DIAG scan_fast result"
    );
    result
}

/// Deep scan — full pipeline including L3 validator LLM call. Runs in
/// background (tokio::spawn). Results go to audit + dashboard + Prometheus.
/// Never blocks the agent response.
///
/// Caller should NOT await this — it's fire-and-forget.
pub fn scan_deep_async(content: String, ctx: ScanContext) {
    let content = content;
    let ctx = ctx;
    tokio::spawn(async move {
        let started = Instant::now();
        let result = scan_response(&content, &ctx).await;
        tracing::info!(
            target: "scanner",
            phase = "deep",
            duration_ms = started.elapsed().as_millis(),
            warnings = result.warnings.len(),
            risk_score = format!("{:.3}", result.risk_score),
            clean = result.clean,
            "scan_deep_async completed (background)"
        );
        // Deep scan results are consumed by the caller's background task
        // which updates stats + audit. This fn just runs the scan.
        // The caller wraps it with stats/audit logic.
        drop(result); // explicitly drop — caller's spawn handles stats
    });
}
// ── scan_response stage helpers (extracted from the main pipeline) ──────

/// L1 fuzzy-match hallucination check. For each API claim absent from the
/// project index, if a close edit-distance match exists, emit a Hallucinated
/// API warning. Silent on no-match — might be a real external API the index
/// doesn't know (L3 handles those).
fn evaluate_l1_claims(
    claims: &[String],
    local_vars: &std::collections::HashSet<String>,
    project_index: &str,
    result: &mut ScanResultData,
) {
    let has_project_context = !project_index.trim().is_empty();
    for claim in claims.iter() {
        let obj_name = claim.split('.').next().unwrap_or("");
        if local_vars.contains(obj_name) {
            continue;
        }
        // Cache has no introspected class/method surface for this name:
        // every entry is a Constant / Property / Module recorded from the
        // user's source (e.g., `const UserSchema = z.object({...})`).
        // Fuzzy "did you mean" is unsound — we never recorded any methods
        // to compare against. Suppress and let TS2339 / scope check / L3
        // catch real hallucinations.
        if crate::symbols::cache::SymbolCache::open().map_or(false, |c| {
            use crate::symbols::types::SymbolKind;
            let entries = c.lookup_global(obj_name);
            !entries.is_empty()
                && !entries.iter().any(|s| matches!(s.kind,
                    SymbolKind::Class
                    | SymbolKind::Method
                    | SymbolKind::Function
                    | SymbolKind::Constructor
                    | SymbolKind::Interface))
        }) {
            continue;
        }
        if has_project_context && !check_claim_in_index(claim, project_index) {
            if let Some(suggestion) = find_close_match_in_index(claim, project_index) {
                let clean_name = format!("{}()", claim.trim_end_matches('('));
                result
                    .warnings
                    .push(format!("Hallucinated API: {clean_name} (did you mean {suggestion}?)"));
                result
                    .details
                    .push(format!("api-claim: {claim} close to indexed {suggestion}"));
            }
        }
    }
}

/// Background-fetch symbols for libraries detected in the content but not yet
/// in the SQLite cache, plus proactive dependency fetching from manifest files.
/// Fire-and-forget: both spawns are detached (cancellable via ctx.cancel) so
/// the scan never blocks on network. First scan misses; next scan hits.
fn spawn_background_fetches(scan_content: &str, ctx: &ScanContext) {
    let terms = extract_lookup_terms(scan_content);
    let terms_for_fetch = terms.clone();
    let cancel = ctx.cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = crate::symbols::auto_fetch_missing(&terms_for_fetch) => {}
            _ = cancel.cancelled() => {}
        }
    });

    if !ctx.project_root.is_empty() {
        let proj_root = ctx.project_root.clone();
        let cancel = ctx.cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = crate::symbols::fetch_project_dependencies(&proj_root) => {},
                _ = cancel.cancelled() => {
                    tracing::debug!(
                        target: "scanner",
                        "fetch_project_dependencies cancelled by parent scan"
                    );
                }
            }
        });
    }
}

/// Post-warning-batch cleanup: recompute derived fields, filter L3 warnings
/// against the symbol cache (deterministic ground truth suppresses probabilistic
/// L3 "doesn't exist" claims contradicted by the cache), then recompute again.
fn finalize_and_filter_warnings(result: &mut ScanResultData) {
    result.recompute();
    let pre_filter_count = result.warnings.len();
    result.warnings = post_filter_l3_against_cache(&result.warnings);
    let suppressed = pre_filter_count - result.warnings.len();
    if suppressed > 0 {
        result.details.push(format!(
            "l3-post-filter: suppressed {} warning(s) contradicted by symbol cache",
            suppressed
        ));
    }
    result.recompute();
}

/// Behavioral correctness check (L2.5). Independent of the cascade — runs
/// whenever L3 is enabled AND behavioral signals are detected. Single LLM call
/// on the full code block (not per-claim). Catches semantic bugs that pass
/// L1.5/FORGE: async scope, missing base case, lifetime panics, off-by-one.
async fn run_behavioral_check(
    scan_content: &str,
    detected_language: &str,
    ctx: &ScanContext,
) -> Option<(Vec<String>, String)> {
    if ctx.llm_api_key.is_empty() {
        return None;
    }
    let behavioral_signals =
        crate::scanner::l3_per_claim::detect_behavioral_signals(scan_content, detected_language);
    if behavioral_signals.is_empty() {
        return None;
    }
    let behavioral_warnings =
        crate::scanner::l3_per_claim::verify_behavioral_correctness(
            scan_content,
            &behavioral_signals,
            ctx,
        )
        .await;
    let signal_summary = behavioral_signals
        .iter()
        .map(|s| s.kind.as_str())
        .collect::<Vec<_>>()
        .join(",");
    Some((behavioral_warnings, signal_summary))
}

/// L1.5 warning emission: cached-hallucination + scope-hallucination loops.
/// Takes the pre-computed symbol_check and session_defined (both reused
/// downstream by FORGE filter + cascade) as references — does not consume
/// them. Runs check_instance_calls internally (scope_check is local to this
/// stage). Pushes deterministic warnings to result.
fn emit_l1_5_warnings(
    symbol_check: &crate::symbols::SymbolCheckResult,
    scope_check: &crate::scanner::scope_analysis::InstanceCheckResult,
    session_defined: &std::collections::HashSet<&str>,
    content: &str,
    result: &mut ScanResultData,
) {
    use crate::scanner::forge_pipeline::prefix;
    // Cached-hallucination: symbol_check found method calls absent from cache.
    if symbol_check.has_deterministic_hallucination() {
        for line in symbol_check.markdown.lines() {
            if let Some(stripped) = line.trim_start().strip_prefix("- ") {
                if stripped.contains("— class ") {
                    let is_session_class = stripped
                        .split("— class ")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .map_or(false, |cls| {
                            if !session_defined.contains(cls) {
                                return false;
                            }
                            let cache = crate::symbols::cache::SymbolCache::open().ok();
                            cache.map_or(true, |c| c.lookup_global(cls).is_empty())
                        });
                    if is_session_class {
                        continue;
                    }
                    // Local-only class suppression: when every cache entry
                    // for the class is a non-introspected kind (Constant /
                    // Property / Module / etc.), the scanner recorded the
                    // NAME from the user's code but never saw the API
                    // surface. cached-hallucination is unsound in that case
                    // — every method call would fire because no methods are
                    // cached. Suppress and rely on the language's real
                    // method check (TS2339 / AST scope / docs.rs / L3).
                    //
                    // Targets the Zod-schema FP pattern: `const UserSchema =
                    // z.object({...})` registers UserSchema as a Constant;
                    // Zod's prototype methods (.parse / .partial /
                    // .safeParse) are never recorded by the local scanner.
                    let has_real_class_surface = stripped
                        .split("— class ")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                        .map_or(false, |cls| {
                            use crate::symbols::types::SymbolKind;
                            let cache = crate::symbols::cache::SymbolCache::open().ok();
                            let entries = cache
                                .as_ref()
                                .map(|c| c.lookup_global(cls))
                                .unwrap_or_default();
                            entries.iter().any(|s| matches!(s.kind,
                                SymbolKind::Class
                                | SymbolKind::Method
                                | SymbolKind::Function
                                | SymbolKind::Constructor
                                | SymbolKind::Interface))
                        });
                    if !has_real_class_surface {
                        continue;
                    }
                    if stripped.contains(".new()") || stripped.contains(".new (") {
                        continue;
                    }
                    // Same-response definition guard: when the scanned
                    // response itself DEFINES the claimed method
                    // (`def/fn/function/func <name>(...)` at statement
                    // start, any language shape), the call cannot be
                    // hallucinated — the cache simply hasn't ingested the
                    // new definition yet (and may have resolved the class
                    // from a stale namespace). Structural, language-generic,
                    // no symbol list (Rule 8).
                    if let Some(method) = stripped
                        .split('(')
                        .next()
                        .unwrap_or("")
                        .rsplit('.')
                        .next()
                        .map(str::trim)
                        .filter(|m| !m.is_empty())
                    {
                        let def_pat = format!(
                            r"(?m)^[ \t]*(?:def|fn|function|func|sub)\s+{}\s*\(",
                            regex::escape(method)
                        );
                        if regex::Regex::new(&def_pat)
                            .map(|re| re.is_match(content))
                            .unwrap_or(false)
                        {
                            continue;
                        }
                    }
                    result
                        .warnings
                        .push(format!("{} {}", prefix::CACHED_HALLUCINATION, stripped));
                }
            }
        }
    }

    // Scope-hallucination: scope_check verifies var.method() patterns.
    for w in &scope_check.warnings {
        if let Some(type_name) = w
            .split(" for type ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
        {
            if session_defined.contains(type_name) {
                let cache = crate::symbols::cache::SymbolCache::open().ok();
                let in_bundle = cache.map_or(false, |c| !c.lookup_global(type_name).is_empty());
                if !in_bundle {
                    continue;
                }
            }
        }
        result
            .warnings
            .push(format!("{} {}", prefix::SCOPE_HALLUCINATION, w));
    }
}

/// Merge language-agnostic supplementary warnings into forge_result: go.sum
/// hash fabrication, Cargo.lock checksum, package-lock.json integrity, and
/// compiler-based verification (clangd/rustc/go vet/dotnet/pyright). All
/// additive to FORGE — merged in-place, dedup via token matching upstream.
async fn merge_supplementary_forge_warnings(
    forge_result: &mut crate::scanner::forge_pipeline::ForgeResult,
    content: &str,
    detected_language: &str,
    code_content: &str,
) {
    let gosum = crate::scanner::forge_go::detect_gosum_hash_fabrication(content);
    if !gosum.is_empty() {
        forge_result.claims_extracted += gosum.len();
        forge_result.claims_hallucinated += gosum.len();
        forge_result.warnings.extend(gosum);
    }
    let cargo = crate::scanner::forge_rust::detect_cargo_lock_checksum_fabrication(content);
    if !cargo.is_empty() {
        forge_result.claims_extracted += cargo.len();
        forge_result.claims_hallucinated += cargo.len();
        forge_result.warnings.extend(cargo);
    }
    let pkg = crate::scanner::forge_ts::detect_pkg_lock_integrity_fabrication(content);
    if !pkg.is_empty() {
        forge_result.claims_extracted += pkg.len();
        forge_result.claims_hallucinated += pkg.len();
        forge_result.warnings.extend(pkg);
    }
    let forge_tokens = crate::scanner::compiler_verifier::extract_forge_tokens(&forge_result.warnings);
    let compiler = crate::scanner::compiler_verifier::verify_with_compiler(
        detected_language,
        code_content,
        &forge_tokens,
    )
    .await;
    if !compiler.is_empty() {
        forge_result.claims_extracted += compiler.len();
        forge_result.claims_hallucinated += compiler.len();
        forge_result.warnings.extend(compiler);
    }
}

/// Push FORGE warnings to result with the universal cross-response FP filter:
/// any warning whose backtick-quoted token matches a session-defined symbol
/// (and isn't in the symbol bundle) is suppressed. Chain-broken/chain-phantom
/// warnings pass through (receiver unresolvable — session filter doesn't help).
fn emit_forge_warnings(
    forge_result: &crate::scanner::forge_pipeline::ForgeResult,
    session_defined: &std::collections::HashSet<&str>,
    result: &mut ScanResultData,
) {
    use crate::scanner::forge_pipeline::prefix;
    if forge_result.warnings.is_empty() {
        return;
    }
    let cache_for_filter = crate::symbols::cache::SymbolCache::open().ok();
    for w in &forge_result.warnings {
        let stripped = w.strip_prefix(prefix::FORGE).unwrap_or(w);
        if stripped.starts_with("chain-broken:") || stripped.starts_with("chain-phantom-member:") {
            result.warnings.push(format!("{}{}", prefix::FORGE, w));
            continue;
        }
        if let Some(full) = w.split('`').nth(1) {
            if session_defined.contains(full) {
                continue;
            }
            let name = full.split('.').next().unwrap_or("").split("::").next().unwrap_or("");
            if !name.is_empty() && session_defined.contains(name) {
                let in_bundle = cache_for_filter
                    .as_ref()
                    .map_or(false, |c| !c.lookup_global(name).is_empty());
                if !in_bundle {
                    continue;
                }
            }
        }
        result.warnings.push(format!("{}{}", prefix::FORGE, w));
    }
    result.docs_assisted = true;
    result.recompute();
}

/// L3 skip threshold. Claims resolved at or above this confidence by
/// deterministic layers (L1.5 symbol cache, FORGE pipeline) are trusted
/// without LLM validation.
const L3_SKIP_CONFIDENCE_THRESHOLD: f64 = 0.85;

/// L2.5 cascade decision: skip the LLM validator (L3) when deterministic
/// layers (L1.5 + FORGE) fully resolved every claim with high confidence.
///
/// Forces L3 on: any L1 unverified warnings, low combined confidence,
/// unresolved FORGE claims, uncertain introspection advisories (chain-*,
/// not-in-module), no deterministic signal at all (vacuous-confidence guard),
/// or presence of reasoning claims (lifecycle/behavioral/performance/idiom
/// statements that deterministic layers cannot verify — see
/// `l3_per_claim::extract_prose_claims`).
fn compute_cascade_decision(
    l1_had_warnings: bool,
    combined_confidence: f64,
    forge_result: &crate::scanner::forge_pipeline::ForgeResult,
    symbol_check: &crate::symbols::SymbolCheckResult,
    has_prose: bool,
) -> bool {
    let has_introspection_warning = forge_result.warnings.iter().any(|w| {
        w.contains("not in module")
            || w.contains("not a method")
            || w.contains("not in known methods")
            || w.starts_with("chain-phantom")
            || w.starts_with("chain-broken")
    });
    let no_deterministic_signal = symbol_check.method_calls_count == 0
        && forge_result.claims_extracted == 0;
    !l1_had_warnings
        && combined_confidence >= L3_SKIP_CONFIDENCE_THRESHOLD
        && forge_result.claims_unknown == 0
        && !has_introspection_warning
        && !no_deterministic_signal
        && !has_prose
}

/// Classify API claims for L3 per-claim verification. Filters out claims
/// already resolved by deterministic layers (cascade skip), calls on
/// user-defined variables/declarations, and claims with high-confidence
/// deterministic verdicts (>= L3_SKIP_CONFIDENCE_THRESHOLD).
fn classify_claims_for_l3(
    api_claims_raw: Vec<String>,
    symbol_check: &crate::symbols::SymbolCheckResult,
    forge_result: &crate::scanner::forge_pipeline::ForgeResult,
    project_index: &str,
    scope_check: &crate::scanner::scope_analysis::InstanceCheckResult,
) -> Vec<String> {
    let mut user_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (var, _ty) in &scope_check.scope_vars {
        user_names.insert(var.clone());
    }
    for line in project_index.lines() {
        if let Some(colon_pos) = line.find(": ") {
            let after = safe_slice_from(&line, colon_pos + 2);
            if let Some(name) = after.split_whitespace().next() {
                if name.len() >= 2
                    && name.chars().next().map_or(false, |c| c.is_alphabetic() || c == '_')
                {
                    user_names.insert(name.to_string());
                }
            }
        }
    }

    api_claims_raw
        .into_iter()
        .filter(|claim| {
            let normalized = claim.trim_end_matches('(').trim_end();
            if symbol_check.verified_claims.contains(normalized) {
                return false;
            }
            if let Some(conf) = symbol_check.claim_confidence.get(normalized) {
                if *conf >= L3_SKIP_CONFIDENCE_THRESHOLD {
                    return false;
                }
            }
            if let Some(conf) = forge_result.claim_confidence.get(normalized) {
                if *conf >= L3_SKIP_CONFIDENCE_THRESHOLD {
                    return false;
                }
            }
            if let Some(dot_pos) = claim.find('.') {
                let receiver = claim[..dot_pos].trim();
                if !receiver.is_empty()
                    && !receiver.contains('.')
                    && !receiver.contains(')')
                    && user_names.contains(receiver)
                {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Build a markdown table of variable->type bindings for the L3 prompt.
fn build_scope_summary(
    scope_check: &crate::scanner::scope_analysis::InstanceCheckResult,
) -> String {
    if scope_check.scope_vars.is_empty() {
        return String::new();
    }
    let mut s = String::from("| Variable | Type |\n|---|---|\n");
    for (var, ty) in scope_check.scope_vars.iter().take(30) {
        s.push_str(&format!("| {} | {} |\n", var, ty));
    }
    s
}

/// Merge per-claim L3 verdicts into result: warnings, risk contribution,
/// claim-decomposition detail, and synthetic validator_response.
fn merge_l3_verdicts(
    l3_verdicts: &[ClaimVerdict],
    api_claims_count: usize,
    result: &mut ScanResultData,
) {
    let (claim_warnings, claim_risk) = aggregate_claims(l3_verdicts);
    for w in &claim_warnings {
        result.warnings.push(w.clone());
        result.details.push(format!("logic: {}", w));
    }
    result.recompute();

    let hallucinated_count = l3_verdicts.iter().filter(|v| v.verdict == "hallucinated").count();
    let uncertain_count = l3_verdicts.iter().filter(|v| v.verdict == "uncertain").count();
    let verified_count = l3_verdicts.iter().filter(|v| v.verdict == "verified").count();
    // CODE claims skip L3 per pivot verdict — compiler gate owns them.
    // Tracked separately so the count math in the detail line adds up.
    let skipped_count = l3_verdicts.iter().filter(|v| v.verdict == "skipped").count();
    result.details.push(format!(
        "claim-decomposition: {} claims -> {} verified, {} hallucinated, {} uncertain, {} skipped (risk_delta={:.2})",
        api_claims_count, verified_count, hallucinated_count, uncertain_count, skipped_count, claim_risk
    ));

    if uncertain_count > 0 && result.warnings.is_empty() {
        result.details.push(format!(" \u{26a0} low confidence ({} claims unverifiable)", uncertain_count));
    }

    result.validator_response = format!(
        "{{\"claims_verified\":{},\"claims_hallucinated\":{},\"claims_uncertain\":{},\"claims_skipped\":{},\"per_claim_consistency\":{}}}",
        verified_count, hallucinated_count, uncertain_count, skipped_count, l3_verdicts.len()
    );
    result.scan_failed = false;
}

/// Append a reasoning-claim telemetry record to `~/.anubis/reasoning_telemetry.jsonl`.
///
/// One JSON line per scan that triggered the reasoning-claim bypass. Used to
/// measure recall / FPR on reasoning claims separately from code claims,
/// since reasoning-claim detection is the new path (Task 1-3 wiring,
/// 2026-08-12) and needs its own evaluation signal.
///
/// Best-effort: errors are logged at `warn` level and swallowed. Telemetry
/// must never break the scan pipeline.
fn log_reasoning_telemetry(
    prose_claims: &[String],
    l3_verdicts: &[ClaimVerdict],
    language: &str,
) {
    use std::io::Write;
    use parking_lot::Mutex;

    static TELEMETRY_LOCK: Mutex<()> = Mutex::new(());
    let _guard = TELEMETRY_LOCK.lock();

    let path = crate::dirs_home().join(".anubis").join("reasoning_telemetry.jsonl");
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(target: "scanner", error = %e, "reasoning telemetry dir create failed");
            return;
        }
    }

    // Collect only verdicts for reasoning claims (skip "skipped" code
    // placeholders and other code-shaped verdicts).
    let prose_set: std::collections::HashSet<&str> =
        prose_claims.iter().map(|s| s.as_str()).collect();
    let prose_verdicts: Vec<&ClaimVerdict> = l3_verdicts
        .iter()
        .filter(|v| prose_set.contains(v.claim.as_str()))
        .collect();

    let hallucinated = prose_verdicts.iter().filter(|v| v.verdict == "hallucinated").count();
    let uncertain = prose_verdicts.iter().filter(|v| v.verdict == "uncertain").count();
    let verified = prose_verdicts.iter().filter(|v| v.verdict == "verified").count();

    let entry = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "language": language,
        "claim_count": prose_claims.len(),
        "verdicts": prose_verdicts.iter().map(|v| serde_json::json!({
            "claim": v.claim,
            "verdict": v.verdict,
            "confidence": v.confidence,
            "reason": v.reason,
        })).collect::<Vec<_>>(),
        "summary": {
            "verified": verified,
            "hallucinated": hallucinated,
            "uncertain": uncertain,
        },
    });

    let mut line = match serde_json::to_string(&entry) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: "scanner", error = %e, "reasoning telemetry serialize failed");
            return;
        }
    };
    line.push('\n');

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(target: "scanner", error = %e, "reasoning telemetry file open failed");
            return;
        }
    };
    if let Err(e) = file.write_all(line.as_bytes()) {
        tracing::warn!(target: "scanner", error = %e, "reasoning telemetry write failed");
    }
}

/// Extract type/function/class/message/service definitions from fenced code
/// blocks whose language differs from the primary detected language. These
/// are added to session_defined so cross-language references (e.g., proto
/// `message Task` used in Go code) are not flagged as hallucinated.
///
/// Handles the general multi-language response problem: when an LLM generates
/// proto + Go, SQL + Python, HTML + TS in one response, each language's type
/// definitions should be visible to all other languages' scope analysis.
fn extract_cross_language_definitions(content: &str, primary_lang: &str) -> Vec<String> {
    use std::sync::OnceLock;
    static TYPE_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = TYPE_RE.get_or_init(|| {
        regex::Regex::new(
            r"^\s*(?:pub\s+|export\s+|public\s+|private\s+|protected\s+|internal\s+)?(?:struct|enum|trait|class|interface|type|message|service|namespace|module|component|func|def|fn)\s+(\w+)"
        ).unwrap()
    });
    let go_type_re = regex::Regex::new(r"^\s*type\s+(\w+)\s+(?:struct|interface)").unwrap();
    let typedef_re = regex::Regex::new(r"^\s*typedef\s+(?:struct|enum)\s*\{[^}]*\}\s*(\w+)").unwrap();
    // proto rpc definitions: `rpc CreateTask(CreateTaskRequest) returns (TaskResponse);`
    let proto_rpc_re = regex::Regex::new(r"^\s*rpc\s+(\w+)\s*\(").unwrap();

    let mut defs = Vec::new();
    let mut in_block = false;
    let mut block_lang = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_block {
                in_block = false;
                block_lang.clear();
            } else {
                in_block = true;
                block_lang = trimmed[3..].trim().to_lowercase();
                // Normalize: take first word (e.g., "typescript" from "typescript tsx")
                block_lang = block_lang.split(|c: char| !c.is_alphanumeric()).next().unwrap_or("").to_string();
            }
        } else if in_block && !block_lang.is_empty() && block_lang != primary_lang {
            if let Some(name) = re.captures(line).and_then(|c| c.get(1)) {
                defs.push(name.as_str().to_string());
            }
            if let Some(name) = go_type_re.captures(line).and_then(|c| c.get(1)) {
                defs.push(name.as_str().to_string());
            }
            if let Some(name) = typedef_re.captures(line).and_then(|c| c.get(1)) {
                defs.push(name.as_str().to_string());
            }
            if let Some(name) = proto_rpc_re.captures(line).and_then(|c| c.get(1)) {
                defs.push(name.as_str().to_string());
            }
        }
    }
    defs
}

/// Store a successful scan result in the verdict cache (24h TTL, 500 cap).
fn verdict_cache_put(cache_key: u64, result: &ScanResultData) {
    if result.scan_failed || result.validator_response.is_empty() {
        return;
    }
    let json = match serde_json::to_string(&ScanResultJson::from(result)) {
        Ok(j) => j,
        Err(_) => return,
    };
    let mut guard = VERDICT_CACHE.lock();
    let cache = guard.get_or_insert_with(HashMap::new);
    evict_expired_cache(cache);
    let now = current_time_ms();
    cache.insert(
        cache_key,
        CachedVerdict {
            result_json: json,
            expires_at: now + VERDICT_CACHE_TTL_MS,
            inserted_at: now,
        },
    );
}

// Main scan pipeline

pub async fn scan_response(content: &str, ctx: &ScanContext) -> ScanResultData {
    let started = Instant::now();
    let scan_id = uuid::Uuid::new_v4();

    // Strip tool outputs before scanning
    let scan_content = strip_tool_outputs(content);
    let stripped_chars = content.len().saturating_sub(scan_content.len());

    // Extract code-only content for scope-aware scanners (check_symbols,
    // scope_analysis, FORGE). LLM responses are markdown; these scanners
    // must analyze code, not prose. Uses the existing extract_code_blocks_only
    // which has a looks_like_code heuristic + raw-code fallback for DELULU.
    // extract_api_claims already uses this internally (line 400).
    let code_content = extract_code_blocks_only(&scan_content);

    // Skip compaction/background traffic
    if ctx.request_class == "compaction" || ctx.request_class == "background" {
        let mut r = ScanResultData::default();
        r.details.push(format!(
            "skipped ({} — non-user-facing traffic)",
            ctx.request_class
        ));
        return r;
    }

    // Token estimation gate.
    //
    // Council A13: prior heuristic `len() / 4` used raw byte count assuming
    // 4 bytes/token — accurate for ASCII English but underestimated CJK
    // content by ~3x (1 CJK char = ~3 UTF-8 bytes, ~1 token). Mixed-content
    // users (Korean/Chinese/Japanese codebases with English identifiers)
    // would get false "too few tokens" gate hits.
    //
    // Replacement: char-iter weighting. ASCII/Latin chars ~0.25 tokens,
    // CJK and other multibyte chars ~1 token (closer to actual BPE behaviour
    // for cl100k_base /GLM tokenizer vocabularies).
    //
    // Floor lowered from 13 → 3 tokens. The deterministic compiler gates
    // (TS, Rust, C#, etc.) operate on code regardless of token count — a
    // 12-character TS sample like `r.parseBody()` (3 tokens) should still
    // reach the compiler gate. L3 (LLM judge) has its own `min_len` gate
    // below, so lowering this floor doesn't increase LLM token spend.
    let est_tokens = estimate_tokens(&scan_content);
    if est_tokens < 3 {
        let mut r = ScanResultData::default();
        r.details.push(format!("too few tokens ({})", est_tokens));
        return r;
    }

    // ── Verdict cache check ────────────────────────────────────────────
    let cache_key = build_cache_key(&scan_content, ctx);
    if let Some(json) = verdict_cache_get(cache_key) {
        if let Ok(result) = serde_json::from_str::<ScanResultJson>(&json) {
            return result.into();
        }
    }
    {
        let mut m = VERDICT_MISSES.lock();
        *m += 1;
    }

    tracing::info!(
        target: "scanner",
        content_len = scan_content.len(),
        raw_content_len = content.len(),
        tool_stripped_chars = stripped_chars,
        est_tokens,
        logic_model = %ctx.logic_model,
        "scanResponse start"
    );

    let mut result = ScanResultData::default();

    // ── Check A: API claim extraction ──────────────────────────────────
    let claims = extract_api_claims(&scan_content);

    // Detect language early — needed for session_symbols language gating
    // (prevents cross-language FP contamination) and L1.5 symbol check.
    let detected_language = if !ctx.language.is_empty() {
        ctx.language.as_str()
    } else {
        crate::scanner::forge_pipeline::detect_language(&scan_content, &ctx.project_root)
    };

    // ── Session symbol accumulation (PRE-scan) ────────────────────────
    // Extract all defined symbols (types, functions, imports, bindings)
    // from THIS response before building the project index, so:
    //   1. Same-response definitions (class Main, imported Objects) land in
    //      session_defined and suppress undefined-variable /
    //      cached-hallucination FPs for symbols the response itself defines.
    //   2. Cross-response: types defined in earlier responses but not yet
    //      on disk (project_index cache lag) still resolve.
    // Accumulating pre-scan subsumes the old post-scan accumulation — the
    // store persists for future scans either way.
    if !code_content.is_empty() {
        crate::scanner::project_index::accumulate_session_symbols(
            &ctx.project_root,
            &code_content,
            detected_language,
        );
    }

    let project_index = if !claims.is_empty() {
        let mut idx = build_project_index(&ctx.project_root);
        // Merge cross-response session symbols — types/functions defined
        // in earlier responses but not yet on disk (project_index cache lag).
        let session_syms = crate::scanner::project_index::get_session_symbols(&ctx.project_root, detected_language);
        if !session_syms.is_empty() && !idx.is_empty() {
            idx.push('\n');
            idx.push_str(&session_syms);
        } else if !session_syms.is_empty() {
            idx = session_syms;
        }
        idx
    } else {
        String::new()
    };

    let local_vars = extract_local_variables(&scan_content);

    // L1 "Unverified API" check: emit warnings ONLY when we have a
    // project_index to check against AND the claim has a close fuzzy
    // match in the index.
    //
    // Why fuzzy-match required: with only declarations/imports/bindings
    // in the index (no external library APIs), every external call misses.
    // Flagging every miss produces 85%+ false-positive rate on legitimate
    // external API calls (see DELULU benchmark golden completions).
    //
    // The fuzzy-match heuristic catches two hallucination patterns:
    //   - Typos: `fit_tranform` vs indexed `fit_transform` (Levenshtein ≤ 2)
    //   - Wrong-suffix: `PolynomialTransformer` vs indexed `PolynomialFeatures`
    //     (shared 4+ char prefix + similar length)
    //
    // Completely-fabricated names (no close match) stay silent — they might
    // be real APIs from external libraries the index doesn't know about.
    // Layer 3 (LLM validator) is the right tool for those cases.
    evaluate_l1_claims(&claims, &local_vars, &project_index, &mut result);

    let has_unverified = !result.warnings.is_empty();
    let min_len = if has_unverified { 50 } else { 50 };

    // ── Auto-fetch missing libraries + proactive dependency fetch ──────
    // Fire-and-forget: detached spawns (cancellable via ctx.cancel) populate
    // the SQLite symbol cache for subsequent scans. Never blocks the scan.
    spawn_background_fetches(&scan_content, ctx);

    // ── Layer 1.5: symbol existence check against local SQLite cache ────
    //
    // ALWAYS runs (not gated behind L3). Two reasons:
    //   1. DELULU benchmark + fresh-install scenarios disable L3 (empty
    //      API key); check_symbols must still fire so cache-populated
    //      libraries contribute deterministic warnings.
    //   2. Cheap SQLite lookup — no network, no LLM cost.
    //
    // The markdown output augments L3 RAG context (pushed into docs_snippet
    // below). The structured `symbol_check` drives the L2.5 cascade.
    //
    // Detect language once here — used by both check_symbols (L1.5) and the
    // FORGE pipeline (L1.7). Hoisted out of the FORGE block so the symbol
    // cache can filter libraries by language (prevents Python's pathlib.Path
    // matching Rust's axum::extract::Path).
    let symbol_check = crate::symbols::check_symbols(&code_content, detected_language);
    // Pre-compute session-defined names for cross-response FP filtering.
    // Used by both cached-hallucination filter (below) and FORGE filter (later).
    // Also enrich with cross-language definitions from fenced blocks (e.g.,
    // proto `message Task` visible when scanning Go code in the same response).
    let cross_lang_defs = extract_cross_language_definitions(&scan_content, detected_language);
    let enriched_index = if cross_lang_defs.is_empty() {
        project_index.to_string()
    } else {
        let mut s = project_index.to_string();
        for d in &cross_lang_defs {
            s.push_str(&format!("\nsession: {}", d));
        }
        s
    };
    let session_defined: std::collections::HashSet<&str> = enriched_index
        .lines()
        .filter_map(|l| l.strip_prefix("session: ").map(|s| s.trim()))
        .collect();
    let scope_check = crate::scanner::scope_analysis::check_instance_calls(&code_content, detected_language);
    emit_l1_5_warnings(&symbol_check, &scope_check, &session_defined, &scan_content, &mut result);

    // ── L1.7: FORGE pipeline (Python only currently) ──────────────────
    //
    // FORGE 2026 pattern (arxiv 2601.19106): AST extraction + dynamic KB
    // introspection achieves 100% precision / 87.6% recall on Python,
    // 50-100x cheaper than LLM judge. Skips L3 for resolved claims (cascade).
    //
    // For non-Python languages: falls through with empty result. Existing
    // L1.5 + L3 path handles them as before.
    // LANGUAGE-AWARE CONTENT ROUTING for FORGE:
    //   Python  → raw scan_content when no fenced blocks (strategy 3 over-filters)
    //   Rust/Go → filtered code_content (regex scope checker needs prose stripped)
    //
    // Rationale: Python AST parser naturally rejects invalid content (prose,
    // JSON, markdown) → safe to pass raw. But when fenced blocks ARE present
    // (real benchmark responses), strategy 1 already extracted clean code.
    // Only bypass filtering when strategy 3 (raw fallback) was the source —
    // detectable by absence of "```" in scan_content.
    let forge_content: &str = if detected_language == "python"
        && !scan_content.contains("```")
        && looks_like_code(&scan_content)
    {
        &scan_content
    } else {
        &code_content
    };
    // ── Append code extracted from tool_use JSON ────────────────────────
    // Anthropic / OpenAI agent protocols wrap file edits in tool_use blocks
    // whose `input` is JSON with fields like `newString`/`oldString`. The
    // code lives inside JSON string values escaped as \\n and \\". The Python
    // AST extractor sees JSON syntax, not Python, so hallucinated calls
    // inside edit commands slip past FORGE on both forge_content paths:
    //   - raw scan_content path: contains JSON wrappers, AST parser rejects
    //   - code_content path: extract_code_blocks_only already extracts
    //     tool_code but only when has_tool_call_json triggers, and only if
    //     the result passes the prose filter gates.
    //
    // This block unconditionally runs extract_tool_call_code on scan_content
    // when a tool-call marker is present, and prepends the extracted code to
    // forge_content so FORGE sees the unwrapped edits.
    let forge_content_with_tool_code: String;
    let forge_content: &str = if detect_tool_call_marker(&scan_content) {
        let tool_code = extract_tool_call_code(&scan_content);
        if !tool_code.is_empty() {
            tracing::debug!(
                target: "scanner",
                tool_code_len = tool_code.len(),
                forge_content_len = forge_content.len(),
                "appended tool_use-extracted code to forge_content"
            );
            forge_content_with_tool_code =
                format!("{}\n\n{}", tool_code, forge_content);
            &forge_content_with_tool_code
        } else {
            forge_content
        }
    } else {
        forge_content
    };
let mut forge_result = if detected_language != "unknown" {
    crate::scanner::forge_pipeline::run_forge_pipeline(
        forge_content,
        detected_language,
        &scope_check.scope_vars,
        &project_index,
        &ctx.project_root,
    )
        .await
    } else {
        crate::scanner::forge_pipeline::ForgeResult::default()
    };
    // Supplementary FORGE warnings: checksum fabrication + compiler verification.
    merge_supplementary_forge_warnings(&mut forge_result, content, detected_language, &code_content).await;

    // Push FORGE warnings with cross-response FP filter.
    emit_forge_warnings(&forge_result, &session_defined, &mut result);

    // ── LSP FP Gate: suppress FORGE false positives via LSP ──
    // LSP servers (rust-analyzer, gopls) resolve symbols FORGE's regex+cache
    // missed (crate:: paths, internal types, cross-package refs). If LSP
    // resolves a flagged symbol → suppress the false positive.
    // Only fires for Rust and Go (languages with mature project-aware LSPs).
    // Safe default: returns warnings unchanged if LSP server unavailable.
    if !result.warnings.is_empty() && (detected_language == "rust" || detected_language == "go") {
        let pre_count = result.warnings.len();
        result.warnings = crate::scanner::lsp_gate::suppress_fps(
            result.warnings,
            &scan_content,
            detected_language,
            std::path::Path::new(&ctx.project_root),
        )
        .await;
        if result.warnings.len() < pre_count {
            tracing::info!(
                target: "scanner",
                suppressed = pre_count - result.warnings.len(),
                remaining = result.warnings.len(),
                "LSP FP gate suppressed false positives"
            );
        }
    }

    // ── Compiler Gate: PRIMARY hallucination detector + FP suppressor ──
    // Runs language compilers on the response. Two modes:
    //   1. FP SUPPRESSION (FORGE has warnings): symbols FORGE flagged that
    //      compiler CONFIRMS are unresolved → keep. Symbols compiler RESOLVES
    //      → suppress as FP.
    //   2. PRIMARY DETECTION (FORGE has 0 warnings): compiler runs anyway,
    //      returns ALL unresolved symbols as NEW hallucination warnings.
    //      This catches hallucinations FORGE's regex/AST pipeline misses.
    // SKIP_COMPILER_GATES=1: fast-path for benchmark runs.
    // Timeout: cap compiler gate at 3s for production usability. If rustc/tsc
    // doesn't finish in 3s, let response through without compiler verification.
    // Content-hash cache makes repeat scans instant (first scan pays the cost).
    if std::env::var("SKIP_COMPILER_GATES").is_err()
        && !code_content.trim().is_empty()
    {
        // Phase 2: content-hash cache wraps the compiler-gate dispatch.
        // Same code+language within TTL (1h) → return cached result without
        // re-running rustc/dotnet/tsc/etc. Cache is process-wide via
        // `compiler_cache::global()`. Hits: regression benchmarks (100%),
        // edit cycles (~50%), prod scans (~10%).
        let code_for_cache = code_content.clone();
        let lang_for_cache = detected_language.to_string();
        let warnings_snapshot = result.warnings.clone();
        let project_root_for_cache = ctx.project_root.clone();
        let gate_genuine: Option<std::collections::HashSet<String>> =
            crate::scanner::compiler_cache::global()
                    .lookup_or_compute(&code_for_cache, &lang_for_cache, || {
                    let code = code_for_cache.clone();
                    let lang = lang_for_cache.clone();
                    let warnings = warnings_snapshot.clone();
                    let project_root = project_root_for_cache.clone();
                    async move {
                        match lang.as_str() {
                            "rust" => {
                                crate::scanner::compiler_verifier::rust_compiler_gate(
                                    &code,
                                    &warnings,
                                    &project_root,
                                )
                                .await
                            }
                            "typescript" | "javascript" => {
                                crate::scanner::ts_method_checker::ts_compiler_gate(
                                    &code,
                                    &warnings,
                                    &project_root,
                                )
                                .await
                            }
                            "python" => {
                                crate::scanner::compiler_verifier::python_compiler_gate(
                                    &code,
                                    &warnings,
                                )
                                .await
                            }
                            "c" | "cpp" => {
                                crate::scanner::compiler_verifier::c_cpp_compiler_gate(
                                    &code,
                                    &warnings,
                                )
                                .await
                            }
                            "go" => {
                                crate::scanner::compiler_verifier::go_compiler_gate(
                                    &code,
                                    &warnings,
                                )
                                .await
                            }
                            "csharp" => {
                                crate::scanner::compiler_verifier::csharp_compiler_gate(
                                    &code,
                                    &warnings,
                                )
                                .await
                            }
                            "gdscript" => {
                                crate::scanner::compiler_verifier::gdscript_compiler_gate(
                                    &code,
                                    &warnings,
                                )
                                .await
                            }
                            "java" => {
                                crate::scanner::compiler_verifier::java_compiler_gate(
                                    &code,
                                    &warnings,
                                )
                                .await
                            }
                            _ => None,
                        }
                    }
                    })
            .await;
    if let Some(genuine) = gate_genuine {
        let pre_count = result.warnings.len();
        // Fragment-blindness guard (TS/JS only): tsc validates ONE extracted
        // fragment per file; identifiers declared elsewhere in the response
        // (param lists, other files' bindings surfaced in prose/old code)
        // read as "Cannot find name" to tsc but are NOT hallucinations.
        // Drop gate symbols that have a declaration shape anywhere in the
        // full scan content before they become compiler-detected warnings
        // (20260818 task-015: `result`/`jobid`/`ctx` FP class).
        let genuine: std::collections::HashSet<String> =
            if detected_language == "typescript" || detected_language == "javascript" {
                genuine
                    .into_iter()
                    .filter(|sym| {
                        !crate::scanner::forge_ts::name_declared_in_content(
                            &scan_content,
                            sym,
                        )
                    })
                    .collect()
            } else {
                genuine
            };
            if pre_count == 0 && !genuine.is_empty() {
                // PRIMARY DETECTION: FORGE found nothing, but compiler detected
                // unresolved symbols. Add them as NEW hallucination warnings.
                for sym in &genuine {
                    result.warnings.push(format!(
                        "compiler-detected: `{}` — unresolved per {} compiler",
                        sym, detected_language
                    ));
                }
                tracing::info!(
                    target: "scanner",
                    language = %detected_language,
                    new_warnings = genuine.len(),
                    "compiler PRIMARY gate detected hallucinations FORGE missed"
                );
            } else {
                // FP SUPPRESSION: retain only warnings the compiler confirms.
                result.warnings.retain(|w| {
                    let symbols =
                        crate::scanner::compiler_verifier::extract_warning_symbols(w);
                    !symbols.is_empty() && symbols.iter().any(|s| genuine.contains(s))
                });
                // Compiler-confirmed symbols FORGE never flagged are still
                // ground-truth hallucination evidence (gate verified the
                // compiler actually rejects them) - surface them the same
                // way PRIMARY mode does. Without this, a stray FORGE warning
                // (e.g. an unrelated variable FP) flips the gate into
                // suppression mode and buries real catches (audit probe:
                // Go SplitN arity error wiped by an unrelated `parts` FP).
                for sym in &genuine {
                    let covered = result.warnings.iter().any(|w| {
                        crate::scanner::compiler_verifier::extract_warning_symbols(w)
                            .iter()
                            .any(|s| s == sym)
                    });
                    if !covered {
                        result.warnings.push(format!(
                            "compiler-detected: `{}` - unresolved per {} compiler",
                            sym, detected_language
                        ));
                    }
                }
                if result.warnings.len() < pre_count {
                    tracing::info!(
                        target: "scanner",
                        language = %detected_language,
                        suppressed = pre_count - result.warnings.len(),
                        remaining = result.warnings.len(),
                        "compiler FP gate suppressed false positives"
                    );
                }
            }
        }
    }

    tracing::debug!(
        target: "scanner",
        language = %detected_language,
        extracted = forge_result.claims_extracted,
        verified = forge_result.claims_verified,
        hallucinated = forge_result.claims_hallucinated,
        unknown = forge_result.claims_unknown,
        latency_ms = forge_result.latency_ms,
        "FORGE pipeline result"
    );

    // ── Output-prediction execution gate (L2.7) ─────────────────────────
    // Runs AFTER the Stage-5 compiler gate so its warnings cannot be
    // wiped by FP suppression (execution evidence outranks compile
    // cleanliness — a program that compiles can still print something
    // other than what the claim predicts). Fail-open: silent on timeout,
    // interpreter missing, non-clean exit, or empty output.
    {
        let exec_warnings = crate::scanner::compiler_verifier::verify_output_prediction(
            &scan_content,
            detected_language,
            &code_content,
        )
        .await;
        if !exec_warnings.is_empty() {
            result.warnings.extend(exec_warnings.iter().cloned());
            result
                .details
                .push(format!("exec-gate: {} output-prediction mismatch(es)", exec_warnings.len()));
        }
    }

    // │ v3 surface gates: installed-package API surface (L2.8) │
    // Runs AFTER the Stage-5 compiler gate so warnings cannot be wiped by FP
    // suppression (surface evidence outranks compile cleanliness; a module that
    // compiles against stale types can still import a nonexistent export).
    // Catches: wrong named export (createServer from graphql-yoga), invented
    // method on typed instance (yoga.listen), removed kwarg (CliRunner mix_stderr).
    let ts_surface = crate::scanner::surface_gate_ts::check(&scan_content, &code_content, &ctx.project_root).await;
    if !ts_surface.is_empty() {
        result.warnings.extend(ts_surface.iter().cloned());
        result.details.push(format!("surface-gate-ts: {} API-surface mismatch(es)", ts_surface.len()));
    }
    let py_surface = crate::scanner::surface_gate_py::check(&scan_content, &code_content, &ctx.project_root).await;
    if !py_surface.is_empty() {
        result.warnings.extend(py_surface.iter().cloned());
        result.details.push(format!("surface-gate-py: {} signature mismatch(es)", py_surface.len()));
    }

    // ── Compute scan-level confidence (always runs, even when L3 is off) ──
    // Confidence is the user-visible answer to "how sure are we?".
    // Drives the L3 cascade when L3 is enabled, and surfaces in the
    // dashboard / log regardless. Computed BEFORE the L3-enabled block
    // so it's available even when L3 is disabled (DELULU_FORGE_ONLY mode).
    let l1_5_conf = symbol_check.scan_confidence();
    let forge_conf = forge_result.scan_confidence();
    let combined_confidence = l1_5_conf.min(forge_conf);
    result.confidence = combined_confidence;
    tracing::debug!(
        target: "scanner",
        l1_5_conf = format!("{:.3}", l1_5_conf),
        forge_conf = format!("{:.3}", forge_conf),
        l1_5_claims = symbol_check.claim_confidence.len(),
        forge_claims = forge_result.claim_confidence.len(),
        forge_warnings = forge_result.warnings.len(),
        combined = format!("{:.3}", combined_confidence),
        "confidence breakdown"
    );

    // ── Check C: Validator LLM call ────────────────────────────────────
    // Skipped in DELULU_FORGE_ONLY mode (offline benchmark tests).
    // Compiler gates still run — only L3 LLM judge is disabled.
    // L2.5 behavioral outcome lands here when it ran concurrently with the
    // L3 wave below; None means it still needs to run at the tail.
    let mut behavioral_result: Option<(Vec<String>, String)> = None;
    if scan_content.len() >= min_len && !ctx.llm_api_key.is_empty()
        && std::env::var("DELULU_FORGE_ONLY").is_err()
    {
        // Diff scanning: only validate new content
        let diff = get_diff_and_update(&ctx.project_root, &scan_content);
        let effective_content = if diff.len() >= 50 {
            diff
        } else {
            scan_content.to_string()
        };

        // Build RAG context for validator
        let manifest_deps = read_project_manifests(&ctx.project_root);
        let mut docs_snippet = search_docs(&scan_content).await;
        let package_api = build_package_api(&effective_content, &ctx.project_root);
        if !docs_snippet.is_empty() {
            result.docs_assisted = true;
        }

        // Push L1.5 markdown into RAG context for the validator prompt.
        if !symbol_check.markdown.is_empty() {
            if !docs_snippet.is_empty() {
                docs_snippet.push_str("\n\n");
            }
            docs_snippet.push_str(&symbol_check.markdown);
            result.docs_assisted = true;
        }

        // ── Library-driven docs fallback (doc-grounding for L3) ────────
        // search_docs() returns empty when extract_lookup_terms finds no
        // terms (no `ClassName.method(` patterns or imports in content)
        // AND the docs Worker has no markdown for any term. For prose
        // claims (lifecycle / behavioral / performance statements) this
        // leaves L3 with `## REFERENCE DOCUMENTATION: NONE AVAILABLE`,
        // biasing the judge toward "uncertain" verdicts (~0.44 conf).
        //
        // Fallback: detect libraries via import statements (covers cases
        // where the LLM mentioned a library in prose but didn't make a
        // class-prefixed API call), pull from symbol cache + remote docs
        // Worker. Bounded cost: 2000-token cache budget, max 3 remote
        // calls (each with 24h disk-cache fast path).
        if docs_snippet.is_empty() {
            let fallback = build_library_docs_fallback(&scan_content).await;
            if !fallback.is_empty() {
                tracing::info!(
                    target: "scanner",
                    fallback_len = fallback.len(),
                    "L3 docs fallback populated docs_snippet (was empty)"
                );
                docs_snippet = fallback;
                result.docs_assisted = true;
            }
        }

        // ── Direct markdown read fallback ──────────────────────────────
        // When search_docs + build_library_docs_fallback both return empty
        // (cold cache, no remote Worker), read markdown files directly from
        // ANUBIS_DOCS_DIR for detected libraries. Uses per-claim focused
        // retrieval (LocalMarkdownProvider) instead of bulk file dump to
        // avoid Lost-in-the-Middle effect (TACL 2024: bulk hurts -46.5%).
        // Kill switch: ANUBIS_L3_DOCS_IN_PROMPT=0 disables ALL doc injection.
        if docs_snippet.is_empty()
            && std::env::var("ANUBIS_L3_DOCS_IN_PROMPT")
                .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
                .unwrap_or(true)
        {
            let focused = crate::doc_provider::per_claim_docs(&scan_content, 500);
            if !focused.is_empty() {
                docs_snippet = focused;
                result.docs_assisted = true;
            }
        }

        // Note: scope_vars injection into L3 prompt was tried (commit f8dc7dd)
        // and reverted — v4 measurement showed it killed parameter-type
        // recall (79% -> 43%) by distracting L3 with scope info. Scope-aware
        // detection stays as L1.5 (check_instance_calls emits its own warnings).

        // ── Layer 2.5: Confidence-graded cascade decision ─────────────
        // Skip the LLM validator call when deterministic layers (L1.5 +
        // FORGE) have HIGH CONFIDENCE about every claim. Escalate to L3
        // only when there's at least one uncertain claim.
        //
        // Confidence thresholds (empirically tuned to DELULU recall + L3
        // call reduction targets):
        //   - 0.85+ : deterministic verdict trusted, skip L3 for this claim
        //            (exact cache hit, AST introspection miss, registry 404)
        //   - 0.30-0.85 : borderline — escalate to L3 for spot-check
        //            (fuzzy class match, weak prefix overlap)
        //   - <0.30 : unknown — also escalate to L3 if L3 is configured,
        //            otherwise silently drop (no signal either way)
        //
        // chaincheck pattern: NLI→judge cascade cuts latency 19× on clear-cut
        // cases. Confidence-graded cascade generalizes this: trust high-conf
        // deterministic verdicts (verified OR hallucinated), escalate the rest.
        let l1_had_warnings = has_unverified;

        // ── Reasoning claim extraction ─────────────────────────────────────
        // Reasoning claims (lifecycle/behavioral/performance/idiom statements)
        // cannot be verified by deterministic layers — they describe semantic
        // properties only an LLM can judge. Extract them from prose (skipping
        // fenced code) and force L3 to run when present, even if the cascade
        // would otherwise skip.
        //
        // Internal implementation: extract_prose_claims / ClaimKind::Prose
        // (canonical names retained — see l3_per_claim.rs).
        let prose_claims = if !ctx.llm_api_key.is_empty() {
            // Union: trigger-word claims + identifier-anchored claims.
            let mut combined = crate::scanner::l3_per_claim::extract_prose_claims(&scan_content);
            let id_claims = crate::scanner::l3_per_claim::extract_identifier_anchored_claims(&scan_content);
            for c in &id_claims {
                if !combined.contains(c) {
                    combined.push(c.clone());
                }
            }
            combined
        } else {
            Vec::new()
        };
        // L1 unverified: if extract_api_claims found API calls that neither
        // L1.5 nor FORGE could verify, force L3 to check them. This catches
        // fabricated methods (e.g. `list.flatten()`, `Iterator::map_to_string()`)
        // that deterministic layers silently skip when no close-match exists.
        let l1_unverified_count = claims.iter()
            .filter(|c| {
                let n = c.trim_end_matches('(').trim_end();
                symbol_check.claim_confidence.get(n).copied().unwrap_or(0.0) < 0.85
                    && forge_result.claim_confidence.get(n).copied().unwrap_or(0.0) < 0.85
            })
            .count();
        let has_prose = !prose_claims.is_empty() || l1_unverified_count > 0;

        // Cascade contract: see compute_cascade_decision() for threshold rationale,
        // introspection-warning guard, vacuous-confidence guard, and reasoning-claim bypass.
        let can_skip_layer3 = compute_cascade_decision(
            l1_had_warnings,
            combined_confidence,
            &forge_result,
            &symbol_check,
            has_prose,
        );

        if can_skip_layer3 {
            tracing::info!(
                target: "scanner",
                method_calls = symbol_check.method_calls_count,
                verified = symbol_check.verified_count,
                symbol_hallucinations = symbol_check.hallucination_count,
                forge_extracted = forge_result.claims_extracted,
                forge_hallucinated = forge_result.claims_hallucinated,
                forge_unknown = forge_result.claims_unknown,
                forge_warnings = forge_result.warnings.len(),
                "L2.5 cascade: skipping L3 (L1.5 fully resolved)"
            );
            result.details.push(format!(
                "cascade-skip: L1.5 verified {} / {} method calls; FORGE saw {} claims ({} hallucinated, {} unknown) — no LLM call needed",
                symbol_check.verified_count,
                symbol_check.method_calls_count,
                forge_result.claims_extracted,
                forge_result.claims_hallucinated,
                forge_result.claims_unknown
            ));
        } else {
            // Refresh local cache only during deep scan (not scan_fast).
            // Fire-and-forget: spawn as detached task so the scan doesn't
            // wait for project file scanning. Same rationale as auto_fetch
            // above — awaiting this inline caused 100+ second stalls when
            // scan_project walked large repos.
            let root_for_refresh = ctx.project_root.clone();
            let cancel = ctx.cancel.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = crate::symbols::local_scanner::refresh_local_cache_if_stale(&root_for_refresh) => {}
                    _ = cancel.cancelled() => {}
                }
            });

            // Auto-fetch was here — moved up so it runs even when Layer 3
            // is disabled. See comment near the move site above.

            // Extract API claims for per-claim verification (claim decomposition).
            // chaincheck pattern: verify each claim independently with focused prompt.
            let api_claims_raw = extract_api_claims(&effective_content);

            // Phase A user-code filter + Phase 2 cascade filter (combined).
            // See classify_claims_for_l3() for the 3-way filter rationale
            // (L1.5-verified, high-confidence deterministic, user-code receiver).
            let mut api_claims: Vec<String> = classify_claims_for_l3(
                api_claims_raw,
                &symbol_check,
                &forge_result,
                &project_index,
                &scope_check,
            );

            // Append prose claims so the same batched L3 call verifies both
            // code-shaped and prose-shaped claims. `verify_claims_per_claim`
            // takes `prose_count` so the trailing prose claims bypass
            // `classify_claim` (which would re-filter identifier-anchored
            // prose as CODE). Prose claims survive `classify_claims_for_l3`
            // filters because they aren't API-shaped (no `Symbol.method(`
            // pattern, no cache entry, no user-variable receiver).
            let prose_count = prose_claims.len();
            if prose_count > 0 {
                api_claims.extend(prose_claims.clone());
            }

            // Log filter savings.
            let total_claims = symbol_check.verified_claims.len() + api_claims.len();
            tracing::debug!(
                target: "scanner",
                verified_l15 = symbol_check.verified_claims.len(),
                user_code_skipped = total_claims.saturating_sub(api_claims.len() + symbol_check.verified_claims.len()),
                remaining_for_l3 = api_claims.len(),
                prose_claims = prose_count,
                "claim classification: cascade + user-code filter + prose bypass"
            );

            // Build scope summary string for L3 prompt context (gives L3
            // variable-type bindings from local scope analysis).
            let scope_summary = build_scope_summary(&scope_check);

            // ── Per-claim L3 verification (falsification judge) ──
            // One claim per call: falsification system prompt + code-first /
            // claim-last user prompt, greedy single sample at 512 tokens,
            // mechanical quote check. Replaces the batched array contract
            // (truncation-prone on small judges) and the 3-sample vote
            // (self-consistency hurt near capacity).
            //
            // `prose_count` flags the trailing prose-originated claims so L3
            // bypasses `classify_claim` — otherwise identifier-anchored prose
            // (e.g. "reads a CSV using read_csv") gets re-classified as CODE
            // and silently skipped before reaching the LLM.
            // L3 wave + L2.5 behavioral judge run CONCURRENTLY. The
            // behavioral call used to run serially AFTER L3 — on small
            // local models that added a full judge latency (~8-12s) to
            // every behavioral-triggering scan on top of the L3 wave.
            let behavioral_fut = run_behavioral_check(&scan_content, detected_language, ctx);
            let (l3_verdicts, behavioral) = tokio::join!(
                crate::scanner::l3_per_claim::verify_claims_per_claim(
                    &api_claims,
                    prose_count,
                    ctx,
                    &docs_snippet,
                    &code_content,
                    &package_api,
                    &scope_summary,
                ),
                behavioral_fut
            );
            behavioral_result = behavioral;

            // Aggregate + merge L3 verdicts into result (warnings, risk, counts).
            merge_l3_verdicts(&l3_verdicts, api_claims.len(), &mut result);

            // ── Reasoning telemetry (Task 3) ─────────────────────────────
            // Log every reasoning-claim bypass invocation so we can measure
            // recall / FPR on reasoning claims separately from code claims.
            // Best-effort: telemetry must never break the scan.
            if prose_count > 0 {
                log_reasoning_telemetry(&prose_claims, &l3_verdicts, detected_language);
            }
        } // end else (run Layer 3)
    }

    // BEHAVIORAL CORRECTNESS (L2.5): independent of cascade. Catches semantic
    // bugs that pass L1.5/FORGE: async scope, missing base case, off-by-one.
    // Already ran concurrently with the L3 wave when L3 fired; runs here on
    // cascade-skip / FORGE_ONLY / short-content paths.
    if behavioral_result.is_none() {
        behavioral_result = run_behavioral_check(&scan_content, detected_language, ctx).await;
    }
    if let Some((behavioral_warnings, signal_summary)) = behavioral_result {
        result.details.push(format!(
            "behavioral: [{}] → {} warning(s)",
            signal_summary,
            behavioral_warnings.len()
        ));
        for w in &behavioral_warnings {
            result.warnings.push(w.clone());
            result.details.push(format!("logic: {}", w));
        }
    }

    // Finalize: recompute, filter L3 warnings against symbol cache, recompute.
    finalize_and_filter_warnings(&mut result);

    // Diagnostic: detect unrecognized warning prefixes.
    use crate::scanner::forge_pipeline::{classify_warning, WarningKind};
    let (cached, scope, forge, unverified, other) = categorize_warnings(&result.warnings);
    if other > 0 {
        // Dump actual warning strings to identify unrecognized prefixes.
        let samples: Vec<&String> = result.warnings.iter()
            .filter(|w| classify_warning(w) == WarningKind::Other)
            .take(3)
            .collect();
        tracing::warn!(
            target: "scanner",
            other_count = other,
            sample_warnings = ?samples,
            "UNRECOGNIZED warning prefixes — risk_score will undercount"
        );
    }
    if !result.warnings.is_empty() {
        tracing::debug!(
            target: "scanner",
            total_warnings = result.warnings.len(),
            cached, scope, forge, unverified, other,
            risk_score = format!("{:.3}", result.risk_score),
            "warning categorization"
        );
    }

    // Auto-parse agent response code blocks -> upsert symbols with version="agent_pending". Fire-and-forget.
    let project_name_owned = crate::symbols::local_scanner::detect_project_name(
        &std::path::PathBuf::from(&ctx.project_root),
    );
    crate::symbols::local_scanner::upsert_agent_symbols(&scan_content, &project_name_owned).await;

    tracing::info!(
        target: "scanner",
        duration_ms = started.elapsed().as_millis(),
        warnings = result.warnings.len(),
        details = result.details.len(),
        scan_failed = result.scan_failed,
        clean = result.clean,
        risk_score = format!("{:.3}", result.risk_score),
        confidence = format!("{:.3}", result.confidence),
        "scanResponse end"
    );

    // Store verdict in cache (24h TTL, 500 cap). Only caches successful results.
    verdict_cache_put(cache_key, &result);

    // ── FP/TP instrumentation ─────────────────────────────────────────
    // Structured per-scan log for passive FP/TP rate measurement.
    // Filter via: target:instrumentation
    // Correlate risk_score + warning_count with eventual compile/test
    // outcomes to compute real FP/TP rates (replacing anecdote with data).
    tracing::debug!(
        target: "instrumentation",
        event = "scan_complete",
        scan_id = %scan_id,
        language = %detected_language,
        content_len = scan_content.len(),
        has_api_key = !ctx.llm_api_key.is_empty(),
        l1_5_method_calls = symbol_check.method_calls_count,
        l1_5_verified = symbol_check.verified_claims.len(),
        forge_extracted = forge_result.claims_extracted,
        forge_hallucinated = forge_result.claims_hallucinated,
        forge_unknown = forge_result.claims_unknown,
        warning_count = result.warnings.len(),
        risk_score = format!("{:.3}", result.risk_score),
        confidence = format!("{:.3}", result.confidence),
        scan_failed = result.scan_failed,
        clean = result.clean,
        docs_assisted = result.docs_assisted,
    );

    if std::env::var("ANUBIS_DUMP_SCAN_CONTENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        && !result.warnings.is_empty()
    {
        let dir = crate::dirs_home().join(".anubis").join("scan-dumps");
        if std::fs::create_dir_all(&dir).is_ok() {
            let path = dir.join(format!(
                "{}-w{}.txt",
                scan_id,
                result.warnings.len()
            ));
            let header = format!(
                "// scan_id={} lang={} warnings={} risk={:.3}\n",
                scan_id,
                detected_language,
                result.warnings.len(),
                result.risk_score
            );
            let _ = std::fs::write(&path, format!("{header}{scan_content}"));
        }
    }

    result
}

// Serialization helper for verdict cache
#[derive(serde::Serialize, serde::Deserialize)]
struct ScanResultJson {
    clean: bool,
    warnings: Vec<String>,
    blocks: Vec<String>,
    details: Vec<String>,
    validator_response: String,
    scan_failed: bool,
    docs_assisted: bool,
    #[serde(default)]
    validator_tokens: u64,
    #[serde(default)]
    risk_score: f64,
    #[serde(default = "default_confidence")]
    confidence: f64,
}

fn default_confidence() -> f64 {
    1.0
}

impl From<&ScanResultData> for ScanResultJson {
    fn from(r: &ScanResultData) -> Self {
        Self {
            clean: r.clean,
            warnings: r.warnings.clone(),
            blocks: r.blocks.clone(),
            details: r.details.clone(),
            validator_response: r.validator_response.clone(),
            scan_failed: r.scan_failed,
            docs_assisted: r.docs_assisted,
            validator_tokens: r.validator_tokens,
            risk_score: r.risk_score,
            confidence: r.confidence,
        }
    }
}

impl From<ScanResultJson> for ScanResultData {
    fn from(j: ScanResultJson) -> Self {
        Self {
            clean: j.clean,
            warnings: j.warnings,
            blocks: j.blocks,
            details: j.details,
            validator_response: j.validator_response,
            scan_failed: j.scan_failed,
            docs_assisted: j.docs_assisted,
            validator_tokens: j.validator_tokens,
            risk_score: j.risk_score,
            confidence: j.confidence,
        }
    }
}

// ---------------------------------------------------------------------------
// Validator LLM call

/// Per-claim verdict from the LLM validator (claim decomposition mode).
///
/// When the L3 prompt includes an explicit list of API claims to verify,
/// the validator returns one of these per claim. Lets us aggregate
/// deterministically instead of relying on free-text issue descriptions.
///
/// Verdicts:
///   - `verified`    — claim is correct, no action
///   - `hallucinated`— claim is wrong/fabricated, weight by confidence
///   - `uncertain`   — can't determine, treat as soft warning
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ClaimVerdict {
    /// The claim text. `#[serde(default)]` so LLM responses that omit this
    /// field still parse — we overwrite with the input claim anyway.
    #[serde(default)]
    pub claim: String,
    /// One of: "verified", "hallucinated", "uncertain".
    pub verdict: String,
    /// Confidence in the verdict, `[0.0, 1.0]`. Higher = more certain.
    #[serde(default)]
    pub confidence: f64,
    /// Short reason for the verdict (displayed to user).
    #[serde(default)]
    pub reason: String,
}

/// Aggregate per-claim verdicts into warnings + risk-score contribution.
///
/// Returns `(warnings_to_add, risk_delta)`:
///   - hallucinated + conf ≥ 0.8 → strong warning (likely block)
///   - hallucinated + conf < 0.8 → warning
///   - uncertain → soft warning
///   - verified → no action
///
/// `risk_delta` is capped at 0.6 — even if every claim is hallucinated,
/// L3 signal alone shouldn't dominate risk (deterministic L1.5 wins).
pub fn aggregate_claims(claims: &[ClaimVerdict]) -> (Vec<String>, f64) {
    // chaincheck pattern: only emit high-confidence verdicts as warnings.
    // Lower-confidence signals (uncertain, hallucinated<0.8) still nudge risk
    // but don't produce user-visible warnings — they're noise that inflates
    // FPR. The DELULU benchmark showed non-high-conf warnings accounted for
    // ~30% of false positives on golden code.
    let mut warnings = Vec::new();
    let mut risk: f64 = 0.0;
    for c in claims {
        let conf = c.confidence.clamp(0.0, 1.0);
        match c.verdict.as_str() {
            "hallucinated" if conf >= 0.6 => {
                warnings.push(format!(
                    "claim-hallucinated (high-conf): {} — {}",
                    c.claim, c.reason
                ));
                risk += 0.20;
            }
            "hallucinated" => {
                // Low-confidence hallucinated — still emit as warning (recall bias).
                // Weak models (gemma4, qwen) saturate at conf ~0.69; the old 0.8
                // threshold made ALL their hallucinated verdicts invisible.
                warnings.push(format!(
                    "claim-hallucinated: {} — {}",
                    c.claim, c.reason
                ));
                risk += 0.06;
            }
            "uncertain" => {
                // chaincheck: unknown/uncertain labels → confidence 0, no warning.
                risk += 0.02;
            }
            _ => {} // verified — no action
        }
    }
    (warnings, risk.min(0.6))
}

/// chaincheck-inspired judge filter: cross-check L3 warnings against the
/// symbol cache (our deterministic ground truth).
///
/// Filters LLM-derived warnings that claim an API "doesn't exist" when the
/// cache shows it does. Catches LLM knowledge errors (e.g., L3 saying
/// `close()` doesn't exist on `std::ofstream` when it does).
///
/// Only filters warnings containing negative-existence phrases. L1.5
/// deterministic warnings use specific prefixes (`cached-hallucination:`,
/// `Unverified API:`, `scope-hallucination:`) that don't match these
/// phrases, so they pass through untouched.
///
/// SUPPRESSION RULE (v1 / strict — measured best): suppress when ANY
/// referenced API in the warning exists in cache. v2 (partial-match:
/// only suppress when ALL refs exist) was tried and reverted — let too
/// much noise through, FPR rose 39% -> 50%.
pub(crate) fn post_filter_l3_against_cache(warnings: &[String]) -> Vec<String> {
    use std::sync::OnceLock;

    let cache = match crate::symbols::cache::SymbolCache::open() {
        Ok(c) => c,
        Err(_) => return warnings.to_vec(),
    };

    // Quick exit: if cache has no libraries, no filtering possible.
    if cache.list_libraries().is_empty() {
        return warnings.to_vec();
    }

    static DOESNT_EXIST_RE: OnceLock<regex::Regex> = OnceLock::new();
    static DOTTED_RE: OnceLock<regex::Regex> = OnceLock::new();
    static BACKTICK_RE: OnceLock<regex::Regex> = OnceLock::new();

    let doesnt_exist = DOESNT_EXIST_RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)does not exist|doesn't exist|don't exist|not exist|no method|unknown method|no such",
        )
        .unwrap()
    });
    let dotted = DOTTED_RE.get_or_init(|| {
        regex::Regex::new(r"\b([A-Z][a-zA-Z_0-9]*)\.([a-zA-Z_][a-zA-Z_0-9]*)")
            .unwrap()
    });
    let backtick = BACKTICK_RE.get_or_init(|| regex::Regex::new(r"`([^`]+)`").unwrap());

    warnings
        .iter()
        .filter(|w| {
            // Compiler-gate warnings are ground truth (rustc/tsc actually
            // rejected the code). The symbol cache can NEVER contradict a
            // real compiler error — exempt them from cache suppression.
            // starts_with (not contains) so an L3 reason merely MENTIONING
            // "compiler:" mid-sentence doesn't dodge the filter.
            if w.starts_with("compiler:")
                || w.starts_with("compiler-detected:")
                || w.starts_with("forge: compiler:")
                || w.starts_with("forge: compiler-detected:")
            {
                return true;
            }
            if !doesnt_exist.is_match(w) {
                return true;
            }

            // Strategy 1: ClassName.method pairs.
            for cap in dotted.captures_iter(w) {
                let class = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let method = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                if class.is_empty() || method.is_empty() {
                    continue;
                }
                let class_syms = cache.lookup_global(class);
                if !class_syms.is_empty() {
                    for sym in &class_syms {
                        if sym.name == method {
                            return false; // suppress: cache contradicts L3
                        }
                    }
                }
            }

            // Strategy 2: backtick-quoted identifiers.
            for cap in backtick.captures_iter(w) {
                let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                if name.is_empty() || name.contains(' ') || name.contains('(') || name.len() > 60 {
                    continue;
                }
                if !cache.lookup_global(name).is_empty() {
                    return false;
                }
                if let Some(last) = name.rsplit(|c| c == '.' || c == ':').next() {
                    if last.len() >= 2 && !cache.lookup_global(last).is_empty() {
                        return false;
                    }
                }
            }

            true
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Validator system prompt
// ---------------------------------------------------------------------------
// Helpers

fn strip_code_fence(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("```") {
        let after_open = s[3..].trim_start_matches("json").trim_start_matches('\n');
        if let Some(end) = after_open.rfind("```") {
            return after_open[..end].trim().to_string();
        }
        return after_open.trim().to_string();
    }
    s.to_string()
}


#[cfg(test)]
mod tests;
