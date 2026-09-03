// Terminal UI dashboard — Rust port of packages/proxy/src/tui.ts.
//
// Ratatui + crossterm alternate-buffer fullscreen. Polls the daemon's
// /__anubis/* internal API every 750ms and renders a two-tab
// dashboard (Overview + Setup). All state is local to the TUI process;
// the daemon is the single source of truth.
//
// The TUI is launched as `ANUBIS tui` and connects to whatever
// daemon URL is configured in ~/.anubis/config.yaml.

use crate::config::{load_config, ANUBISConfig, RoutingMode};
use crate::harness::HarnessStatus;
use crate::trial;
use anyhow::{Context, Result};
use chrono::NaiveDateTime;
use crossterm::{
    event::{
        DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEvent,
        KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
        widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap},
    Frame, Terminal,
};
use serde::Deserialize;
use std::io::{self, Stdout};
use std::time::Duration;

const VERSION: &str = crate::VERSION;
const TICK_MS: u64 = 200;

// ─── Color palette (dark theme + purple accent) ───────────────────────

const PURPLE: Color = Color::Rgb(123, 97, 255);
const OK: Color = Color::Rgb(16, 185, 129);
const WARN: Color = Color::Rgb(245, 158, 11);
const ERR: Color = Color::Rgb(239, 68, 68);
const DIM_FG: Color = Color::Rgb(140, 140, 160);
const BORDER: Color = Color::Rgb(70, 70, 95);
const MUTED: Color = Color::Rgb(110, 110, 130);

// ─── DTOs (mirror daemon's JSON: camelCase top-level, snake_case entries) ─

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyStatsDto {
    #[serde(default)]
    total_requests: u64,
    #[serde(default)]
    total_errors: u64,
    #[serde(default)]
    total_tokens: u64,
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    reasoning_tokens: u64,
    #[serde(default)]
    clean_count: u64,
    #[serde(default)]
    warning_count: u64,
    #[serde(default)]
    blocked_count: u64,
    #[serde(default)]
    skipped_count: u64,
    #[serde(default)]
    validator_tokens: u64,
    #[serde(default)]
    validator_calls: u64,
    #[serde(default)]
    local_check_count: u64,
    #[serde(default)]
    agent_check_count: u64,
    #[serde(default)]
    docs_hit_count: u64,
    #[serde(default)]
    compaction_count: u64,
    #[serde(default)]
    background_count: u64,
    #[serde(default)]
    cache_hit_count: u64,
    #[serde(default)]
    recent_entries: Vec<RecentEntryDto>,
    /// Running sum of risk_score across all scans (for avg computation).
    #[serde(default)]
    risk_score_sum: f64,
    /// Count of scans contributing to risk_score_sum.
    #[serde(default)]
    risk_score_count: u64,
}

#[derive(Debug, Default, Deserialize)]
struct RecentEntryDto {
    #[serde(default)]
    ts: String,
    #[serde(default)]
    request_id: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    streaming: bool,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    latency_ms: u32,
    #[serde(default)]
    total_tokens: u64,
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    reasoning_tokens: u64,
    #[serde(default)]
    scan_result: String,
    #[serde(default)]
    scan_details: Vec<String>,
    #[serde(default)]
    validator_response: String,
    /// Continuous risk score [0.0, 1.0] from scanner. Displayed as 0-10
    /// integer in the dashboard for at-a-glance severity.
    #[serde(default)]
    risk_score: f64,
    /// Scan-level confidence [0.0, 1.0] — how sure the deterministic layers
    /// (L1.5 + FORGE) are about the verdict. Displayed as 0-10 alongside
    /// risk_score. Low confidence (<0.85) triggers L3 escalation.
    #[serde(default = "default_confidence_one")]
    confidence: f64,
}

fn default_confidence_one() -> f64 {
    1.0
}

#[derive(Debug, Default, Deserialize)]
struct PingDto {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    version: String,
}

// ─── Daemon HTTP client ────────────────────────────────────────────────

struct DaemonClient {
    url: String,
    http: reqwest::Client,
}

impl DaemonClient {
    fn new(url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { url, http }
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        // Auth token removed — daemon trusts localhost boundary.
        // License check happens at daemon startup, not per-request.
        self.http.request(method, format!("{}{}", self.url, path))
    }

    async fn stats(&self) -> Option<ProxyStatsDto> {
        self.req(reqwest::Method::GET, "/__anubis/stats")
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()
    }

    async fn ping(&self) -> Option<PingDto> {
        self.req(reqwest::Method::GET, "/__anubis/ping")
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()
    }

    async fn clear(&self) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/clear")
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn harnesses(&self) -> Option<Vec<HarnessStatus>> {
        self.req(reqwest::Method::GET, "/__anubis/harnesses")
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()
    }

    async fn enable_provider(&self, harness_id: &str, provider_id: &str) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/harness/enable")
            .json(&serde_json::json!({"harnessId": harness_id, "providerId": provider_id}))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn disable_provider(&self, harness_id: &str, provider_id: &str) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/harness/disable")
            .json(&serde_json::json!({"harnessId": harness_id, "providerId": provider_id}))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    async fn set_routing(&self, mode: &str) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/routing")
            .json(&serde_json::json!({"mode": mode}))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Set routing mode to Custom AND update custom_url in one round-trip.
    /// The /__anubis/routing endpoint accepts both fields atomically.
    async fn set_custom_url(&self, url: &str) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/routing")
            .json(&serde_json::json!({"mode": "custom", "custom_url": url}))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Toggle block-on-hallucination mode. When ON, hallucinated tool calls
    /// are blocked (response replaced with synthetic assistant message).
    async fn set_block_mode(&self, enabled: bool) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/scanner")
            .json(&serde_json::json!({"block_on_hallucination": enabled}))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Toggle auto-doc injection. When ON, the proxy injects cached API
    /// reference as a system message before forwarding upstream.
    async fn set_auto_inject_docs(&self, enabled: bool) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/scanner")
            .json(&serde_json::json!({"auto_inject_docs": enabled}))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Toggle post-edit verification. When ON, file edits trigger
    /// tsc/cargo check/py_compile and results are injected next turn.
    async fn set_post_edit_verify(&self, enabled: bool) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/scanner")
            .json(&serde_json::json!({"post_edit_verify": enabled}))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Set scanner model + base_url (used by provider/model selection).
    async fn set_scanner_model_url(&self, model: &str, base_url: &str) -> bool {
        self.req(reqwest::Method::POST, "/__anubis/scanner")
            .json(&serde_json::json!({
                "model": model,
                "base_url": base_url,
            }))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// Fetch current config from daemon (used to reload after settings change).
    async fn fetch_config(&self) -> Option<crate::config::ANUBISConfig> {
        let resp = self.req(reqwest::Method::GET, "/__anubis/config").send().await.ok()?;
        let text = resp.text().await.ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Fetch available models from the scanner provider's /models endpoint.
    /// Returns Vec<(model_id,)> sorted alphabetically. Empty if api_key
    /// not set or provider unreachable.
    async fn fetch_scanner_models(&self) -> Vec<String> {
        match self
            .req(reqwest::Method::GET, "/__anubis/models")
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    return Vec::new();
                }
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => json["models"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|m| m.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    Err(_) => Vec::new(),
                }
            }
            Err(_) => Vec::new(),
        }
    }
}

// ─── State ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Setup,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Requests,
    Validator,
}

struct TuiState {
    daemon_url: String,
    daemon_version: String,
    stats: ProxyStatsDto,
    config: Option<ANUBISConfig>,
    tab: Tab,
    focus: Focus,
    selected_request_id: Option<String>,
    recent_scroll: usize,
    validator_scroll: usize,
    should_quit: bool,
    connected: bool,
    status_msg: Option<String>,
    harnesses: Vec<HarnessStatus>,
    /// List widget selection state for the Setup tab. Stores absolute item
    /// index + scroll offset. We snap selected to a selectable item each render
    /// since the list contains non-selectable headers/separators/detail rows.
    setup_state: ListState,
    /// Models fetched live from scanner provider's /models endpoint.
    /// Empty until first Setup tab poll or if api_key not set.
    scanner_models: Vec<String>,

    /// Active popup overlay (provider/model selection). None = no popup.
    popup: Option<PopupState>,

    /// Inline edit buffers for CUSTOM scanner provider. When Some, the
    /// corresponding field is being edited (cursor shown, keys captured).
    editing_scanner_url: bool,
    editing_scanner_model: bool,
    scanner_url_buf: String,
    scanner_model_buf: String,

    // Layout cache (refreshed every render, used for mouse hit-testing).
    rects: LayoutRects,
}

/// State for the dropdown popup overlay.
#[derive(Clone)]
struct PopupState {
    kind: PopupKind,
    /// (display_name, value_to_send) pairs
    items: Vec<(String, String)>,
    selected: usize,
    title: String,
    /// Buffer for CustomUrlEdit kind. None = use empty input. Other kinds
    /// leave this as None.
    text_input: Option<String>,
}

#[derive(Clone, Copy)]
enum PopupKind {
    ProviderSelect,
    ModelSelect,
    /// Inline text-entry popup for editing `routing.custom_url` from the
    /// dashboard. Saves via POST /__anubis/routing on Enter.
    CustomUrlEdit,
}

#[derive(Default, Clone, Copy)]
struct LayoutRects {
    tab_overview: Rect,
    tab_setup: Rect,
    quit_btn: Rect,
    clear_btn: Rect,
    recent_body: Rect,
    validator_body: Rect,
    setup_body: Rect,
    popup_body: Rect,
}

impl TuiState {
    fn new(daemon_url: String) -> Self {
        Self {
            daemon_url,
            daemon_version: "—".to_string(),
            stats: ProxyStatsDto::default(),
            config: None,
            tab: Tab::Overview,
            focus: Focus::Requests,
            selected_request_id: None,
            recent_scroll: 0,
            validator_scroll: 0,
            should_quit: false,
            connected: false,
            status_msg: None,
            harnesses: Vec::new(),
            setup_state: ListState::default(),
            scanner_models: Vec::new(),
        popup: None,
        editing_scanner_url: false,
        editing_scanner_model: false,
        scanner_url_buf: String::new(),
        scanner_model_buf: String::new(),
        rects: LayoutRects::default(),
        }
    }

    fn selected_entry(&self) -> Option<&RecentEntryDto> {
        let id = self.selected_request_id.as_ref()?;
        self.stats
            .recent_entries
            .iter()
            .find(|e| &e.request_id == id)
    }

    fn select_request(&mut self, id: Option<String>) {
        if self.selected_request_id != id {
            self.validator_scroll = 0;
        }
        self.selected_request_id = id;
    }

    fn move_recent_cursor(&mut self, delta: i32) {
        let entries = &self.stats.recent_entries;
        if entries.is_empty() {
            return;
        }
        let cur = self
            .selected_request_id
            .as_ref()
            .and_then(|id| entries.iter().position(|e| &e.request_id == id));
        let next = match cur {
            None => 0,
            Some(i) => (i as i32 + delta).max(0).min(entries.len() as i32 - 1) as usize,
        };
        self.select_request(Some(entries[next].request_id.clone()));

        let visible = self.rects.recent_body.height as usize;
        if next < self.recent_scroll {
            self.recent_scroll = next;
        } else if visible > 0 && next >= self.recent_scroll + visible {
            self.recent_scroll = next + 1 - visible;
        }
    }

    fn clamp_validator_scroll(&mut self) {
        let total = self.validator_line_count();
        let visible = self.rects.validator_body.height as usize;
        let max = total.saturating_sub(visible);
        if self.validator_scroll > max {
            self.validator_scroll = max;
        }
    }

    fn validator_line_count(&self) -> usize {
        self.selected_entry()
            .map(|e| e.validator_response.lines().count())
            .unwrap_or(0)
    }
}

// ─── Formatting helpers (ported from tui.ts) ───────────────────────────

fn fmt_tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn fmt_latency_ms(ms: u32) -> String {
    if ms >= 1000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else {
        format!("{}ms", ms)
    }
}

/// Format a [0.0, 1.0] risk_score as a 0-10 integer string.
/// Used for at-a-glance severity in the dashboard recent entries.
///   0.0     → "0/10"  (clean)
///   0.42    → "4/10"
///   0.78    → "8/10"
///   1.0     → "10/10" (certain hallucination)
fn fmt_risk(score: f64) -> String {
    let scaled = (score * 10.0).round() as i32;
    let clamped = scaled.clamp(0, 10);
    format!("{}/10", clamped)
}

/// Format a [0.0, 1.0] confidence as a 0-10 integer string with C: prefix
/// to distinguish from risk. Low confidence (<0.85 → C<9) signals L3
/// escalation was warranted.
///   1.0     → "C10/10" (every claim resolved with strong evidence)
///   0.85    → "C9/10"  (borderline — cascaded skip threshold)
///   0.50    → "C5/10"  (uncertain — L3 spot-check needed)
///   0.0     → "C0/10"  (no claims resolved)
fn fmt_confidence(conf: f64) -> String {
    let scaled = (conf * 10.0).round() as i32;
    let clamped = scaled.clamp(0, 10);
    format!("C:{}/10", clamped)
}

fn pct(n: u64, denom: u64) -> u64 {
    if denom == 0 {
        0
    } else {
        (n as f64 * 100.0 / denom as f64).round() as u64
    }
}

fn pad(s: &str, len: usize) -> String {
    if s.chars().count() >= len {
        let truncated: String = s.chars().take(len).collect();
        truncated
    } else {
        let mut out = s.to_string();
        out.push_str(&" ".repeat(len - s.chars().count()));
        out
    }
}

fn short_url(url: &str) -> String {
    url.replacen("https://", "", 1).replacen("http://", "", 1)
}

fn fmt_time(ts: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        return dt.format("%H:%M:%S").to_string();
    }
    for fmt in &[
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, fmt) {
            return ndt.format("%H:%M:%S").to_string();
        }
    }
    ts.chars().take(8).collect()
}

fn scan_result_color(s: &str) -> Color {
    match s {
        "clean" => OK,
        "warning" => WARN,
        "blocked" | "error" => ERR,
        _ => DIM_FG,
    }
}

// ─── Styles ────────────────────────────────────────────────────────────

fn heading_style() -> Style {
    Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)
}
fn dim_style() -> Style {
    Style::default().fg(DIM_FG)
}
fn muted_style() -> Style {
    Style::default().fg(MUTED)
}

// ─── Scan stage summarizer (ported from summarizeScanStages) ────────────

fn summarize_scan_stages(entry: &RecentEntryDto) -> Vec<String> {
    let mut lines = Vec::new();

    let length_detail = entry
        .scan_details
        .iter()
        .find(|d| d.starts_with("too short"));
    if let Some(d) = length_detail {
        lines.push(format!("• content: {}", d));
    } else {
        lines.push(format!(
            "• content: scanned (prompt {} → completion {})",
            fmt_tokens(entry.prompt_tokens),
            fmt_tokens(entry.completion_tokens)
        ));
        if entry.reasoning_tokens > 0 {
            lines.push(format!(
                "• reasoning tokens: {} (model produces hidden thinking)",
                fmt_tokens(entry.reasoning_tokens)
            ));
        }
    }

    // Show ACTUAL warning text — not just counts
    // Filter is best-effort: anything not matching a known warning prefix
    // still counts as a warning if scan_result says so (checked below).
    let warnings: Vec<&String> = entry
        .scan_details
        .iter()
        .filter(|d| {
            d.starts_with(crate::scanner::forge_pipeline::prefix::UNVERIFIED_API)
                || d.starts_with("forbidden")
                || d.starts_with("logic:")
                || d.starts_with("⚠")
        })
        .collect();

    if !warnings.is_empty() {
        lines.push(format!("• warnings ({}):", warnings.len()));
        for w in &warnings {
            lines.push(format!("    → {}", w));
        }
    }

    let failed = entry
        .scan_details
        .iter()
        .find(|d| d.starts_with("validator-failed"));
    let scanned = entry.scan_details.iter().find(|d| d.starts_with("scanned"));
    let short = entry
        .scan_details
        .iter()
        .find(|d| d.starts_with("content-too-short-for-validator"));

    if failed.is_some() {
        lines.push(
            "• validator: ❌ FAILED — see raw response for reason (HTTP error, abort, or empty content)"
                .to_string(),
        );
    } else if !warnings.is_empty() || entry.scan_result == "warning" {
        // Discriminant is scan_result, not warning-prefix matching — otherwise
        // warning entries with non-standard detail strings fall through to
        // "stage state unknown".
        lines.push("• validator: ⚠ issues found".to_string());
    } else if entry.scan_result == "error" {
        // Error state (e.g., scan-fast-timeout) takes precedence over the
        // "scanned" prefix — the scan STARTED but didn't complete cleanly.
        lines.push(format!(
            "• validator: ⚠ scan error (scan_result={})",
            entry.scan_result
        ));
    } else if entry.scan_result == "blocked" {
        lines.push("• validator: ⛔ blocked — hallucination detected".to_string());
    } else if scanned.is_some() && entry.scan_result == "clean" {
        // Only claim success when scan_result actually confirms clean.
        lines.push("• validator: ✓ ran successfully, no issues found".to_string());
    } else if let Some(s) = short {
        lines.push(format!("• validator: ⊘ skipped ({})", s));
    } else if entry.scan_result == "skipped" {
        lines.push("• validator: ⊘ skipped (scan did not run)".to_string());
    } else if entry.scan_result == "clean" {
        lines.push("• validator: ✓ ran successfully, no issues found".to_string());
    } else if scanned.is_some() {
        // "scanned" prefix without a clean scan_result — partial scan ran
        // but final verdict is neither clean nor warning nor error.
        lines.push(format!(
            "• validator: ? partial scan (scan_result={})",
            entry.scan_result
        ));
    } else {
        lines.push(format!(
            "• validator: ? (stage state unknown — scan_result={})",
            entry.scan_result
        ));
    }

    lines.push(format!("• verdict: {}", entry.scan_result));
    lines
}

/// Human-readable explanation when no validator_response was captured.
fn explain_no_body(entry: &RecentEntryDto) -> String {
    let detail = entry.scan_details.join(" | ");
    // Show ALL scan_details as the explanation — no filtering by prefix.
    if !entry.scan_details.is_empty() {
        let mut out = String::new();
        for finding in entry.scan_details.iter().take(12) {
            out.push_str(&format!("  • {}\n", finding));
        }
        let more = entry.scan_details.len().saturating_sub(12);
        if more > 0 {
            out.push_str(&format!("  • ...and {} more\n", more));
        }
        return out.trim_end().to_string();
    }
    if detail.contains("scan-fast-timeout") {
        return "Scan timed out (5s budget for fast scan). The request was forwarded but not fully analyzed. \
                Increase content size budget or check daemon load."
            .to_string();
    }
    if detail.contains("too short to scan") {
        return "Response was too short to scan (< 50 chars). No checks performed — too little content to verify."
            .to_string();
    }
    if detail.contains("content-too-short-for-validator") {
        let chars = detail
            .find("content-too-short-for-validator (")
            .map(|i| {
                let rest = &detail[i + "content-too-short-for-validator (".len()..];
                rest.split(')').next().unwrap_or("")
            })
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "?".to_string());
        return format!(
            "Response was {} chars — below the 200-char threshold for LLM validation.\n\
             Local API claim check ran and found no suspicious function calls.\n\
             Validator skipped: not enough content for the LLM to reason about.\n\
             Marked clean: no hallucinated APIs detected by local pattern matching.",
            chars
        );
    }
    if detail.contains("validator-failed") || detail.contains("demoted") {
        return "Validator ran but did not produce a usable verdict (timeout, rate limit, or parse error).\n\
                This response was NOT verified by the LLM.\n\
                Result marked skipped — not confirmed safe, just couldn't check."
            .to_string();
    }
    if detail.contains("streaming passthrough") {
        return "Response was streamed and scanner could not buffer enough content to scan.\n\
                No checks performed."
            .to_string();
    }
    if entry.scan_result == "clean" {
        return "No validator response available.\n\
                Local API claim check found no suspicious calls.\n\
                Response marked clean based on local checks only."
            .to_string();
    }
    if entry.scan_result == "error" {
        return "Scan pipeline returned an error state. \
                See scan stages above for the specific failure (timeout, network, or parse)."
            .to_string();
    }
    "Validator did not run. See scan stages above for details.".to_string()
}

// ─── Rendering ─────────────────────────────────────────────────────────

fn mode_label(m: RoutingMode) -> &'static str {
    match m {
        RoutingMode::Sleev => "SLEEV",
        RoutingMode::Direct => "DIRECT",
        RoutingMode::Custom => "CUSTOM",
    }
}

fn target_url_of(cfg: &ANUBISConfig) -> String {
    match cfg.routing.mode {
        RoutingMode::Sleev => "http://127.0.0.1:17321".to_string(),
        RoutingMode::Direct => String::new(),
        RoutingMode::Custom => cfg.routing.custom_url.clone(),
    }
}

fn ui(f: &mut Frame, state: &mut TuiState) {
    let area = f.area();

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .padding(Padding::symmetric(1, 0));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    // Header (2 lines) + body (fill) + footer (1 line)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(inner);

    render_header(f, chunks[0], state);
    match state.tab {
        Tab::Overview => render_overview(f, chunks[1], state),
        Tab::Setup => {
            render_setup(f, chunks[1], state);
        }
    }
    render_footer(f, chunks[2], state);

    // Popup overlays last so it sits above all other content.
    if state.popup.is_some() {
        render_popup(f, state);
    }
}

fn render_header(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    // Row 1: status line (left) + connection status (right)
    let status_line = if state.connected {
        Line::from(vec![
            Span::styled(format!("ANUBIS proxy v{}", VERSION), heading_style()),
            Span::styled(" · ", dim_style()),
            Span::styled(
                state
                    .config
                    .as_ref()
                    .map(|c| mode_label(c.routing.mode))
                    .unwrap_or("SLEEV"),
                heading_style(),
            ),
            Span::styled(
                state
                    .config
                    .as_ref()
                    .map(|c| {
                        let t = target_url_of(c);
                        if t.is_empty() {
                            String::new()
                        } else {
                            format!(" → {}", short_url(&t))
                        }
                    })
                    .unwrap_or_default(),
                Style::default(),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(format!("ANUBIS proxy v{}", VERSION), heading_style()),
            Span::styled("  ⚠ connecting to daemon…", Style::default().fg(WARN)),
        ])
    };
    f.render_widget(Paragraph::new(status_line), rows[0]);

    // Row 2: [Overview] [Setup] spacer + version info
    let bar = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Min(0),
        ])
        .split(rows[1]);

    let overview_active = state.tab == Tab::Overview;
    let setup_active = state.tab == Tab::Setup;

    let tab_style_active = heading_style();
    let tab_style_inactive = muted_style();

    let overview_style = if overview_active {
        tab_style_active
    } else {
        tab_style_inactive
    };
    let setup_style = if setup_active {
        tab_style_active
    } else {
        tab_style_inactive
    };

    let overview_para = Paragraph::new(Line::from(vec![
        Span::styled(
            if overview_active { "[" } else { " " },
            Style::default().fg(PURPLE),
        ),
        Span::styled("Overview", overview_style),
        Span::styled(
            if overview_active { "]" } else { " " },
            Style::default().fg(PURPLE),
        ),
    ]));
    f.render_widget(overview_para, bar[0]);
    state.rects.tab_overview = bar[0];

    let setup_para = Paragraph::new(Line::from(vec![
        Span::styled(
            if setup_active { "[" } else { " " },
            Style::default().fg(PURPLE),
        ),
        Span::styled("Setup", setup_style),
        Span::styled(
            if setup_active { "]" } else { " " },
            Style::default().fg(PURPLE),
        ),
    ]));
    f.render_widget(setup_para, bar[1]);
    state.rects.tab_setup = bar[1];

    let mut right_parts = vec![];

    // License info (tier + email)
    let lic_state = crate::license::load_state();
    match lic_state.tier {
        crate::license::LicenseTier::Licensed => {
            if let Some(label) = &lic_state.tier_label {
                right_parts.push(Span::styled(format!("{} ", label), dim_style()));
            } else {
                right_parts.push(Span::styled("Licensed ", dim_style()));
            }
            if let Some(email) = &lic_state.email {
                right_parts.push(Span::styled(email, dim_style()));
                right_parts.push(Span::raw(" · "));
            }
        }
        _ => {}
    }

    // Trial days remaining
    if let Some(days) = trial::days_remaining_str() {
        let warn = days.starts_with("expired") || days.contains("1 day");
        let trial_style = if warn {
            Style::default().fg(WARN)
        } else {
            dim_style()
        };
        right_parts.push(Span::styled("trial ", dim_style()));
        right_parts.push(Span::styled(days, trial_style));
    }

    if right_parts.is_empty() {
        right_parts.push(Span::raw(""));
    }
    f.render_widget(
        Paragraph::new(Line::from(right_parts)).alignment(Alignment::Right),
        bar[2],
    );
}

fn render_footer(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let quit_para = Paragraph::new(Line::from(vec![
        Span::styled("[", Style::default().fg(ERR)),
        Span::styled(
            "quit",
            Style::default().fg(ERR).add_modifier(Modifier::BOLD),
        ),
        Span::styled("]", Style::default().fg(ERR)),
    ]));
    f.render_widget(quit_para, cols[0]);
    state.rects.quit_btn = cols[0];

    let hint = match state.tab {
        Tab::Overview => "Tab/click navigate · ↑↓/jk scroll requests · PgUp/PgDn scroll validator · 1/2 switch tabs · q quit",
        Tab::Setup => "Tab/1/2 navigate · q quit · scanner config edits the YAML directly",
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(hint, dim_style()))),
        cols[1],
    );
}

fn panel_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .title_top(format!(" {} ", title))
        .padding(Padding::symmetric(1, 0))
}

// ─── Overview tab ──────────────────────────────────────────────────────

fn render_overview(f: &mut Frame, area: Rect, state: &mut TuiState) {
    // Left column (Overview stats + Recent Requests) | Right column (Scan Details)
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left_col_gap = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(16), Constraint::Min(0)])
        .split(cols[0]);

    render_overview_panel(f, left_col_gap[0], state);
    render_recent_requests(f, left_col_gap[1], state);
    render_scan_details(f, cols[1], state);
}

fn render_overview_panel(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let st = &state.stats;
    let block = panel_block("Overview");
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split inner: stats paragraph + 1-line button row at bottom
    let panel_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let stats_area = panel_layout[0];
    let btn_area = panel_layout[1];

    let mut lines: Vec<Line> = Vec::new();

    // ── TOKENS ──
    lines.push(Line::from(Span::styled("TOKENS", heading_style())));
    lines.push(stat_kv(
        "throughput",
        &format!(
            "{}  ({} in · {} out · {} rsn)",
            fmt_tokens(st.total_tokens),
            fmt_tokens(st.prompt_tokens),
            fmt_tokens(st.completion_tokens),
            fmt_tokens(st.reasoning_tokens)
        ),
        None,
    ));
    lines.push(stat_kv(
        "scanner",
        &format!(
            "{}  ({} calls)",
            fmt_tokens(st.validator_tokens),
            st.validator_calls
        ),
        None,
    ));
    lines.push(divider_line(inner.width));

    // ── PIPELINE | VERDICTS ──
    let half = inner.width as usize / 2;
    let pipe_label = "PIPELINE";
    let verd_label = "VERDICTS";
    let mut header_spans = Vec::new();
    header_spans.push(Span::styled(pipe_label, heading_style()));
    header_spans.push(Span::raw(
        " ".repeat(half.saturating_sub(pipe_label.chars().count())),
    ));
    header_spans.push(Span::styled(verd_label, heading_style()));
    lines.push(Line::from(header_spans));

    let pipeline: Vec<(&str, String, Option<Color>)> = vec![
        ("total", st.total_requests.to_string(), None),
        ("scanned", st.local_check_count.to_string(), None),
        ("  local", st.local_check_count.saturating_sub(st.agent_check_count).to_string(), Some(OK)),
        ("  agent", st.agent_check_count.to_string(), Some(WARN)),
        ("not scan", (st.total_requests - st.local_check_count).to_string(), Some(DIM_FG)),
        ("docs", st.docs_hit_count.to_string(), None),
    ];
    let verdicts: Vec<(&str, String, Color)> = vec![
        (
            "clean",
            format!(
                "{}  ({}%)",
                st.clean_count,
                pct(st.clean_count, st.total_requests)
            ),
            OK,
        ),
        (
            "warning",
            format!(
                "{}  ({}%)",
                st.warning_count,
                pct(st.warning_count, st.total_requests)
            ),
            WARN,
        ),
        (
            "errors",
            format!(
                "{}  ({}%)",
                st.total_errors,
                pct(st.total_errors, st.total_requests)
            ),
            ERR,
        ),
        (
            "avg risk",
            format!(
                "{}/10  (over {} scans)",
                {
                    let avg = if st.risk_score_count > 0 {
                        st.risk_score_sum / (st.risk_score_count as f64)
                    } else {
                        0.0
                    };
                    ((avg * 10.0).round() as i32).clamp(0, 10)
                },
                st.risk_score_count
            ),
            // Color by avg: green 0-2, yellow 3-6, red 7-10
            {
                let avg = if st.risk_score_count > 0 {
                    st.risk_score_sum / (st.risk_score_count as f64)
                } else {
                    0.0
                };
                let scaled = (avg * 10.0).round() as i32;
                match scaled.clamp(0, 10) {
                    0..=2 => OK,
                    3..=6 => WARN,
                    _ => ERR,
                }
            },
        ),
    ];
    let row_count = pipeline.len().max(verdicts.len());
    for i in 0..row_count {
        let mut spans = Vec::new();
        let pipe_width: usize;
        if let Some((label, val, color)) = pipeline.get(i) {
            spans.push(Span::styled(format!("{:<9}", label), dim_style()));
            spans.push(Span::styled(
                val.clone(),
                color.map(|c| Style::default().fg(c)).unwrap_or_default(),
            ));
            pipe_width = 9 + val.chars().count();
        } else {
            spans.push(Span::raw(" ".repeat(half)));
            pipe_width = half;
        }
        let pad_n = half.saturating_sub(pipe_width);
        spans.push(Span::raw(" ".repeat(pad_n)));
        if let Some((label, val, color)) = verdicts.get(i) {
            spans.push(Span::styled(format!("{:<9}", label), dim_style()));
            spans.push(Span::styled(val.clone(), Style::default().fg(*color)));
        }
        lines.push(Line::from(spans));
    }

    f.render_widget(Paragraph::new(lines), stats_area);

    // ── Clear-log button under PIPELINE section ──
    let clear_para = Paragraph::new(Line::from(vec![
        Span::styled("[", Style::default().fg(MUTED)),
        Span::styled("clear log", Style::default().fg(WARN)),
        Span::styled("]", Style::default().fg(MUTED)),
    ]));
    f.render_widget(clear_para, btn_area);
    state.rects.clear_btn = btn_area;
}

/// Width of "label   value" (label padded to 9 + value chars).
#[allow(dead_code)]
fn stat_line_width(p: Option<&(&str, String, Option<Color>)>) -> usize {
    match p {
        None => 0,
        Some((_label, val, _)) => 9 + val.chars().count(),
    }
}

fn stat_kv(label: &str, value: &str, color: Option<Color>) -> Line<'static> {
    let value_style = color.map(|c| Style::default().fg(c)).unwrap_or_default();
    Line::from(vec![
        Span::styled(format!("{:<9}", label), dim_style()),
        Span::styled(value.to_string(), value_style),
    ])
}

fn divider_line(width: u16) -> Line<'static> {
    Line::from(Span::styled(
        "─".repeat(width.saturating_sub(0) as usize),
        Style::default().fg(BORDER),
    ))
}

// ─── Recent Requests ───────────────────────────────────────────────────

fn render_recent_requests(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let block = panel_block("Recent Requests  (click to inspect)");
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Header row (full width — clear-log button moved to Overview panel)
    let cw_time = 8usize;
    let cw_model = 12usize;
    let cw_tokens = 6usize;
    let cw_latency = 7usize;
    let cw_status = 4usize;
    let cw_risk = 6usize; // "10/10" + padding
    let cw_conf = 7usize; // "C10/10" + padding

    let header = format!(
        "  {} {} {} {} {} {} {} result",
        pad("time", cw_time),
        pad("model", cw_model),
        pad("tok", cw_tokens),
        pad("lat", cw_latency),
        pad("st", cw_status),
        pad("risk", cw_risk),
        pad("conf", cw_conf),
    );
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(header, dim_style()))),
        inner,
    );

    // Body rect (below header)
    let body = Rect {
        x: inner.x,
        y: inner.y + 1,
        width: inner.width,
        height: inner.height.saturating_sub(1),
    };

    let recent = &state.stats.recent_entries;
    if recent.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled("(no requests yet)", dim_style()))),
            body,
        );
        state.rects.recent_body = body;
        return;
    }

    let visible = body.height as usize;
    let total = recent.len();
    if visible > 0 && state.recent_scroll + visible > total {
        state.recent_scroll = total.saturating_sub(visible);
    }

    let start = state.recent_scroll.min(total.saturating_sub(1));
    let end = (start + visible).min(total);

    let mut lines: Vec<Line> = Vec::new();
    for idx in start..end {
        let r = &recent[idx];
        let is_selected = state.selected_request_id.as_deref() == Some(r.request_id.as_str());
        let marker = if is_selected { "▶" } else { " " };
        let model_display: String = if r.model.is_empty() {
            "—".to_string()
        } else if r.model.chars().count() > cw_model {
            let cut: String = r.model.chars().take(cw_model - 1).collect();
            format!("{}…", cut)
        } else {
            r.model.clone()
        };
        let tokens_display =
            if r.total_tokens == 0 && r.prompt_tokens == 0 && r.completion_tokens == 0 {
                "—".to_string()
            } else {
                fmt_tokens(r.total_tokens)
            };
        let latency_display = if r.latency_ms == 0 {
            "—".to_string()
        } else {
            fmt_latency_ms(r.latency_ms)
        };
        let status_display = if r.status == 0 {
            "—".to_string()
        } else {
            r.status.to_string()
        };

        let row_style = if is_selected {
            Style::default().fg(PURPLE).add_modifier(Modifier::BOLD)
        } else {
            // Tint the whole row by risk if non-default — draws eye to
            // medium/high-risk entries in the list.
            if r.scan_result != "skipped" && r.risk_score >= 0.7 {
                Style::default().fg(Color::Red)
            } else if r.scan_result != "skipped" && r.risk_score >= 0.3 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            }
        };

        let risk_display = if r.scan_result == "skipped" {
            "—".to_string()
        } else {
            fmt_risk(r.risk_score)
        };

        // Confidence: same dash treatment as risk for skipped scans. For
        // real scans, format as C0/10-C10/10 to distinguish from risk.
        let conf_display = if r.scan_result == "skipped" {
            "—".to_string()
        } else {
            fmt_confidence(r.confidence)
        };

        let row = format!(
            "{} {} {} {} {} {} {} {} {}",
            marker,
            pad(&fmt_time(&r.ts), cw_time),
            pad(&model_display, cw_model),
            pad(&tokens_display, cw_tokens),
            pad(&latency_display, cw_latency),
            pad(&status_display, cw_status),
            pad(&risk_display, cw_risk),
            pad(&conf_display, cw_conf),
            r.scan_result
        );
        lines.push(Line::from(Span::styled(row, row_style)));
    }

    f.render_widget(Paragraph::new(lines), body);
    state.rects.recent_body = body;
}

// ─── Scan Details ──────────────────────────────────────────────────────

fn render_scan_details(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let block = panel_block("Scan Details");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let selected = match state.selected_entry() {
        Some(e) => e,
        None => {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "(click a request to inspect)",
                    dim_style(),
                ))),
                inner,
            );
            state.rects.validator_body = Rect::ZERO;
            return;
        }
    };

    let result_color = scan_result_color(&selected.scan_result);
    let _validator_model = state
        .config
        .as_ref()
        .map(|c| c.scanner.model.clone())
        .unwrap_or_else(|| "—".to_string());
    let stage_lines = summarize_scan_stages(selected);

    // Header lines (fixed height)
    let mut header: Vec<Line> = Vec::new();
    header.push(Line::from(vec![
        Span::styled("result:   ", dim_style()),
        Span::styled(
            selected.scan_result.clone(),
            Style::default().fg(result_color),
        ),
    ]));
    header.push(Line::from(vec![
        Span::styled("model:    ", dim_style()),
        Span::styled(
            if selected.model.is_empty() {
                "—".to_string()
            } else {
                selected.model.clone()
            },
            Style::default(),
        ),
    ]));
    header.push(Line::from(vec![
        Span::styled("tokens:   ", dim_style()),
        Span::styled(
            if selected.total_tokens == 0
                && selected.prompt_tokens == 0
                && selected.completion_tokens == 0
            {
                "—".to_string()
            } else {
                fmt_tokens(selected.total_tokens)
            },
            Style::default(),
        ),
    ]));
    header.push(Line::from(vec![
        Span::styled("latency:  ", dim_style()),
        Span::styled(
            if selected.latency_ms == 0 {
                "—".to_string()
            } else {
                fmt_latency_ms(selected.latency_ms)
            },
            Style::default(),
        ),
    ]));
    header.push(divider_line(inner.width));
    header.push(Line::from(Span::styled("scan stages:", heading_style())));
    for line in &stage_lines {
        header.push(Line::from(Span::styled(line.clone(), dim_style())));
    }
    header.push(divider_line(inner.width));

    // Only show parsed warnings + explanation — never raw validator JSON.
    let body = selected.validator_response.trim();
    if body.is_empty() {
        header.push(Line::from(Span::styled("explanation:", heading_style())));
        for line in explain_no_body(selected).split('\n') {
            header.push(Line::from(Span::styled(
                line.to_string(),
                Style::default().fg(MUTED),
            )));
        }
    }

    f.render_widget(
        Paragraph::new(header).wrap(Wrap { trim: false }),
        inner,
    );
    state.rects.validator_body = Rect::ZERO;
}

// ─── Setup tab (basic — degrades when config not exposed by daemon) ────

/// Detect which provider the current scanner base_url points to.
fn detect_scanner_provider(base_url: &str) -> String {
    let url = base_url.to_lowercase();
    if url.contains("127.0.0.1") || url.contains("localhost") {
        if url.contains("11434") { return "ollama".into(); }
        return "zai-coding".into(); // proxy URL default
    }
    if url.contains("z.ai/api/coding") { return "zai-coding".into(); }
    if url.contains("z.ai") { return "zai".into(); }
    if url.contains("anthropic.com") { return "anthropic".into(); }
    if url.contains("openai.com") { return "openai".into(); }
    if url.contains("googleapis.com") { return "google".into(); }
    if url.contains("openrouter.ai") { return "openrouter".into(); }
    if url.contains("deepseek.com") { return "deepseek".into(); }
    if url.contains("mistral.ai") { return "mistral".into(); }
    "custom".into()
}

/// Map harness provider IDs to canonical provider IDs for matching.
/// Harnesses use compound names like "zai-coding-plan" which need to
/// match the canonical "zai" from detect_scanner_provider.
fn canonicalize_provider_id(harness_id: &str) -> String {
    let h = harness_id.to_lowercase();
    // z.ai variants
    if h.starts_with("zai") || h.starts_with("z-ai") || h.starts_with("z_ai") {
        return "zai".into();
    }
    // Anthropic variants
    if h.starts_with("anthropic") || h.contains("claude") {
        return "anthropic".into();
    }
    // OpenAI variants (but not "openai-compatible" generic)
    if h.starts_with("openai") && !h.contains("compatible") {
        return "openai".into();
    }
    // Google variants
    if h.starts_with("google") || h.starts_with("gemini") {
        return "google".into();
    }
    // OpenRouter
    if h.starts_with("openrouter") {
        return "openrouter".into();
    }
    // DeepSeek
    if h.starts_with("deepseek") {
        return "deepseek".into();
    }
    // Mistral
    if h.starts_with("mistral") {
        return "mistral".into();
    }
    // Ollama (local, no API key needed)
    if h.starts_with("ollama") {
        return "ollama".into();
    }
    // Unknown — keep as-is
    harness_id.to_string()
}

/// Collect provider list from harnesses (routed providers) + CUSTOM.
/// Provider IDs are canonicalized so harness names like "zai-coding-plan"
/// match detected provider "zai".
/// Static list of all known scanner providers with endpoint shown.
fn collect_scanner_providers(_harnesses: &[HarnessStatus]) -> Vec<(String, String)> {
    vec![
        ("zai-coding".into(),  "Z.AI Coding Plan → api.z.ai/api/coding/paas/v4".into()),
        ("zai".into(),         "Z.AI → api.z.ai/api/paas/v4".into()),
        ("anthropic".into(),   "Anthropic → api.anthropic.com".into()),
        ("openai".into(),      "OpenAI → api.openai.com/v1".into()),
        ("google".into(),      "Google → generativelanguage.googleapis.com/v1beta".into()),
        ("ollama".into(),      "Ollama → localhost:11434/v1".into()),
        ("deepseek".into(),    "DeepSeek → api.deepseek.com".into()),
        ("mistral".into(),     "Mistral → api.mistral.ai/v1".into()),
        ("openrouter".into(),  "OpenRouter → openrouter.ai/api/v1".into()),
        ("custom".into(),      "CUSTOM (enter endpoint + model manually)".into()),
    ]
}

/// Hardcoded model presets per provider.
/// First entry is the default when provider is selected.
fn models_for_provider(provider: &str) -> Vec<(&'static str, &'static str)> {
    match provider {
        "zai" | "z.ai" => vec![
            ("glm-4.7-flash", "https://api.z.ai/api/paas/v4"),
            ("glm-4.7",       "https://api.z.ai/api/paas/v4"),
            ("glm-4.6",       "https://api.z.ai/api/paas/v4"),
        ],
        "zai-coding" => vec![
            ("glm-4.7-flash", "https://api.z.ai/api/coding/paas/v4"),
            ("glm-4.7",       "https://api.z.ai/api/coding/paas/v4"),
            ("glm-4.6",       "https://api.z.ai/api/coding/paas/v4"),
        ],
        "anthropic" => vec![
            ("claude-sonnet-4-5-20250514", "https://api.anthropic.com"),
            ("claude-opus-4-20250514",     "https://api.anthropic.com"),
            ("claude-haiku-3-5-20241022",  "https://api.anthropic.com"),
        ],
        "openai" => vec![
            ("gpt-4o",      "https://api.openai.com/v1"),
            ("gpt-4o-mini", "https://api.openai.com/v1"),
            ("o3-mini",     "https://api.openai.com/v1"),
        ],
        "google" | "google-genai" => vec![
            ("gemini-2.0-flash", "https://generativelanguage.googleapis.com/v1beta"),
            ("gemini-1.5-pro",   "https://generativelanguage.googleapis.com/v1beta"),
        ],
        "openrouter" => vec![
            ("auto", "https://openrouter.ai/api/v1"),
        ],
        "deepseek" => vec![
            ("deepseek-chat", "https://api.deepseek.com"),
            ("deepseek-reasoner", "https://api.deepseek.com"),
        ],
        "mistral" => vec![
            ("mistral-large-latest", "https://api.mistral.ai/v1"),
            ("mistral-small-latest", "https://api.mistral.ai/v1"),
        ],
        "ollama" => vec![
            ("qwen2.5-coder:7b",  "http://localhost:11434/v1"),
            ("llama3.2",          "http://localhost:11434/v1"),
            ("deepseek-r1:7b",    "http://localhost:11434/v1"),
        ],
        _ => vec![],
    }
}

/// Get the base URL for a provider (used for display in radio buttons).
fn provider_base_url(provider: &str) -> &str {
    models_for_provider(provider)
        .first()
        .map(|(_, url)| *url)
        .unwrap_or("")
}

/// Return model IDs for a provider, preferring live-fetched models from
/// the provider's /models endpoint when available. Falls back to hardcoded
/// presets.
///
/// - If `live_models` is non-empty AND `provider == current_provider`:
///   return live models (just the IDs, no URL needed — same provider URL)
/// - Otherwise: return preset model IDs from models_for_provider()
fn live_or_preset_models(
    provider: &str,
    live_models: &[String],
    current_provider: &str,
) -> Vec<String> {
    let presets: Vec<String> = models_for_provider(provider)
        .iter()
        .map(|(id, _)| id.to_string())
        .collect();
    if !live_models.is_empty() && provider == current_provider {
        // Merge live + presets, dedup, sorted.
        let mut all: std::collections::BTreeSet<String> = live_models.iter().cloned().collect();
        for p in &presets { all.insert(p.clone()); }
        all.into_iter().collect()
    } else {
        presets
    }
}

/// Build flat list of selectable items in the Setup tab.
/// Returns (text, highlighted) pairs — cursor only stops on items where action.is_some().
fn build_setup_items(state: &TuiState) -> Vec<(String, bool)> {
    let mut items: Vec<(String, bool)> = Vec::new();
    let cfg = match &state.config {
        Some(c) => c,
        None => return items,
    };

    // ── Harnesses ──
    items.push(("Harnesses".to_string(), false));

    if state.harnesses.is_empty() {
        items.push(("  (no harnesses detected)".to_string(), false));
    } else {
        for h in &state.harnesses {
            if !h.installed {
                continue;
            }
            let routed = h.providers.iter().filter(|p| p.routed).count();
            let total = h.providers.len();
            items.push((format!("  {} ({}/{})", h.name, routed, total), false));
            for p in &h.providers {
                let glyph = if p.routed { "[✓]" } else { "[ ]" };
                let url = if p.routed {
                    short_url(&state.daemon_url)
                } else if !p.original_url.is_empty() {
                    short_url(&p.original_url)
                } else {
                    "(unknown)".to_string()
                };
                items.push((format!("    {} {} → {}", glyph, p.name, url), true));
            }
        }
    }

    items.push(("".to_string(), false));

    // ── Routing ──
    items.push(("Upstream".to_string(), false));
    let modes = [
        (RoutingMode::Sleev, "Sleev (auto-discovered)"),
        (RoutingMode::Direct, "Direct (route by model)"),
        (RoutingMode::Custom, "Custom URL"),
    ];
    let target = target_url_of(cfg);
    for (mode, label) in &modes {
        let active = cfg.routing.mode == *mode;
        let glyph = if active { "(•)" } else { "( )" };
        match mode {
            RoutingMode::Sleev => {
                items.push((
                    format!("  {} {}  → {}", glyph, label, short_url(&target)),
                    true,
                ));
            }
            RoutingMode::Direct => {
                if active {
                    // Radio without inline detail; sub-rows below list each URL.
                    items.push((format!("  {} {}", glyph, label), true));
                    let mut url_count = 0usize;
                    for h in &state.harnesses {
                        if !h.installed {
                            continue;
                        }
                        for p in &h.providers {
                            url_count += 1;
                            // harness.rs already resolved proxy-loop URLs via
                            // backup → models.dev registry. If the URL is STILL a
                            // loop here, resolution failed — surface "(needs URL)"
                            // instead of showing the user an Anubis→Anubis loop.
                            let dest = if p.original_url.is_empty() {
                                "(no URL configured)".to_string()
                            } else if crate::harness::is_proxy_loop(
                                &p.original_url,
                                &state.daemon_url,
                            ) {
                                "(needs URL)".to_string()
                            } else {
                                format!("→ {}", short_url(&p.original_url))
                            };
                            items.push((format!("      {} {}", p.name, dest), false));
                        }
                    }
                    if url_count == 0 {
                        items.push((
                            "      (no upstream URLs configured)".to_string(),
                            false,
                        ));
                    }
                } else {
                    // Inactive: show upstream count as a hint.
                    let count: usize = state
                        .harnesses
                        .iter()
                        .filter(|h| h.installed)
                        .flat_map(|h| h.providers.iter())
                        .filter(|p| !p.original_url.is_empty())
                        .count();
                    let summary = if count > 0 {
                        format!("  ({} upstreams)", count)
                    } else {
                        String::new()
                    };
                    items.push((format!("  {} {}{}", glyph, label, summary), true));
                }
            }
            RoutingMode::Custom => {
                let detail = if cfg.routing.custom_url.is_empty() {
                    if active {
                        "  → (press 'e' to set URL)".to_string()
                    } else {
                        "  → (not set)".to_string()
                    }
                } else {
                    format!("  → {}", short_url(&cfg.routing.custom_url))
                };
                items.push((format!("  {} {}{}", glyph, label, detail), true));
            }
        }
    }

    items.push(("".to_string(), false));

    // ── Scanner ──
    items.push(("Scanner".to_string(), false));
    let current_provider = detect_scanner_provider(&cfg.scanner.base_url);
    let providers = collect_scanner_providers(&state.harnesses);
    // Show active provider name
    let provider_name = providers
        .iter()
        .find(|(pid, _)| pid == &current_provider)
        .map(|(_, name)| name.clone())
        .unwrap_or_else(|| "CUSTOM".to_string());
    items.push((format!("  Provider: {}  ▸", provider_name), true));
    // When custom, show inline editable endpoint + model rows.
    if current_provider == "custom" {
        let url_display = if state.editing_scanner_url {
            format!("  Endpoint: {}█", state.scanner_url_buf)
        } else {
            format!("  Endpoint: {}  ▸", cfg.scanner.base_url)
        };
        items.push((url_display, true));
        let model_display = if state.editing_scanner_model {
            format!("  Model: {}█", state.scanner_model_buf)
        } else {
            format!("  Model: {}  ▸", cfg.scanner.model)
        };
        items.push((model_display, true));
    } else {
        items.push((format!("  Model: {}  ▸", cfg.scanner.model), true));
    }

    items.push(("".to_string(), false));

    // ── Block mode ──
    items.push(("Safety".to_string(), false));
    let block_glyph = if cfg.scanner.block_on_hallucination {
        "[✓]"
    } else {
        "[ ]"
    };
    items.push((
        format!(
            "  {} Block hallucinated tool calls",
            block_glyph
        ),
        true,
    ));
    if cfg.scanner.block_on_hallucination {
        items.push((
            "      → tool calls with hallucinated APIs are replaced".to_string(),
            false,
        ));
        items.push((
            "        with reasoning; agent retries on next turn".to_string(),
            false,
        ));
    }

    let inject_glyph = if cfg.scanner.auto_inject_docs {
        "[✓]"
    } else {
        "[ ]"
    };
    items.push((
        format!(
            "  {} Auto-inject cached API docs",
            inject_glyph
        ),
        true,
    ));
    if cfg.scanner.auto_inject_docs {
        items.push((
            "      → library refs detected, symbol cache queried,".to_string(),
            false,
        ));
        items.push((
            "        focused API reference injected as system message".to_string(),
            false,
        ));
    }

    let verify_glyph = if cfg.scanner.post_edit_verify {
        "[✓]"
    } else {
        "[ ]"
    };
    items.push((
        format!(
            "  {} Post-edit verification (tsc/cargo/py_compile)",
            verify_glyph
        ),
        true,
    ));
    if cfg.scanner.post_edit_verify {
        items.push((
            "      → after edit tool calls, run compiler/linter;".to_string(),
            false,
        ));
        items.push((
            "        results injected as context on next turn".to_string(),
            false,
        ));
    }

    items
}

fn render_setup(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let block = panel_block("Setup");
    let inner = block.inner(area);
    f.render_widget(block, area);
    // Record the actual content rect for mouse hit-testing so clicks map
    // 1:1 to rendered rows. List widget renders exactly one row per item
    // (no wrap), so visual_row == item_index from inner.top().
    state.rects.setup_body = inner;

    let _cfg = match &state.config {
        Some(c) => c,
        None => {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "(connecting to daemon...)",
                    dim_style(),
                ))),
                inner,
            );
            return;
        }
    };

    let items = build_setup_items(state);

    // Compute selectable indices — snap current ListState selection onto a
    // selectable item so navigation never lands on a header/separator/detail.
    let selectable_indices: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, (_, sel))| *sel)
        .map(|(i, _)| i)
        .collect();
    if selectable_indices.is_empty() {
        state.setup_state.select(None);
    } else {
        let cur = state.setup_state.selected().unwrap_or(selectable_indices[0]);
        // If current selection is non-selectable or out of bounds, snap to
        // the nearest selectable item (prefer forward).
        let needs_snap = cur >= items.len() || !selectable_indices.contains(&cur);
        if needs_snap {
            let nearest = selectable_indices
                .iter()
                .min_by_key(|&&i| {
                    let d = i as i64 - cur as i64;
                    if d >= 0 { d } else { -d }
                })
                .copied()
                .unwrap_or(selectable_indices[0]);
            state.setup_state.select(Some(nearest));
        }
    }

    // Build ListItems with per-item styling. Headers (non-selectable, no
    // leading space) get heading_style; detail sub-rows (start with "      →")
    // get dim style; everything else default.
    let list_items: Vec<ListItem> = items
        .iter()
        .map(|(text, sel)| {
            let mut item = ListItem::new(text.clone());
            if !sel {
                if text.starts_with("      →") {
                    item = item.style(Style::default().fg(Color::DarkGray));
                } else if !text.is_empty() && !text.starts_with(' ') {
                    item = item.style(heading_style());
                }
            }
            item
        })
        .collect();

    let list = List::new(list_items)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, inner, &mut state.setup_state);
}

/// Render the dropdown popup overlay (provider/model selection) centered on
/// the screen, above all other content. Opens via handle_setup_enter for
/// Scanner entries; closed on Enter (apply) or Esc (cancel).
fn render_popup(f: &mut Frame, state: &mut TuiState) {
    let popup = match &state.popup {
        Some(p) => p.clone(),
        None => return,
    };
    let area = f.area();

    // CustomUrlEdit: single-line text input field with a cursor block.
    if matches!(popup.kind, PopupKind::CustomUrlEdit) {
        let width = 70u16.min(area.width.saturating_sub(4));
        let height = 3u16;
        let popup_rect = Rect::new(
            area.x + (area.width.saturating_sub(width)) / 2,
            area.y + (area.height.saturating_sub(height)) / 2,
            width,
            height,
        );
        f.render_widget(Clear, popup_rect);
        let block = panel_block(&popup.title);
        let inner = block.inner(popup_rect);
        f.render_widget(block, popup_rect);
        let text = popup.text_input.as_deref().unwrap_or("");
        let display = format!("{}█", text);
        f.render_widget(Paragraph::new(display), inner);
        state.rects.popup_body = inner;
        return;
    }

    let content_h = popup.items.len() as u16 + 3;
    let width = 60u16.min(area.width.saturating_sub(4));
    let height = content_h.min(area.height.saturating_sub(4));
    let popup_rect = Rect::new(
        area.x + (area.width.saturating_sub(width)) / 2,
        area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    );
    f.render_widget(Clear, popup_rect);
    let block = panel_block(&popup.title);
    let inner = block.inner(popup_rect);
    f.render_widget(block, popup_rect);
    state.rects.popup_body = inner;

    let lines: Vec<Line> = popup
        .items
        .iter()
        .enumerate()
        .map(|(i, (display, _))| {
            if i == popup.selected {
                Line::from(Span::styled(format!("▶ {}", display), heading_style()))
            } else {
                Line::from(format!("  {}", display))
            }
        })
        .collect();

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

// ─── Event handling ────────────────────────────────────────────────────

/// Actions for selectable Setup items, in same order as build_setup_items.
enum SetupAction {
    ToggleProvider {
        harness_id: String,
        provider_id: String,
        routed: bool,
    },
    SetRouting {
        mode: RoutingMode,
    },
    OpenProviderPopup,
    OpenModelPopup,
    ToggleScannerUrlEdit,
    ToggleScannerModelEdit,
    SetScannerProvider {
        provider_id: String,
    },
    SetScannerModel {
        model: String,
        base_url: String,
    },
    ToggleBlockMode {
        enabled: bool,
    },
    ToggleAutoInjectDocs {
        enabled: bool,
    },
    TogglePostEditVerify {
        enabled: bool,
    },
}

fn build_setup_actions(state: &TuiState) -> Vec<SetupAction> {
    let mut actions = Vec::new();
    for h in &state.harnesses {
        if !h.installed {
            continue;
        }
        for p in &h.providers {
            actions.push(SetupAction::ToggleProvider {
                harness_id: h.id.clone(),
                provider_id: p.id.clone(),
                routed: p.routed,
            });
        }
    }
    let _cfg = match &state.config {
        Some(c) => c,
        None => return actions,
    };
    for mode in [RoutingMode::Sleev, RoutingMode::Direct, RoutingMode::Custom] {
        actions.push(SetupAction::SetRouting { mode });
    }
    // Scanner actions — extra Endpoint row when provider is custom.
    actions.push(SetupAction::OpenProviderPopup);
    if detect_scanner_provider(&_cfg.scanner.base_url) == "custom" {
        actions.push(SetupAction::ToggleScannerUrlEdit);
        actions.push(SetupAction::ToggleScannerModelEdit);
    } else {
        actions.push(SetupAction::OpenModelPopup);
    }
    // Block mode toggle — reflects current state, handler flips it.
    actions.push(SetupAction::ToggleBlockMode {
        enabled: _cfg.scanner.block_on_hallucination,
    });
    actions.push(SetupAction::ToggleAutoInjectDocs {
        enabled: _cfg.scanner.auto_inject_docs,
    });
    actions.push(SetupAction::TogglePostEditVerify {
        enabled: _cfg.scanner.post_edit_verify,
    });
    actions
}

async fn handle_setup_enter(state: &mut TuiState, client: &DaemonClient) {
    let actions = build_setup_actions(state);
    if actions.is_empty() {
        return;
    }
    // Convert absolute ListState selection into a selectable-position index
    // so we can index into `actions` (which parallels the selectable subset).
    let items = build_setup_items(state);
    let selectable: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, (_, sel))| *sel)
        .map(|(i, _)| i)
        .collect();
    if selectable.is_empty() {
        return;
    }
    let cur_abs = state.setup_state.selected().unwrap_or(selectable[0]);
    let cursor_pos = selectable.iter().position(|&i| i == cur_abs).unwrap_or(0);
    let idx = cursor_pos % actions.len();
    match &actions[idx] {
        SetupAction::ToggleProvider {
            harness_id,
            provider_id,
            routed,
        } => {
            if *routed {
                let _ = client.disable_provider(harness_id, provider_id).await;
                state.status_msg = Some(format!("disabled {} → {}", harness_id, provider_id));
            } else {
                let _ = client.enable_provider(harness_id, provider_id).await;
                state.status_msg = Some(format!("enabled {} → {}", harness_id, provider_id));
            }
            // Refresh harnesses
            if let Some(h) = client.harnesses().await {
                state.harnesses = h;
            }
        }
        SetupAction::SetRouting { mode } => {
            let mode_str = match mode {
                RoutingMode::Sleev => "sleev",
                RoutingMode::Direct => "direct",
                RoutingMode::Custom => "custom",
            };
            let _ = client.set_routing(mode_str).await;
            state.status_msg = Some(format!("routing: {}", mode_str));
            // Reload config
            if let Some(c) = client.fetch_config().await {
                state.config = Some(c);
            }
        }
        SetupAction::OpenProviderPopup => {
            let providers = collect_scanner_providers(&state.harnesses);
            let current = detect_scanner_provider(
                &state.config.as_ref().map(|c| c.scanner.base_url.clone()).unwrap_or_default(),
            );
            let selected = providers.iter().position(|(pid, _)| pid == &current).unwrap_or(0);
            state.popup = Some(PopupState {
                kind: PopupKind::ProviderSelect,
                items: providers.into_iter().map(|(pid, name)| (name, pid)).collect(),
                selected,
                title: "Select Provider".into(),
                text_input: None,
            });
        }
        SetupAction::ToggleScannerUrlEdit => {
            let cfg = match &state.config { Some(c) => c.clone(), None => return };
            if state.editing_scanner_url {
                // Save: POST url to daemon, keep current model.
                let model = cfg.scanner.model.clone();
                if client.set_scanner_model_url(&model, &state.scanner_url_buf).await {
                    state.status_msg = Some(format!("scanner endpoint → {}", state.scanner_url_buf));
                    if let Some(c) = client.fetch_config().await { state.config = Some(c); }
                }
                state.editing_scanner_url = false;
            } else {
                state.scanner_url_buf = cfg.scanner.base_url.clone();
                state.editing_scanner_url = true;
                state.editing_scanner_model = false;
            }
        }
        SetupAction::ToggleScannerModelEdit => {
            let cfg = match &state.config { Some(c) => c.clone(), None => return };
            if state.editing_scanner_model {
                let url = cfg.scanner.base_url.clone();
                if client.set_scanner_model_url(&state.scanner_model_buf, &url).await {
                    state.status_msg = Some(format!("scanner model → {}", state.scanner_model_buf));
                    if let Some(c) = client.fetch_config().await { state.config = Some(c); }
                }
                state.editing_scanner_model = false;
            } else {
                state.scanner_model_buf = cfg.scanner.model.clone();
                state.editing_scanner_model = true;
                state.editing_scanner_url = false;
            }
        }
        SetupAction::OpenModelPopup => {
            let cfg = match &state.config { Some(c) => c.clone(), None => return };
            let current_provider = detect_scanner_provider(&cfg.scanner.base_url);
            let models = live_or_preset_models(&current_provider, &state.scanner_models, &current_provider);
            let url = provider_base_url(&current_provider).to_string();
            let selected = models.iter().position(|m| m == &cfg.scanner.model).unwrap_or(0);
            state.popup = Some(PopupState {
                kind: PopupKind::ModelSelect,
                items: models.into_iter().map(|m| (m, url.clone())).collect(),
                selected,
                title: "Select Model".into(),
                text_input: None,
            });
        }
        SetupAction::SetScannerProvider { provider_id } => {
            // Legacy direct selection (not used in popup flow)
            if provider_id == "custom" {
                state.status_msg = Some("CUSTOM selected — edit config.yaml".into());
            } else {
                let models = models_for_provider(&provider_id);
                if let Some((model, url)) = models.first() {
                    if client.set_scanner_model_url(model, url).await {
                        state.status_msg = Some(format!("scanner: {} via {}", model, provider_id));
                        state.scanner_models.clear();
                    }
                }
            }
            if let Some(c) = client.fetch_config().await {
                state.config = Some(c);
            }
        }
        SetupAction::SetScannerModel { model, base_url } => {
            if client.set_scanner_model_url(model, base_url).await {
                state.status_msg = Some(format!("scanner model: {}", model));
            }
            if let Some(c) = client.fetch_config().await {
                state.config = Some(c);
            }
        }
        SetupAction::ToggleBlockMode { enabled } => {
            let new_val = !*enabled;
            if client.set_block_mode(new_val).await {
                let cfg = load_config();
                state.config = Some(cfg);
                state.status_msg = Some(format!(
                    "block hallucinated tool calls: {}",
                    if new_val { "ON" } else { "OFF" }
                ));
            } else {
                state.status_msg = Some("failed to toggle block mode".to_string());
            }
        }
        SetupAction::ToggleAutoInjectDocs { enabled } => {
            let new_val = !*enabled;
            if client.set_auto_inject_docs(new_val).await {
                let cfg = load_config();
                state.config = Some(cfg);
                state.status_msg = Some(format!(
                    "auto-inject cached API docs: {}",
                    if new_val { "ON" } else { "OFF" }
                ));
            } else {
                state.status_msg = Some("failed to toggle auto-inject".to_string());
            }
        }
        SetupAction::TogglePostEditVerify { enabled } => {
            let new_val = !*enabled;
            if client.set_post_edit_verify(new_val).await {
                let cfg = load_config();
                state.config = Some(cfg);
                state.status_msg = Some(format!(
                    "post-edit verification: {}",
                    if new_val { "ON" } else { "OFF" }
                ));
            } else {
                state.status_msg = Some("failed to toggle post-edit verify".to_string());
            }
        }
    }
}

async fn handle_event(ev: Event, state: &mut TuiState, client: &DaemonClient) {
    match ev {
        Event::Key(k) => {
            // ── Popup intercept — all keys route to popup when open ──
            if state.popup.is_some() && k.kind == KeyEventKind::Press {
                // CustomUrlEdit popup handles text entry, not list navigation.
                if matches!(
                    state.popup.as_ref().map(|p| p.kind),
                    Some(PopupKind::CustomUrlEdit)
                ) {
                    match k.code {
                        KeyCode::Char(c) => {
                            if let Some(text) = state.popup.as_mut().unwrap().text_input.as_mut() {
                                text.push(c);
                            }
                            return;
                        }
                        KeyCode::Backspace => {
                            if let Some(text) = state.popup.as_mut().unwrap().text_input.as_mut() {
                                text.pop();
                            }
                            return;
                        }
                        KeyCode::Enter => {
                            let (url, is_scanner) = state
                                .popup
                                .as_ref()
                                .map(|p| (
                                    p.text_input.clone().unwrap_or_default(),
                                    p.title.contains("Scanner"),
                                ))
                                .unwrap_or_default();
                            state.popup = None;
                            let trimmed = url.trim();
                            if trimmed.is_empty() {
                                state.status_msg = Some("URL not saved (empty)".into());
                            } else if is_scanner {
                                // Scanner endpoint: keep current model, update base_url only.
                                let model = state.config.as_ref()
                                    .map(|c| c.scanner.model.clone())
                                    .unwrap_or_default();
                                if client.set_scanner_model_url(&model, trimmed).await {
                                    state.status_msg = Some(format!("scanner endpoint → {}", trimmed));
                                } else {
                                    state.status_msg = Some("failed to save scanner endpoint".into());
                                }
                            } else if client.set_custom_url(trimmed).await {
                                state.status_msg = Some(format!("custom URL → {}", trimmed));
                            } else {
                                state.status_msg = Some("failed to save custom URL".into());
                            }
                            if let Some(c) = client.fetch_config().await {
                                state.config = Some(c);
                            }
                            return;
                        }
                        KeyCode::Esc => {
                            state.popup = None;
                            return;
                        }
                        _ => return,
                    }
                }
                match k.code {
                    KeyCode::Char('j') | KeyCode::Down => {
                        if let Some(popup) = state.popup.as_mut() {
                            if popup.selected + 1 < popup.items.len() {
                                popup.selected += 1;
                            }
                        }
                        return;
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        if let Some(popup) = state.popup.as_mut() {
                            if popup.selected > 0 {
                                popup.selected -= 1;
                            }
                        }
                        return;
                    }
                    KeyCode::Enter => {
                        let (display, value, is_provider) = {
                            let popup = state.popup.as_ref().unwrap();
                            let (d, v) = popup.items[popup.selected].clone();
                            (d, v, matches!(popup.kind, PopupKind::ProviderSelect))
                        };
                        state.popup = None; // close popup
                        if is_provider {
                            if value != "custom" {
                                let models = models_for_provider(&value);
                                if let Some((model, url)) = models.first() {
                                    client.set_scanner_model_url(model, url).await;
                                    state.scanner_models.clear();
                                    state.status_msg = Some(format!("scanner → {} ({})", value, model));
                                }
                            } else {
                                // CUSTOM: open URL entry popup for scanner endpoint.
                                state.popup = Some(crate::dashboard::PopupState {
                                    kind: crate::dashboard::PopupKind::CustomUrlEdit,
                                    items: Vec::new(),
                                    selected: 0,
                                    title: "Scanner Endpoint URL — Enter to save, Esc to cancel".into(),
                                    text_input: Some(String::new()),
                                });
                                return;
                            }
                        } else {
                            client.set_scanner_model_url(&display, &value).await;
                            state.status_msg = Some(format!("scanner model → {}", display));
                        }
                        if let Some(c) = client.fetch_config().await {
                            state.config = Some(c);
                        }
                        return;
                    }
                    KeyCode::Esc => {
                        state.popup = None;
                        return;
                    }
                    _ => return,
                }
            }
            // 'e' on Setup tab → open CustomUrlEdit popup when cursor is on
            // the Custom URL radio row. Lets user set the URL without leaving
            // the dashboard or hand-editing config.yaml.
            if k.kind == KeyEventKind::Press
                && k.code == KeyCode::Char('e')
                && state.tab == Tab::Setup
                && state.popup.is_none()
            {
                let actions = build_setup_actions(state);
                let items = build_setup_items(state);
                let selectable: Vec<usize> = items
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, sel))| *sel)
                    .map(|(i, _)| i)
                    .collect();
                if !selectable.is_empty() {
                    let cur_abs = state.setup_state.selected().unwrap_or(selectable[0]);
                    let cur_pos = selectable.iter().position(|&i| i == cur_abs).unwrap_or(0);
                    let idx = cur_pos % actions.len();
                    if matches!(
                        actions[idx],
                        SetupAction::SetRouting { mode: RoutingMode::Custom }
                    ) {
                        let current_url = state
                            .config
                            .as_ref()
                            .map(|c| c.routing.custom_url.clone())
                            .unwrap_or_default();
                        state.popup = Some(PopupState {
                            kind: PopupKind::CustomUrlEdit,
                            items: vec![],
                            selected: 0,
                            title: "Custom URL — Enter to save, Esc to cancel".into(),
                            text_input: Some(current_url),
                        });
                        return;
                    }
                }
            }
            // Check for Enter on Setup tab before sync handler
            if k.kind == KeyEventKind::Press && k.code == KeyCode::Enter && state.tab == Tab::Setup
            {
                handle_setup_enter(state, client).await;
                return;
            }
            handle_key(k, state);
        }
        Event::Mouse(m) => handle_mouse(m, state, client).await,
        Event::Resize(_, _) => {
            // Force layout cache invalidation — LayoutRects are recomputed
            // on next render in ui(), so just marking dirty is enough.
            // The loop redraws immediately after this handler returns.
        }
        _ => {}
    }
}

/// Navigate the Setup list by `delta` selectable items (forward/backward).
/// Skips non-selectable rows (headers, separators, detail sub-rows) and wraps
/// around. Keeps `state.setup_state.selected()` always pointing at a real
/// selectable absolute index.
fn navigate_setup(state: &mut TuiState, delta: i32) {
    let items = build_setup_items(state);
    let selectable: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, (_, sel))| *sel)
        .map(|(i, _)| i)
        .collect();
    if selectable.is_empty() {
        state.setup_state.select(None);
        return;
    }
    let cur_abs = state.setup_state.selected().unwrap_or(selectable[0]);
    let cur_pos = selectable.iter().position(|&i| i == cur_abs).unwrap_or(0);
    let len = selectable.len() as i32;
    let new_pos = ((cur_pos as i32 + delta).rem_euclid(len)) as usize;
    state.setup_state.select(Some(selectable[new_pos]));
}

fn handle_key(k: KeyEvent, state: &mut TuiState) {
    if k.kind == KeyEventKind::Release {
        return;
    }
    // Inline scanner edit mode: capture all keys.
    if state.editing_scanner_url || state.editing_scanner_model {
        match k.code {
            KeyCode::Esc => {
                state.editing_scanner_url = false;
                state.editing_scanner_model = false;
                return;
            }
            KeyCode::Enter => {
                // Fire setup enter on the current cursor row to save.
                SETUP_TOGGLE_REQUESTED.store(
                    state.setup_state.selected().unwrap_or(0),
                    std::sync::atomic::Ordering::Relaxed,
                );
                return;
            }
            KeyCode::Backspace => {
                if state.editing_scanner_url { state.scanner_url_buf.pop(); }
                if state.editing_scanner_model { state.scanner_model_buf.pop(); }
                return;
            }
            KeyCode::Char(c) => {
                if state.editing_scanner_url { state.scanner_url_buf.push(c); }
                if state.editing_scanner_model { state.scanner_model_buf.push(c); }
                return;
            }
            _ => return,
        }
    }
    match k.code {
        KeyCode::Char('q') | KeyCode::Esc => state.should_quit = true,
        KeyCode::Char('1') => state.tab = Tab::Overview,
        KeyCode::Char('2') => state.tab = Tab::Setup,
        KeyCode::Tab | KeyCode::BackTab => {
            state.tab = match state.tab {
                Tab::Overview => Tab::Setup,
                Tab::Setup => Tab::Overview,
            };
        }
            KeyCode::Char('j') | KeyCode::Down => {
                if state.tab == Tab::Overview {
                    if state.focus == Focus::Validator {
                        state.validator_scroll = state.validator_scroll.saturating_add(1);
                    } else {
                        state.move_recent_cursor(1);
                    }
                } else if state.tab == Tab::Setup {
                    navigate_setup(state, 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if state.tab == Tab::Overview {
                    if state.focus == Focus::Validator {
                        state.validator_scroll = state.validator_scroll.saturating_sub(1);
                    } else {
                        state.move_recent_cursor(-1);
                    }
                } else if state.tab == Tab::Setup {
                    navigate_setup(state, -1);
                }
            }
        KeyCode::PageDown => {
            state.validator_scroll = state.validator_scroll.saturating_add(10);
            state.clamp_validator_scroll();
        }
        KeyCode::PageUp => {
            state.validator_scroll = state.validator_scroll.saturating_sub(10);
        }
        KeyCode::Char('g') => {
            if state.tab == Tab::Overview {
                state.validator_scroll = 0;
            }
        }
        KeyCode::Char('G') => {
            if state.tab == Tab::Overview {
                let total = state.validator_line_count();
                let visible = state.rects.validator_body.height as usize;
                state.validator_scroll = total.saturating_sub(visible);
            }
        }
        KeyCode::Enter => {
            // Toggle selection off if something selected
            if state.selected_request_id.is_some() {
                state.select_request(None);
            }
        }
        _ => {}
    }
}

async fn handle_mouse(m: MouseEvent, state: &mut TuiState, _client: &DaemonClient) {
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => handle_left_click(m, state).await,
        MouseEventKind::ScrollDown => handle_scroll(m, state, 1),
        MouseEventKind::ScrollUp => handle_scroll(m, state, -1),
        _ => {}
    }
}

async fn handle_left_click(m: MouseEvent, state: &mut TuiState) {
    // Popup intercepts ALL clicks when open.
    if state.popup.is_some() {
        let body = state.rects.popup_body;
        if in_rect(body, m.column, m.row) {
            // Click inside popup → select item by row offset.
            if let Some(ref mut popup) = state.popup {
                if !matches!(popup.kind, PopupKind::CustomUrlEdit) {
                    let row_idx = (m.row - body.y) as usize;
                    if row_idx < popup.items.len() {
                        popup.selected = row_idx;
                    }
                }
            }
        } else {
            // Click outside popup → close it.
            state.popup = None;
        }
        return; // Never pass through to background when popup is open.
    }

    // Tab buttons
    if in_rect(state.rects.tab_overview, m.column, m.row) {
        state.tab = Tab::Overview;
        return;
    }
    if in_rect(state.rects.tab_setup, m.column, m.row) {
        state.tab = Tab::Setup;
        return;
    }
    // Quit
    if in_rect(state.rects.quit_btn, m.column, m.row) {
        state.should_quit = true;
        return;
    }
    // Clear button
    if state.tab == Tab::Overview && in_rect(state.rects.clear_btn, m.column, m.row) {
        // Fire-and-forget POST — polled by run_loop on next tick.
        state.status_msg = Some("clearing…".to_string());
        CLEAR_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    // Recent requests click → select entry
    if state.tab == Tab::Overview && in_rect(state.rects.recent_body, m.column, m.row) {
        state.focus = Focus::Requests;
        let body = state.rects.recent_body;
        let row_idx = (m.row as usize).saturating_sub(body.y as usize) + state.recent_scroll;
        let entries = &state.stats.recent_entries;
        if row_idx < entries.len() {
            let id = entries[row_idx].request_id.clone();
            state.select_request(Some(id));
        }
        return;
    }
    // Validator body click → focus
    if state.tab == Tab::Overview && in_rect(state.rects.validator_body, m.column, m.row) {
        state.focus = Focus::Validator;
        return;
    }
    // Setup tab click → select nearest selectable item to clicked row.
    // List widget renders exactly 1 row per item (no wrap), so visual row
    // maps 1:1 to item index from inner.top(). We add ListState.offset()
    // to support scrolling when the list is taller than the viewport.
    if state.tab == Tab::Setup && in_rect(state.rects.setup_body, m.column, m.row) {
        let body = state.rects.setup_body;
        let offset = state.setup_state.offset();
        let clicked_idx = (m.row as usize).saturating_sub(body.y as usize) + offset;
        let items = build_setup_items(state);
        let selectable: Vec<usize> = items
            .iter()
            .enumerate()
            .filter(|(_, (_, sel))| *sel)
            .map(|(i, _)| i)
            .collect();
        if selectable.is_empty() {
            return;
        }
        // Snap forward to the next selectable item at-or-after the click;
        // if click is past the last selectable, snap to the last one.
        let abs_idx = selectable
            .iter()
            .find(|&&i| i >= clicked_idx)
            .or(selectable.last())
            .copied()
            .unwrap();
        state.setup_state.select(Some(abs_idx));
        // Trigger the action via the existing poll-loop drain. Store the
        // SELECTABLE POSITION (not absolute index) so handle_setup_enter's
        // `idx % actions.len()` math still works.
        let cursor_pos = selectable.iter().position(|&i| i == abs_idx).unwrap_or(0);
        SETUP_TOGGLE_REQUESTED.store(cursor_pos, std::sync::atomic::Ordering::Relaxed);
        return;
    }
}

fn handle_scroll(m: MouseEvent, state: &mut TuiState, delta: i32) {
    if state.tab != Tab::Overview {
        return;
    }
    // Decide which region based on x/y hit
    if in_rect(state.rects.recent_body, m.column, m.row) {
        state.focus = Focus::Requests;
        state.move_recent_cursor(delta);
    } else if in_rect(state.rects.validator_body, m.column, m.row) {
        state.focus = Focus::Validator;
        if delta > 0 {
            state.validator_scroll = state.validator_scroll.saturating_add(delta as usize);
        } else {
            state.validator_scroll = state.validator_scroll.saturating_sub((-delta) as usize);
        }
        state.clamp_validator_scroll();
    }
}

fn in_rect(r: Rect, x: u16, y: u16) -> bool {
    x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height
}

// Flag for cross-task clear (set by event handler, drained by poll loop).
static CLEAR_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Flag for setup toggle-on-click (stores cursor pos, drained by poll loop).
static SETUP_TOGGLE_REQUESTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

// ─── Polling loop ──────────────────────────────────────────────────────

async fn poll_once(state: &mut TuiState, client: &DaemonClient) {
    if let Some(stats) = client.stats().await {
        state.stats = stats;
        state.connected = true;
        // Drop selected if it disappeared
        if let Some(id) = &state.selected_request_id {
            let still_present = state
                .stats
                .recent_entries
                .iter()
                .any(|e| &e.request_id == id);
            if !still_present {
                state.select_request(None);
            }
        }
    } else {
        state.connected = false;
    }

    if state.daemon_version == "—" {
        if let Some(p) = client.ping().await {
            if !p.version.is_empty() {
                state.daemon_version = p.version;
            }
        }
    }

    if CLEAR_REQUESTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
        if client.clear().await {
            state.status_msg = Some("cleared".to_string());
            state.select_request(None);
        } else {
            state.status_msg = Some("clear failed".to_string());
        }
    }

    // Drain setup toggle-on-click request. toggle_idx is a SELECTABLE POSITION
    // (parallel to actions vec); convert to absolute index for ListState.
    let toggle_idx = SETUP_TOGGLE_REQUESTED.swap(usize::MAX, std::sync::atomic::Ordering::Relaxed);
    if toggle_idx != usize::MAX {
        let items = build_setup_items(state);
        let selectable: Vec<usize> = items
            .iter()
            .enumerate()
            .filter(|(_, (_, sel))| *sel)
            .map(|(i, _)| i)
            .collect();
        if !selectable.is_empty() {
            let pos = toggle_idx.min(selectable.len() - 1);
            state.setup_state.select(Some(selectable[pos]));
        }
        handle_setup_enter(state, client).await;
    }

    // Poll harnesses + scanner models when on Setup tab
    if state.tab == Tab::Setup {
        if let Some(harnesses) = client.harnesses().await {
            state.harnesses = harnesses;
        }
        // Fetch models from provider's /models endpoint (cached in TuiState).
        // Only fetch once per Setup tab session — empty vec means not yet fetched.
        if state.scanner_models.is_empty() {
            let models = client.fetch_scanner_models().await;
            if !models.is_empty() {
                state.scanner_models = models;
            }
        }
    }
}

// ─── Public entrypoint ─────────────────────────────────────────────────

pub async fn run() -> Result<()> {
    let cfg = load_config();
    let daemon_url = cfg.proxy_url();
    let client = DaemonClient::new(daemon_url.clone());
    let mut state = TuiState::new(daemon_url);
    state.config = Some(cfg);

    // Setup terminal
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).context("enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("init terminal")?;
    terminal.clear().ok();

    // Initial fetch before first paint
    poll_once(&mut state, &client).await;

    let result = run_loop(&mut terminal, &mut state, &client).await;

    // Teardown (best-effort, never mask original error)
    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut TuiState,
    client: &DaemonClient,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(TICK_MS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        terminal.draw(|f| ui(f, state))?;

        if state.should_quit {
            return Ok(());
        }

        tokio::select! {
            biased;
            maybe_ev = events.next() => {
                if let Some(Ok(ev)) = maybe_ev {
                    handle_event(ev, state, client).await;
                }
            }
            _ = tick.tick() => {
                poll_once(state, client).await;
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::fmt_risk;

    #[test]
    fn fmt_risk_zero() {
        assert_eq!(fmt_risk(0.0), "0/10");
    }

    #[test]
    fn fmt_risk_clean_low() {
        assert_eq!(fmt_risk(0.05), "1/10");
        assert_eq!(fmt_risk(0.15), "2/10");
    }

    #[test]
    fn fmt_risk_medium() {
        assert_eq!(fmt_risk(0.35), "4/10");
        assert_eq!(fmt_risk(0.55), "6/10");
    }

    #[test]
    fn fmt_risk_high() {
        assert_eq!(fmt_risk(0.75), "8/10");
    }

    #[test]
    fn fmt_risk_max() {
        assert_eq!(fmt_risk(1.0), "10/10");
    }

    #[test]
    fn fmt_risk_clamps_above_one() {
        // Defensive — score should never exceed 1.0 but clamp just in case.
        assert_eq!(fmt_risk(1.5), "10/10");
    }

    #[test]
    fn fmt_risk_clamps_below_zero() {
        assert_eq!(fmt_risk(-0.5), "0/10");
    }

    #[test]
    fn fmt_risk_rounds_half_up() {
        // 0.45 * 10 = 4.5 → rounds to 5 (banker's rounding in Rust would give 4,
        // but we want consistent .5-up behavior for UI clarity).
        // Actually Rust's round() rounds half away from zero, so 4.5 → 5.
        assert_eq!(fmt_risk(0.45), "5/10");
    }
}
