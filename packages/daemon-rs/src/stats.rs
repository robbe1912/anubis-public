// Statistics tracking — mirrors ProxyStats + RequestLogEntry from TypeScript.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Aggregate proxy statistics. Shared between HTTP handler + internal API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyStats {
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_tokens: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub reasoning_tokens: u64,
    pub clean_count: u64,
    pub warning_count: u64,
    pub blocked_count: u64,
    pub skipped_count: u64,
    pub validator_tokens: u64,
    pub validator_calls: u64,
    pub local_check_count: u64,
    pub agent_check_count: u64,
    pub docs_hit_count: u64,
    pub compaction_count: u64,
    pub background_count: u64,
    pub cache_hit_count: u64,
    pub latencies: Vec<u32>,
    pub recent_entries: Vec<RequestLogEntry>,
    /// Running sum of `risk_score` across all scans. Divide by
    /// `risk_score_count` to get the average. Lets the Prometheus exporter
    /// surface `anubis_avg_risk_score` without storing every sample.
    pub risk_score_sum: f64,
    pub risk_score_count: u64,
}

impl ProxyStats {
    pub const MAX_RECENT: usize = 50;
    pub const MAX_LATENCIES: usize = 200;

    /// Push a request entry to recent (newest first, capped at MAX_RECENT).
    pub fn push_recent(&mut self, entry: RequestLogEntry) {
        self.recent_entries.insert(0, entry);
        if self.recent_entries.len() > Self::MAX_RECENT {
            self.recent_entries.pop();
        }
    }

    /// Record a latency sample (capped at MAX_LATENCIES).
    pub fn record_latency(&mut self, ms: u32) {
        self.latencies.push(ms);
        if self.latencies.len() > Self::MAX_LATENCIES {
            self.latencies.remove(0);
        }
    }

    /// Calculate p50/p95/p99 from stored latencies.
    pub fn percentile(&self, p: f64) -> u32 {
        if self.latencies.is_empty() {
            return 0;
        }
        let mut sorted = self.latencies.clone();
        sorted.sort_unstable();
        let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Reset all counters to zero.
    pub fn clear(&mut self) {
        *self = ProxyStats::default();
    }

    /// Update an existing recent entry with corrected scan data.
    /// Called when a deeper scan (background/deep) completes after the
    /// initial fast-scan recording. Adjusts aggregate counters so the
    /// dashboard always reflects the authoritative result.
    ///
    /// This is the SINGLE METHOD that handles entry updates — all deep
    /// scan callbacks must go through here, not touch counters directly.
    pub fn update_scan_result(
        &mut self,
        request_id: &str,
        scan_result: ScanResult,
        risk_score: f64,
        confidence: f64,
        scan_details: Vec<String>,
        validator_response: String,
        validator_tokens: u64,
        docs_assisted: bool,
    ) {
        let entry = match self.recent_entries.iter_mut().rev().find(|e| e.request_id == request_id) {
            Some(e) => e,
            None => {
                tracing::warn!(
                    target: "stats",
                    request_id = %request_id,
                    "update_scan_result: entry not found — skipping"
                );
                return;
            }
        };

        // ── Undo old result from aggregate counters ──
        match entry.scan_result {
            ScanResult::Clean => { self.clean_count = self.clean_count.saturating_sub(1); }
            ScanResult::Warning => { self.warning_count = self.warning_count.saturating_sub(1); }
            ScanResult::Blocked => { self.blocked_count = self.blocked_count.saturating_sub(1); }
            _ => { self.skipped_count = self.skipped_count.saturating_sub(1); }
        }
        self.risk_score_sum -= entry.risk_score;

        // ── Apply new result ──
        entry.scan_result = scan_result.clone();
        entry.risk_score = risk_score;
        entry.confidence = confidence;
        entry.scan_details = scan_details;
        entry.validator_response = validator_response.clone();

        match scan_result {
            ScanResult::Clean => { self.clean_count += 1; }
            ScanResult::Warning => { self.warning_count += 1; }
            ScanResult::Blocked => { self.blocked_count += 1; }
            _ => { self.skipped_count += 1; }
        }
        self.risk_score_sum += risk_score;

        if !validator_response.is_empty() {
            self.validator_calls += 1;
            self.agent_check_count += 1;
        }
        self.validator_tokens += validator_tokens;
        if docs_assisted {
            self.docs_hit_count += 1;
        }
    }
}

/// A single request log entry — mirrors TS RequestLogEntry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub ts: String,
    pub request_id: String,
    pub method: String,
    pub path: String,
    pub model: String,
    pub streaming: bool,
    pub status: u16,
    pub latency_ms: u32,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
    pub scan_result: ScanResult,
    pub scan_details: Vec<String>,
    #[serde(default)]
    pub validator_response: String,
    /// Continuous risk score `[0.0, 1.0]`. 0.0 = clean, 1.0 = certain
    /// hallucination. Computed by [`scanner::compute_risk_score`].
    #[serde(default)]
    pub risk_score: f64,
    /// Scanner-level confidence in the verdict `[0.0, 1.0]`. From
    /// `ScanResultData.confidence`. Defaults to 1.0 for back-compat with
    /// entries written before this field existed. The dashboard surfaces
    /// this as "C0/10–C10/10" alongside the risk score.
    #[serde(default = "default_confidence_one")]
    pub confidence: f64,
}

fn default_confidence_one() -> f64 {
    1.0
}

/// Scan result classification.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanResult {
    Clean,
    Warning,
    Blocked,
    Error,
    #[default]
    Skipped,
}

impl std::fmt::Display for ScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanResult::Clean => write!(f, "clean"),
            ScanResult::Warning => write!(f, "warning"),
            ScanResult::Blocked => write!(f, "blocked"),
            ScanResult::Error => write!(f, "error"),
            ScanResult::Skipped => write!(f, "skipped"),
        }
    }
}

/// Thread-safe shared stats wrapper.
pub type SharedStats = Arc<RwLock<ProxyStats>>;

/// Create a new shared stats instance.
pub fn create_shared_stats() -> SharedStats {
    Arc::new(RwLock::new(ProxyStats::default()))
}
