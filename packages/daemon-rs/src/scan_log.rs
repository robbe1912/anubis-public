// Append-only JSONL scan log. SINGLE source of truth for scan results.
//
// KISS: every scan phase (fast, egress, deep) appends one line. The
// dashboard reads the file directly and displays each line as one entry
// (no deduplication, no merge). Clear button truncates the file.
//
// Why no dedup: egress + deep phases are separate events. The user can
// see the progression. Timestamps disambiguate.

use crate::stats::ScanResult;
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanLogLine {
    pub ts: String,
    pub request_id: String,
    pub phase: String, // "fast" | "egress" | "deep"
    pub scan_result: String,
    pub risk_score: f64,
    pub scan_details: Vec<String>,
    pub validator_response: String,
    pub model: String,
    pub streaming: bool,
    pub status: u16,
    pub latency_ms: u32,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
    /// Scanner-level confidence in the verdict `[0.0, 1.0]`. From
    /// `ScanResultData.confidence` — drives the dashboard's "C0/10–C10/10"
    /// display. Defaults to 1.0 when absent (back-compat with older log
    /// lines written before this field existed).
    #[serde(default = "default_confidence_one")]
    pub confidence: f64,
}

fn default_confidence_one() -> f64 {
    1.0
}

fn log_path() -> PathBuf {
    crate::config::home_dir().join(".anubis").join("scans.jsonl")
}

/// Append one scan result. Called from ALL scan paths.
pub fn append(line: &ScanLogLine) {
    use std::io::Write;
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json = serde_json::to_string(line).unwrap_or_default();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}", json);
    }

    // Prune: keep last 500 lines
    if let Ok(lines) = std::fs::read_to_string(&path) {
        let all: Vec<&str> = lines.lines().collect();
        if all.len() > 1000 {
            let keep: String = all[all.len() - 500..]
                .iter()
                .map(|l| format!("{}\n", l))
                .collect();
            let _ = std::fs::write(&path, keep);
        }
    }
}

/// Read recent entries, ONE per request_id (best available data).
///
/// The JSONL file is append-only — each scan phase (egress, deep) writes
/// its own line. For display, we collapse to one row per request_id by
/// keeping the entry with the highest severity (warning > clean), then
/// highest risk_score. When a deep scan completes with risk=0.8, it
/// replaces the egress entry with risk=0 for the same request. The
/// dashboard polls this every ~200ms so updates appear live.
pub fn read_recent(n: usize) -> Vec<ScanLogLine> {
    let path = log_path();
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let lines: Vec<String> = std::io::BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .collect();

    // Parse all lines (need all phases per request to pick the best)
    let all: Vec<ScanLogLine> = lines
        .into_iter()
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect();

    // Group by request_id, keep best entry (highest severity then risk)
    // AND merge model/tokens/latency from sibling entries.
    let mut best: std::collections::HashMap<String, ScanLogLine> =
        std::collections::HashMap::new();
    for entry in all.into_iter().rev() {
        let key = entry.request_id.clone();
        match best.get_mut(&key) {
            None => {
                best.insert(key, entry);
            }
            Some(existing) => {
                let new_sev = severity_rank(&entry.scan_result);
                let old_sev = severity_rank(&existing.scan_result);
                let higher_sev = new_sev > old_sev;
                let same_sev = new_sev == old_sev;
                let higher_risk = entry.risk_score > existing.risk_score;
                let same_risk = entry.risk_score == existing.risk_score;
                let new_has_model = !entry.model.is_empty();
                let old_has_model = !existing.model.is_empty();
                let model_better = new_has_model && !old_has_model;

                let replace = higher_sev
                    || (same_sev && higher_risk)
                    || (same_sev && same_risk && model_better);

                if replace {
                    // Merge missing fields from old into new before replacing.
                    let mut merged = entry;
                    if merged.model.is_empty() && old_has_model {
                        merged.model = existing.model.clone();
                    }
                    if merged.prompt_tokens == 0 { merged.prompt_tokens = existing.prompt_tokens; }
                    if merged.completion_tokens == 0 { merged.completion_tokens = existing.completion_tokens; }
                    if merged.total_tokens == 0 { merged.total_tokens = existing.total_tokens; }
                    if merged.latency_ms == 0 { merged.latency_ms = existing.latency_ms; }
                    *existing = merged;
                } else {
                    // Existing wins — merge missing fields from incoming.
                    if existing.model.is_empty() && new_has_model {
                        existing.model = entry.model.clone();
                    }
                    if existing.prompt_tokens == 0 { existing.prompt_tokens = entry.prompt_tokens; }
                    if existing.completion_tokens == 0 { existing.completion_tokens = entry.completion_tokens; }
                    if existing.total_tokens == 0 { existing.total_tokens = entry.total_tokens; }
                    if existing.latency_ms == 0 { existing.latency_ms = entry.latency_ms; }
                }
            }
        }
    }

    // Sort by timestamp descending, take n
    let mut entries: Vec<ScanLogLine> = best.into_values().collect();
    entries.sort_by(|a, b| b.ts.cmp(&a.ts));
    entries.truncate(n);
    entries
}

fn severity_rank(result: &str) -> u8 {
    match result {
        "blocked" => 4,
        "error" => 3,
        "warning" => 2,
        "clean" => 1,
        _ => 0,
    }
}

/// Truncate the log file to empty. Called by the dashboard's "clear log"
/// button. The next /stats poll will see an empty list and the display
/// will refresh to "(no requests yet)".
pub fn clear() {
    let path = log_path();
    let _ = std::fs::write(&path, "");
}

/// Build aggregate stats from the recent log entries.
pub fn compute_stats() -> (u64, u64, u64, u64, u64, u64, f64, Vec<ScanLogLine>) {
    let entries = read_recent(200);
    let total = entries.len() as u64;
    let clean = entries.iter().filter(|e| e.scan_result == "clean").count() as u64;
    let warning = entries.iter().filter(|e| e.scan_result == "warning").count() as u64;
    let blocked = entries.iter().filter(|e| e.scan_result == "blocked").count() as u64;
    let skipped = entries
        .iter()
        .filter(|e| matches!(e.scan_result.as_str(), "error" | "skipped"))
        .count() as u64;
    let risk_sum: f64 = entries.iter().map(|e| e.risk_score).sum();
    (total, clean, warning, blocked, skipped, 0, risk_sum, entries)
}
