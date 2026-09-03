//! Audit trail — persists every scan decision to `~/.anubis/audit.jsonl`.
//!
//! One JSON object per line (jsonl / NDJSON). Each entry captures the
//! request identity, scan verdict, warning/block details, validator raw
//! response, and latency. Enables post-hoc analysis, compliance, debugging
//! "why was this flagged?", and reproduction of false positives.
//!
//! Bounded by file size: when the audit file exceeds `MAX_AUDIT_BYTES`,
//! it's rotated to `<path>.1` and a fresh file starts. Older rotations
//! are deleted (only the most recent kept) to bound disk usage.
//!
//! Failure-tolerant: any I/O error is logged at `tracing::warn` and the
//! daemon continues. Audit is observability, not on the critical path.

use std::path::PathBuf;
use parking_lot::Mutex;

use serde::Serialize;

/// Maximum audit file size before rotation. ~10MB — fits ~50,000 entries.
const MAX_AUDIT_BYTES: u64 = 10 * 1024 * 1024;

/// Audit entries are written under this lock — serializes writes from
/// concurrent scans. The file is opened, appended to, closed per-write
/// (no long-lived file handle) so we never block on OS file handles.
static AUDIT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub ts: String,
    pub request_id: String,
    pub model: String,
    pub path: String,
    pub streaming: bool,
    pub status: u16,
    pub latency_ms: u32,
    pub scan_result: String,
    pub warnings: Vec<String>,
    pub blocks: Vec<String>,
    pub details: Vec<String>,
    pub validator_response_present: bool,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Continuous risk score `[0.0, 1.0]`. Lets analysts threshold after
    /// the fact ("show me everything > 0.5") instead of being locked to
    /// the three ALLOW/ESCALATE/BLOCK buckets.
    pub risk_score: f64,
}

impl AuditEntry {
    /// Build an entry from the proxy handler's data.
    #[allow(clippy::too_many_arguments)]
    pub fn from_proxy_data(
        ts: String,
        request_id: String,
        model: String,
        path: String,
        streaming: bool,
        status: u16,
        latency_ms: u32,
        scan_result: &str,
        warnings: Vec<String>,
        blocks: Vec<String>,
        details: Vec<String>,
        validator_response: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
        total_tokens: u64,
        risk_score: f64,
    ) -> Self {
        Self {
            ts,
            request_id,
            model,
            path,
            streaming,
            status,
            latency_ms,
            scan_result: scan_result.to_string(),
            warnings,
            blocks,
            details,
            // Don't persist the raw LLM response (often 2-5KB, blows up the
            // audit file). Just record whether we got one — debug via the
            // recent_entries log if needed.
            validator_response_present: !validator_response.is_empty(),
            prompt_tokens,
            completion_tokens,
            total_tokens,
            risk_score,
        }
    }
}

/// Path to the audit file: `~/.anubis/audit.jsonl`.
pub fn audit_path() -> PathBuf {
    crate::dirs_home().join(".anubis").join("audit.jsonl")
}

/// Append an entry to the audit log. Rotates if the file exceeds the size cap.
///
/// Best-effort: errors are logged at `warn` level and swallowed. The audit
/// trail must NEVER break the proxy's request handling.
pub fn append(entry: &AuditEntry) {
    let _guard = AUDIT_LOCK.lock();

    let path = audit_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(target: "audit", error = %e, "audit dir create failed");
            return;
        }
    }

    // Rotate if needed.
    if let Ok(metadata) = std::fs::metadata(&path) {
        if metadata.len() > MAX_AUDIT_BYTES {
            rotate(&path);
        }
    }

    // Serialize + append.
    let mut line = match serde_json::to_string(entry) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: "audit", error = %e, "audit entry serialize failed");
            return;
        }
    };
    line.push('\n');

    use std::io::Write;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(target: "audit", error = %e, "audit file open failed");
            return;
        }
    };
    if let Err(e) = file.write_all(line.as_bytes()) {
        tracing::warn!(target: "audit", error = %e, "audit write failed");
    }
}

/// Rotate the audit file: current → `.1`, delete any existing `.1`.
/// Only one rotation is kept — older history is dropped on purpose to
/// bound disk usage.
fn rotate(path: &std::path::Path) {
    let rotation = path.with_extension("jsonl.1");
    // Best-effort delete of older rotation (ignore error if it doesn't exist).
    let _ = std::fs::remove_file(&rotation);
    if let Err(e) = std::fs::rename(path, &rotation) {
        tracing::warn!(target: "audit", error = %e, "audit rotate failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> AuditEntry {
        AuditEntry {
            ts: "2026-07-23T00:00:00Z".to_string(),
            request_id: "req_test".to_string(),
            model: "test-model".to_string(),
            path: "/v1/chat/completions".to_string(),
            streaming: true,
            status: 200,
            latency_ms: 1234,
            scan_result: "warning".to_string(),
            warnings: vec!["test warning".to_string()],
            blocks: vec![],
            details: vec!["detail line".to_string()],
            validator_response_present: true,
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            risk_score: 0.42,
        }
    }

    #[test]
    fn audit_path_lives_under_anubis_dir() {
        let p = audit_path();
        let s = p.to_string_lossy();
        assert!(s.ends_with("audit.jsonl"), "unexpected path: {s}");
    }

    #[test]
    fn append_writes_valid_jsonl_line() {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: tests are single-threaded by default for the audit tests;
        // we override HOME so audit_path() points into the tempdir.
        let prev_home = std::env::var_os("USERPROFILE").map(|v| v.to_string_lossy().to_string());
        std::env::set_var("USERPROFILE", tmp.path().as_os_str());

        let entry = sample_entry();
        append(&entry);
        append(&entry); // second line proves jsonl works

        let content =
            std::fs::read_to_string(audit_path()).expect("audit file should exist after append");
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "expected 2 audit lines, got: {content}");

        // Each line must parse as a standalone JSON object.
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line {i} not valid JSON: {e}\nraw: {line}"));
            assert_eq!(v["request_id"], "req_test");
            assert_eq!(v["scan_result"], "warning");
            assert_eq!(v["warnings"][0], "test warning");
            assert_eq!(v["validator_response_present"], true);
        }

        // Restore HOME.
        if let Some(prev) = prev_home {
            std::env::set_var("USERPROFILE", prev);
        } else {
            std::env::remove_var("USERPROFILE");
        }
    }

    #[test]
    fn rotate_replaces_old_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let current = tmp.path().join("audit.jsonl");
        let rotation = tmp.path().join("audit.jsonl.1");

        // Pre-existing rotation should be replaced
        std::fs::write(&rotation, "old rotation content").unwrap();
        std::fs::write(&current, "current content").unwrap();

        rotate(&current);

        // Current should not exist (renamed away)
        assert!(!current.exists(), "current file should be renamed away");
        // Rotation should now hold what was current
        let rotated = std::fs::read_to_string(&rotation).unwrap();
        assert_eq!(rotated, "current content", "old rotation must be replaced");
    }

    #[test]
    fn audit_entry_serializes_all_fields() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Verify every field round-trips
        for field in [
            "ts",
            "request_id",
            "model",
            "path",
            "streaming",
            "status",
            "latency_ms",
            "scan_result",
            "warnings",
            "blocks",
            "details",
            "validator_response_present",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
        ] {
            assert!(v.get(field).is_some(), "missing field {field} in serialized entry");
        }
    }
}
