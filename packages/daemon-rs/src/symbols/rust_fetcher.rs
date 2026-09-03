//! Rust symbol fetcher.
//!
//! Downloads rustdoc JSON from docs.rs for the requested crate+version.
//! Stores raw JSON under ~/.anubis/symbols/rust/<crate>/<version>/rustdoc.json
//! for the parser to consume.
//!
//! docs.rs endpoint: https://docs.rs/<crate>/<version>/rustdoc.json
//! If version is None, follows redirect to /latest/ which docs.rs handles.

use std::path::{Path, PathBuf};
use std::time::Duration;

use once_cell::sync::Lazy;
use reqwest::Client;

use crate::dirs_home;

const HTTP_TIMEOUT_SECS: u64 = 90; // rustdoc JSON can be large (~10MB for serde)
const DOCS_RS_BASE: &str = "https://docs.rs";

static USER_AGENT: &str = concat!(
    "anubis-daemon/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/robbe1912/anubis-public)"
);

/// Optional bearer token — not currently used (docs.rs is anonymous) but
/// reserved for future authenticated access.
static _DOCS_RS_TOKEN: Lazy<Option<String>> = Lazy::new(|| std::env::var("DOCS_RS_TOKEN").ok());

/// Result of a fetch operation.
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub crate_name: String,
    pub version: String,
    pub bytes_downloaded: usize,
    pub skipped_fresh: bool,
    pub raw_path: PathBuf,
}

/// Fetch rustdoc JSON for a crate at the given version (or latest).
///
/// Stores under `~/.anubis/symbols/rust/<crate>/<version>/rustdoc.json`.
/// Skips if file exists and is fresh (< 7 days).
pub async fn fetch_rustdoc_json(
    crate_name: &str,
    version: Option<&str>,
) -> Result<FetchResult, String> {
    let client = build_client()?;

    // Step 1: resolve version (follow redirect if None)
    let (resolved_version, json_bytes) = fetch_with_redirect(&client, crate_name, version).await?;

    let raw_dir = raw_dir_for(crate_name, &resolved_version);
    let raw_path = raw_dir.join("rustdoc.json");

    // Step 2: check freshness — skip if file exists and is < 7 days old
    if is_file_fresh(&raw_path) {
        return Ok(FetchResult {
            crate_name: crate_name.to_string(),
            version: resolved_version,
            bytes_downloaded: 0,
            skipped_fresh: true,
            raw_path,
        });
    }

    // Step 3: ensure dir exists
    if let Err(e) = std::fs::create_dir_all(&raw_dir) {
        return Err(format!(
            "failed to create {}: {}",
            raw_dir.display(),
            e
        ));
    }

    // Step 4: atomic write (.tmp + rename). `tokio::fs::write` keeps the
    // async function non-blocking on slow disk; create_dir_all + rename
    // stay sync — they're cheap (single syscall, atomic on the same fs).
    let tmp_path = raw_path.with_extension("json.tmp");
    tokio::fs::write(&tmp_path, &json_bytes)
        .await
        .map_err(|e| format!("write tmp {}: {}", tmp_path.display(), e))?;
    std::fs::rename(&tmp_path, &raw_path)
        .map_err(|e| format!("rename to {}: {}", raw_path.display(), e))?;

    Ok(FetchResult {
        crate_name: crate_name.to_string(),
        version: resolved_version,
        bytes_downloaded: json_bytes.len(),
        skipped_fresh: false,
        raw_path,
    })
}

/// Build HTTP client with UA + timeout.
fn build_client() -> Result<Client, String> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("failed to build reqwest client: {}", e))
}

/// Fetch JSON, following redirect to resolve version.
///
/// docs.rs URL pattern (per https://docs.rs/about/rustdoc-json):
///   https://docs.rs/crate/<name>/latest/json     → latest version, default target
///   https://docs.rs/crate/<name>/<version>/json  → specific version
///   https://docs.rs/crate/<name>/~4/json         → latest v4 via semver
///
/// We use the explicit /latest/ or /<version>/ form. docs.rs redirects
/// /latest/ to the actual version, which reqwest follows automatically.
async fn fetch_with_redirect(
    client: &Client,
    crate_name: &str,
    version: Option<&str>,
) -> Result<(String, Vec<u8>), String> {
    let ver_param = version.unwrap_or("latest");
    // Use .gz suffix — docs.rs serves rustdoc JSON zstd-compressed by default
    // (which Rust's reqwest doesn't auto-decode). Gzip is supported with .gz suffix
    // per https://docs.rs/about/rustdoc-json
    let url = format!(
        "{}/crate/{}/{}/json.gz",
        DOCS_RS_BASE,
        crate_name,
        ver_param
    );

    // docs.rs rate-limits (429) and occasionally returns 5xx. A single
    // transient failure would cause Rust recall loss for that type — without
    // retry, the symbol cache never gets populated and the type's methods
    // stay flagged as hallucinated. Bounded retry with exponential backoff
    // (1s, 3s) respects Retry-After when present. FETCH_SEMAPHORE in
    // symbols/mod.rs already gates concurrency to 2, so this is per-slot.
    const BACKOFF_SECS: [u64; 2] = [1, 3];
    let mut last_status_err = String::new();

    for attempt in 0..=BACKOFF_SECS.len() {
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("network: {}", e))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(format!(
                "crate {} not found on docs.rs (404) — wrong name or unpublished before 2025-05-23",
                crate_name
            ));
        }

        let status = resp.status();
        if status.is_success() {
            // Extract resolved version from final URL.
            // Final URL pattern: https://docs.rs/crate/<crate>/<version>/json.gz
            let final_url = resp.url().as_str();
            let resolved_version = extract_version_from_url(final_url, crate_name)
                .unwrap_or_else(|| ver_param.to_string());

            let compressed = resp
                .bytes()
                .await
                .map_err(|e| format!("read body: {}", e))?
                .to_vec();

            // Defense-in-depth: reject oversized responses (council #3 finding #5).
            // docs.rs rustdoc JSON for large crates (serde ~10MB compressed) —
            // 64MB cap is generous but prevents OOM on corrupt/compromised responses.
            const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
            if compressed.len() > MAX_COMPRESSED_BYTES {
                return Err(format!(
                    "rustdoc JSON body too large: {} bytes (cap {})",
                    compressed.len(), MAX_COMPRESSED_BYTES
                ));
            }

            // Decompress gzip with decompressed size cap (defense-in-depth
            // against zip bombs).
            use std::io::Read;
            use flate2::read::GzDecoder;
            const MAX_DECOMPRESSED_BYTES: usize = 256 * 1024 * 1024;
            let mut decoder = GzDecoder::new(&compressed[..]);
            let mut bytes = Vec::with_capacity(compressed.len().min(1024 * 1024) * 4);
            loop {
                let mut chunk = [0u8; 64 * 1024];
                let n = decoder.read(&mut chunk).map_err(|e| format!("gzip decompress: {}", e))?;
                if n == 0 { break; }
                if bytes.len() + n > MAX_DECOMPRESSED_BYTES {
                    return Err(format!(
                        "decompressed rustdoc JSON exceeds {} bytes cap",
                        MAX_DECOMPRESSED_BYTES
                    ));
                }
                bytes.extend_from_slice(&chunk[..n]);
            }

            return Ok((resolved_version, bytes));
        }

        // Retryable: 429 (Too Many Requests) or 5xx (server error).
        // Anything else (e.g., 403, 401) is treated as permanent.
        let retryable = status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error();
        if retryable && attempt < BACKOFF_SECS.len() {
            // Respect Retry-After header (seconds form only — HTTP-date
            // form is rare for docs.rs and adds date-parsing complexity).
            let wait = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or_else(|| Duration::from_secs(BACKOFF_SECS[attempt]));
            tracing::warn!(
                target: "symbols",
                attempt = attempt + 1,
                status = %status,
                wait_ms = wait.as_millis() as u64,
                crate_name = %crate_name,
                url = %url,
                "docs.rs transient error — retrying"
            );
            last_status_err = format!("docs_rs: status {} for {}", status, url);
            tokio::time::sleep(wait).await;
            continue;
        }

        return Err(format!("docs_rs: status {} for {}", status, url));
    }

    // Exhausted all retries.
    Err(if last_status_err.is_empty() {
        format!("docs_rs: retries exhausted for {}", url)
    } else {
        format!("{} (after {} retries)", last_status_err, BACKOFF_SECS.len())
    })
}

/// Parse version from final URL: .../crate/<crate>/<version>/json[.gz]
fn extract_version_from_url(url: &str, crate_name: &str) -> Option<String> {
    let suffixes = ["/json.gz", "/json"];
    let prefix = format!("/crate/{}/", crate_name);

    let trimmed = suffixes
        .iter()
        .find_map(|s| url.strip_suffix(s))
        .unwrap_or(url);

    let after_crate = trimmed.rsplit_once(&prefix)?.1;

    if after_crate.is_empty() || after_crate == "latest" {
        None
    } else {
        Some(after_crate.to_string())
    }
}

/// Check if file exists and was modified within the last 7 days.
fn is_file_fresh(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let elapsed = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    elapsed.as_secs() < 7 * 24 * 60 * 60
}

/// Resolve raw JSON storage directory for a given crate + version.
/// `~/.anubis/symbols/rust/<crate>/<version>/`
pub fn raw_dir_for(crate_name: &str, version: &str) -> PathBuf {
    let mut p = PathBuf::from(dirs_home());
    p.push(".anubis");
    p.push("symbols");
    p.push("rust");
    p.push(crate_name);
    p.push(version);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_dir_path_includes_crate_and_version() {
        let p = raw_dir_for("serde", "1.0.210");
        let s = p.to_string_lossy();
        assert!(s.contains("rust"));
        assert!(s.contains("serde"));
        assert!(s.contains("1.0.210"));
    }

    #[test]
    fn extract_version_from_real_url() {
        let url = "https://docs.rs/crate/serde/1.0.210/json.gz";
        assert_eq!(
            extract_version_from_url(url, "serde"),
            Some("1.0.210".to_string())
        );
    }

    #[test]
    fn extract_version_from_latest_redirect() {
        let url = "https://docs.rs/crate/tokio/1.40.0/json.gz";
        assert_eq!(
            extract_version_from_url(url, "tokio"),
            Some("1.40.0".to_string())
        );
    }

    #[test]
    fn extract_version_handles_crate_with_dashes() {
        // crate names can contain dashes (e.g., reqwest)
        let url = "https://docs.rs/crate/reqwest/0.12.8/json.gz";
        assert_eq!(
            extract_version_from_url(url, "reqwest"),
            Some("0.12.8".to_string())
        );
    }

    #[test]
    fn extract_version_returns_none_for_unrecognized_format() {
        let url = "https://example.com/something/else.json";
        assert_eq!(extract_version_from_url(url, "serde"), None);
    }

    #[test]
    fn is_file_fresh_returns_false_for_missing_file() {
        let p = Path::new("/nonexistent/anubis-test-12345.json");
        assert!(!is_file_fresh(p));
    }

    #[test]
    fn user_agent_includes_version() {
        assert!(USER_AGENT.starts_with("anubis-daemon/"));
        assert!(USER_AGENT.contains("github.com/robbe1912/anubis-public"));
    }

    #[tokio::test]
    #[ignore = "requires network + docs.rs access"]
    async fn fetch_real_serde_returns_json() {
        let result = fetch_rustdoc_json("serde", None).await;
        assert!(result.is_ok(), "fetch failed: {:?}", result.err());
        let r = result.unwrap();
        assert_eq!(r.crate_name, "serde");
        assert!(!r.version.is_empty());
        // Either fresh download (bytes > 0) or skipped-fresh (bytes = 0).
        // Both are valid — what matters is the file is on disk.
        assert!(r.raw_path.exists(), "file should exist after fetch: {}", r.raw_path.display());
    }

    #[tokio::test]
    #[ignore = "requires network — full fetch + parse pipeline"]
    async fn fetch_and_parse_serde_emits_symbols() {
        // Fetch (may skip-fresh if previous run cached)
        let fetch_result = fetch_rustdoc_json("serde", None).await.unwrap();
        assert!(!fetch_result.version.is_empty());

        // Read JSON from disk
        let json = std::fs::read_to_string(&fetch_result.raw_path).unwrap();
        assert!(json.len() > 100_000, "rustdoc JSON should be ~MB, got {}", json.len());

        // Parse
        let symbols =
            crate::symbols::rust_parser::parse_rustdoc_json(&json, "serde", &fetch_result.version)
                .expect("parse must succeed");
        assert!(
            symbols.len() > 50,
            "serde should emit at least 50 symbols, got {}",
            symbols.len()
        );

        // Verify a known top-level symbol
        let serialize_sym = symbols
            .iter()
            .find(|s| s.name == "Serialize")
            .expect("serde::Serialize trait must be in symbols");
        assert_eq!(serialize_sym.kind, crate::symbols::types::SymbolKind::Interface);
        assert_eq!(serialize_sym.path, "serde.Serialize");
    }
}
