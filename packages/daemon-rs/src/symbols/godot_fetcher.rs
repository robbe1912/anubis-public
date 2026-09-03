//! Godot class reference fetcher.
//!
//! Downloads ~1500 XML files from github.com/godotengine/godot/doc/classes/
//! at the requested version (tag or branch). Stores raw XML under
//! ~/.anubis/symbols/godot/<version>/raw/*.xml for the parser to consume.
//!
//! Tier behavior:
//!   - Both Offline and Subscription tiers use this (daemon fetches direct
//!     from GitHub, Worker doesn't proxy this — saves bandwidth)
//!   - GITHUB_TOKEN env var enables 5K/hr quota (anonymous = 60/hr)

use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::dirs_home;

/// Default version if none specified. Master branch is bleeding-edge;
/// stable releases use `master` until we pin to a tag like `4.3-stable`.
const DEFAULT_VERSION: &str = "master";

/// Concurrency cap for parallel XML downloads.
/// GitHub tolerates ~10 concurrent requests per IP comfortably.
const MAX_CONCURRENT_DOWNLOADS: usize = 5;

/// HTTP timeout for any single request (list or download).
const HTTP_TIMEOUT_SECS: u64 = 60;

/// User-Agent identifies us to GitHub — required by their ToS.
static USER_AGENT: &str = concat!(
    "anubis-daemon/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/robbe1912/anubis-public)"
);

/// Semaphore reused across calls to bound concurrency.
static DOWNLOAD_SEMAPHORE: Lazy<Semaphore> =
    Lazy::new(|| Semaphore::const_new(MAX_CONCURRENT_DOWNLOADS));

/// Optional GitHub token from env (GITHUB_TOKEN or GH_TOKEN).
/// Raises 60/hr anon ceiling to 5K/hr authed.
static GITHUB_TOKEN: Lazy<Option<String>> =
    Lazy::new(|| env::var("GITHUB_TOKEN").or_else(|_| env::var("GH_TOKEN")).ok());

/// Entry returned by GitHub Contents API.
#[derive(Debug, Deserialize)]
struct ContentsEntry {
    name: String,
    #[serde(rename = "type")]
    kind: String,
}

/// Result of a fetch operation.
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub version: String,
    pub files_downloaded: usize,
    pub files_skipped_fresh: usize,
    pub files_failed: usize,
    pub raw_dir: PathBuf,
}

/// Fetch all Godot class XML files at the given version.
///
/// Stores under `~/.anubis/symbols/godot/<version>/raw/*.xml`.
/// Skips files already present and fresh (< 7 days old).
///
/// Returns total file count on success. Errors abort the batch but
/// already-downloaded files remain on disk.
pub async fn fetch_godot_classes(version: Option<&str>) -> Result<FetchResult, String> {
    let version = version.unwrap_or(DEFAULT_VERSION);
    let raw_dir = raw_dir_for(version);

    // Ensure raw/ dir exists
    if let Err(e) = std::fs::create_dir_all(&raw_dir) {
        return Err(format!("failed to create {}: {}", raw_dir.display(), e));
    }

    let client = build_client()?;

    // Step 1: list files in godotengine/godot/doc/classes at this ref
    let files = list_class_files(&client, version).await?;

    // Filter to .xml files only (some versions have README or .meta files)
    let xml_files: Vec<String> = files
        .into_iter()
        .filter(|name| name.ends_with(".xml"))
        .collect();

    if xml_files.is_empty() {
        return Err(format!(
            "no XML files found at godotengine/godot@{} in doc/classes/ — wrong tag?",
            version
        ));
    }

    // Step 2: download each (skipping fresh ones)
    let mut downloaded = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    // Process in small batches to avoid saturating the semaphore wait queue
    for chunk in xml_files.chunks(MAX_CONCURRENT_DOWNLOADS) {
        let mut tasks = Vec::with_capacity(chunk.len());

        for file_name in chunk {
            let target_path = raw_dir.join(file_name);

            // Skip if file exists and is fresh (< 7 days)
            if is_file_fresh(&target_path) {
                skipped += 1;
                continue;
            }

            let client = client.clone();
            let file_name = file_name.clone();
            let version_owned = version.to_string();

            let permit = DOWNLOAD_SEMAPHORE.acquire().await.map_err(|e| e.to_string())?;
            tasks.push(tokio::spawn(async move {
                let _permit = permit; // hold until done
                let result = download_one(&client, &version_owned, &file_name, &target_path).await;
                (file_name, result)
            }));
        }

        // Wait for batch
        for task in tasks {
            match task.await {
                Ok((_name, Ok(true))) => downloaded += 1,
                Ok((name, Ok(false))) => {
                    tracing::warn!("download failed silently: {}", name);
                    failed += 1;
                }
                Ok((name, Err(e))) => {
                    tracing::warn!("download error for {}: {}", name, e);
                    failed += 1;
                }
                Err(e) => {
                    tracing::error!("task panicked: {}", e);
                    failed += 1;
                }
            }
        }
    }

    Ok(FetchResult {
        version: version.to_string(),
        files_downloaded: downloaded,
        files_skipped_fresh: skipped,
        files_failed: failed,
        raw_dir,
    })
}

/// Build the HTTP client with UA + timeout.
fn build_client() -> Result<Client, String> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("failed to build reqwest client: {}", e))
}

/// List XML file names in godotengine/godot/doc/classes at the given ref.
/// Uses GitHub Contents API: GET /repos/{owner}/{repo}/contents/{path}?ref={ref}
async fn list_class_files(client: &Client, version: &str) -> Result<Vec<String>, String> {
    let url = format!(
        "https://api.github.com/repos/godotengine/godot/contents/doc/classes?ref={}",
        version
    );

    let mut req = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");

    if let Some(token) = GITHUB_TOKEN.as_deref() {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req.send().await.map_err(|e| format!("network: {}", e))?;

    if resp.status() == reqwest::StatusCode::FORBIDDEN {
        // Likely rate-limited
        let reset = resp
            .headers()
            .get("X-RateLimit-Reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let retry_after = reset
            .map(|ts| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                ts.saturating_sub(now)
            })
            .unwrap_or(60);
        return Err(format!(
            "rate_limited: GitHub API quota exhausted, retry after {}s",
            retry_after
        ));
    }

    if !resp.status().is_success() {
        return Err(format!("github_api: status {}", resp.status()));
    }

    let entries: Vec<ContentsEntry> =
        resp.json().await.map_err(|e| format!("parse: {}", e))?;

    Ok(entries
        .into_iter()
        .filter(|e| e.kind == "file")
        .map(|e| e.name)
        .collect())
}

/// Download a single XML file from raw.githubusercontent.com.
/// Returns Ok(true) if downloaded, Ok(false) if fetch succeeded but body
/// wasn't written for some reason, Err on network failure.
async fn download_one(
    client: &Client,
    version: &str,
    file_name: &str,
    target_path: &Path,
) -> Result<bool, String> {
    let url = format!(
        "https://raw.githubusercontent.com/godotengine/godot/{}/doc/classes/{}",
        version, file_name
    );

    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("status {} for {}", resp.status(), file_name));
    }

    let body = resp.bytes().await.map_err(|e| e.to_string())?;

    // Atomic-ish write: write to .tmp then rename
    let tmp_path = target_path.with_extension("xml.tmp");
    std::fs::write(&tmp_path, &body)
        .map_err(|e| format!("write tmp {}: {}", tmp_path.display(), e))?;
    std::fs::rename(&tmp_path, target_path)
        .map_err(|e| format!("rename to {}: {}", target_path.display(), e))?;

    Ok(true)
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

/// Resolve raw XML storage directory for a given version.
/// `~/.anubis/symbols/godot/<version>/raw/`
pub fn raw_dir_for(version: &str) -> PathBuf {
    let mut p = PathBuf::from(dirs_home());
    p.push(".anubis");
    p.push("symbols");
    p.push("godot");
    p.push(version);
    p.push("raw");
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_dir_path_includes_version() {
        let p = raw_dir_for("4.3-stable");
        assert!(p.to_string_lossy().contains("godot"));
        assert!(p.to_string_lossy().contains("4.3-stable"));
        assert!(p.to_string_lossy().contains("raw"));
    }

    #[test]
    fn default_version_is_master() {
        assert_eq!(DEFAULT_VERSION, "master");
    }

    #[test]
    fn semaphore_allows_configured_concurrency() {
        // Just verifies the const is sensible
        assert!(MAX_CONCURRENT_DOWNLOADS > 0);
        assert!(MAX_CONCURRENT_DOWNLOADS <= 10);
    }

    #[test]
    fn user_agent_includes_version() {
        assert!(USER_AGENT.starts_with("anubis-daemon/"));
        assert!(USER_AGENT.contains("github.com/robbe1912/anubis-public"));
    }

    #[test]
    fn is_file_fresh_returns_false_for_missing_file() {
        let p = Path::new("/nonexistent/anubis-test-12345.xml");
        assert!(!is_file_fresh(p));
    }

    #[tokio::test]
    #[ignore = "requires network + GitHub API access"]
    async fn fetch_real_master_lists_1500_files() {
        // Smoke test — only run manually with --ignored
        let result = fetch_godot_classes(Some("master")).await;
        assert!(result.is_ok(), "fetch failed: {:?}", result.err());
        let r = result.unwrap();
        assert!(r.files_downloaded + r.files_skipped_fresh > 1000);
    }
}
