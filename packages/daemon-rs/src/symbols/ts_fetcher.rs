//! TypeScript declaration (`.d.ts`) fetcher.
//!
//! Downloads the package's `.d.ts` files from unpkg.com (a fast npm CDN that
//! mirrors the npm registry). Stores raw text under
//! `~/.anubis/symbols/ts/<pkg>/<version>/raw/` for the parser to consume.
//!
//! unpkg endpoints (https://unpkg.com/):
//!   - `https://unpkg.com/<pkg>@<version>/`          → resolves to package root
//!   - `https://unpkg.com/<pkg>@<version>/<path>`    → serves that file
//!   - `https://unpkg.com/<pkg>@<version>/?meta`     → JSON directory listing
//!
//! Fetch strategy:
//!   1. Resolve version (follow redirect if `None`) by hitting `/<pkg>/package.json`.
//!   2. Hit `?meta` for the package root to enumerate files.
//!   3. Filter for paths ending in `.d.ts` (skip test files, `node_modules/`).
//!   4. Download each `.d.ts` into the raw dir.
//!   5. Also fetch `<pkg>/index.d.ts` and the path declared in `package.json`
//!      `types`/`typings` field as a fallback when `?meta` is unhelpful.
//!
//! The fetcher is intentionally robust to CDN quirks: if `?meta` 404s or
//! returns an unexpected shape, we fall back to common default paths.

use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use crate::dirs_home;
use crate::symbols::ts_parser;

const HTTP_TIMEOUT_SECS: u64 = 60;
const UNPKG_BASE: &str = "https://unpkg.com";
const JSDELIVR_BASE: &str = "https://cdn.jsdelivr.net/npm";
/// Maximum number of `.d.ts` files we'll fetch per package. Caps the worst
/// case where `?meta` lists thousands of files (e.g. `@types/node`).
const MAX_DTS_FILES: usize = 200;

static USER_AGENT: &str = concat!(
    "anubis-daemon/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/robbe1912/anubis-public)"
);

/// Result of a fetch operation. Mirrors `rust_fetcher::FetchResult` so the
/// symbols_cli glue can treat them interchangeably.
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub package: String,
    pub version: String,
    pub bytes_downloaded: usize,
    pub skipped_fresh: bool,
    /// All `.d.ts` files written to `raw_dir/`. Always non-empty on success.
    pub raw_files: Vec<PathBuf>,
    /// Parent dir (`~/.anubis/symbols/ts/<pkg>/<version>/`).
    pub raw_dir: PathBuf,
}

/// Fetch all `.d.ts` declarations for `package@version`.
///
/// `version = None` resolves to "latest" via unpkg's redirect.
pub async fn fetch_dts(
    package: &str,
    version: Option<&str>,
) -> Result<FetchResult, String> {
    let client = build_client()?;
    let ver_param = version.unwrap_or("latest");

    // Resolve real version via /package.json (follows redirect).
    let resolved_version = resolve_version(&client, package, ver_param).await?;

    let raw_dir = raw_dir_for(package, &resolved_version);
    let marker_path = raw_dir.join(".fetch-complete");

    // Freshness: if marker exists and is < 7 days old, skip re-fetch.
    if is_file_fresh(&marker_path) {
        let raw_files = list_cached_dts(&raw_dir);
        if !raw_files.is_empty() {
            return Ok(FetchResult {
                package: package.to_string(),
                version: resolved_version,
                bytes_downloaded: 0,
                skipped_fresh: true,
                raw_files,
                raw_dir,
            });
        }
    }

    // Enumerate candidate .d.ts files via ?meta.
    let dts_paths = enumerate_dts_paths(&client, package, &resolved_version).await?;

    if dts_paths.is_empty() {
        return Err(format!(
            "no .d.ts files found for {}@{} — not a TypeScript-typed package",
            package, resolved_version
        ));
    }

    std::fs::create_dir_all(&raw_dir)
        .map_err(|e| format!("create {}: {}", raw_dir.display(), e))?;

    let raw_subdir = raw_dir.join("raw");
    std::fs::create_dir_all(&raw_subdir)
        .map_err(|e| format!("create {}: {}", raw_subdir.display(), e))?;

    let mut total_bytes = 0usize;
    let mut raw_files = Vec::with_capacity(dts_paths.len().min(MAX_DTS_FILES));

    for rel_path in dts_paths.iter().take(MAX_DTS_FILES) {
        // Try jsDelivr first (faster CDN), then unpkg fallback.
        let urls = [
            format!("{}/{}@{}/{}", JSDELIVR_BASE, package, resolved_version, rel_path),
            format!("{}/{}@{}/{}", UNPKG_BASE, package, resolved_version, rel_path),
        ];
        let mut bytes: Option<Vec<u8>> = None;
        for url in &urls {
            match client.get(url).send().await {
                Ok(r) if r.status().is_success() => {
                    match r.bytes().await {
                        Ok(b) => {
                            bytes = Some(b.to_vec());
                            break;
                        }
                        Err(e) => {
                            tracing::debug!(target: "symbols", "read fail {}: {}", url, e);
                            continue;
                        }
                    }
                }
                Ok(r) => {
                    tracing::debug!(target: "symbols", "skip {} (status {})", url, r.status());
                    continue;
                }
                Err(e) => {
                    tracing::debug!(target: "symbols", "skip {} (network: {})", url, e);
                    continue;
                }
            }
        }
        let bytes = match bytes {
            Some(b) => b,
            None => continue,
        };

        // Flatten path into a filename (replace `/` with `__`).
        let flat = rel_path.replace('/', "__");
        let dest = raw_subdir.join(flat);
        std::fs::write(&dest, &bytes)
            .map_err(|e| format!("write {}: {}", dest.display(), e))?;
        total_bytes += bytes.len();
        raw_files.push(dest);
    }

    if raw_files.is_empty() {
        return Err(format!(
            "all .d.ts fetches failed for {}@{}",
            package, resolved_version
        ));
    }

    // Touch marker so we skip-fresh next time.
    let _ = std::fs::write(&marker_path, &resolved_version);

    Ok(FetchResult {
        package: package.to_string(),
        version: resolved_version,
        bytes_downloaded: total_bytes,
        skipped_fresh: false,
        raw_files,
        raw_dir,
    })
}

/// Fetch + parse + write a single consolidated `index.d.ts` representation
/// into the cache-friendly layout used by `symbols_cli`. Returns the
/// concatenated source for the parser.
pub async fn fetch_and_concat(
    package: &str,
    version: Option<&str>,
) -> Result<(FetchResult, String), String> {
    let result = fetch_dts(package, version).await?;
    let mut combined = String::new();
    for f in &result.raw_files {
        if let Ok(text) = std::fs::read_to_string(f) {
            combined.push_str(&text);
            combined.push_str("\n\n");
        }
    }
    Ok((result, combined))
}

// ─── Internals ───────────────────────────────────────────────────────

fn build_client() -> Result<Client, String> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("build reqwest client: {}", e))
}

async fn resolve_version(
    client: &Client,
    package: &str,
    requested: &str,
) -> Result<String, String> {
    // /<pkg>@<requested>/package.json — final URL after redirect contains
    // the resolved version.
    let url = format!("{}/{}@{}/package.json", UNPKG_BASE, package, requested);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("network: {}", e))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(format!("package {} not found on npm (404)", package));
    }
    if !resp.status().is_success() {
        return Err(format!("unpkg: status {} for {}", resp.status(), url));
    }
    // final URL like https://unpkg.com/react@18.2.0/package.json
    let final_url = resp.url().as_str();
    extract_version_from_url(final_url, package).ok_or_else(|| {
        format!(
            "could not extract resolved version from final URL: {}",
            final_url
        )
    })
}

fn extract_version_from_url(url: &str, package: &str) -> Option<String> {
    let prefix = format!("{}@", package);
    let after = url.split(&prefix).nth(1)?;
    // version is the segment between `@` and the next `/`
    let ver = after.split('/').next()?;
    if ver.is_empty() || ver == "latest" {
        None
    } else {
        Some(ver.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct MetaFile {
    path: String,
    #[serde(default)]
    r#type: String, // "file" | "directory"
}

#[derive(Debug, Deserialize)]
struct MetaResponse {
    #[serde(default)]
    files: Vec<MetaFile>,
}

/// Resolve `.d.ts` file paths from `package.json` `types`/`typings` + `exports` map.
/// Uses jsDelivr CDN (faster, more reliable than unpkg for large packages).
/// Derives `.d.ts` paths from JS paths in `exports` when no explicit `types`
/// condition exists (common for packages using modern `exports` without types).
async fn resolve_types_from_package_json(
    client: &Client,
    package: &str,
    version: &str,
) -> Vec<String> {
    let url = format!("{}/{}@{}/package.json", JSDELIVR_BASE, package, version);
    let text = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    let pkg: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut paths = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let normalize = |s: &str| -> String {
        s.trim_start_matches("./").trim_start_matches('/').to_string()
    };
    let add = |p: &str, paths: &mut Vec<String>, seen: &mut std::collections::HashSet<String>| {
        if p.ends_with(".d.ts") {
            let n = normalize(p);
            if seen.insert(n.clone()) {
                paths.push(n);
            }
        }
    };

    // 1. Root types/typings field
    for key in ["types", "typings"] {
        if let Some(types) = pkg.get(key).and_then(|v| v.as_str()) {
            add(types, &mut paths, &mut seen);
        }
    }

    // 2. Exports map — resolve types for each subpath entry
    if let Some(exports) = pkg.get("exports").and_then(|v| v.as_object()) {
        for (_, conditions) in exports {
            // Direct types condition
            if let Some(types_path) = conditions.get("types").and_then(|v| v.as_str()) {
                add(types_path, &mut paths, &mut seen);
            }
            // Nested conditions (import/require/default) with types
            for cond_key in ["import", "require", "default"] {
                if let Some(cond) = conditions.get(cond_key) {
                    if let Some(types_path) = cond.get("types").and_then(|v| v.as_str()) {
                        add(types_path, &mut paths, &mut seen);
                    }
                }
            }
            // Derive .d.ts from JS paths when no explicit types condition
            for cond_key in ["import", "require", "default"] {
                if let Some(js_path) = conditions.get(cond_key).and_then(|v| v.as_str()) {
                    if js_path.starts_with("./") {
                        let base = js_path
                            .trim_end_matches(".mjs")
                            .trim_end_matches(".cjs")
                            .trim_end_matches(".js");
                        let dts = format!("{}.d.ts", base);
                        add(&dts, &mut paths, &mut seen);
                    }
                }
            }
        }
    }

    paths
}

/// Enumerate `.d.ts` file paths under the package root via `?meta`.
/// Falls back to a small set of well-known paths when meta fails.
async fn enumerate_dts_paths(
    client: &Client,
    package: &str,
    version: &str,
) -> Result<Vec<String>, String> {
    // Strategy 1: Resolve from package.json types/exports via jsDelivr (fast, targeted).
    // Catches modern packages (exports without types condition) where unpkg ?meta
    // is slow or incomplete. e.g. @trpc/server has types at dist/adapters/express.d.ts
    // derived from exports['./adapters/express'].import = './dist/adapters/express.mjs'.
    let resolved = resolve_types_from_package_json(client, package, version).await;
    if !resolved.is_empty() {
        tracing::debug!(
            target: "symbols",
            package, version,
            "resolved {} .d.ts paths from package.json exports",
            resolved.len()
        );
        return Ok(resolved);
    }

    // Strategy 2: unpkg ?meta file listing.
    let url = format!("{}/{}@{}/?meta", UNPKG_BASE, package, version);
    let resp = client.get(&url).send().await;
    let paths: Vec<String> = match resp {
        Ok(r) if r.status().is_success() => match r.json::<MetaResponse>().await {
            Ok(body) => body
                .files
                .into_iter()
                .filter(|f| f.r#type == "file" && f.path.ends_with(".d.ts"))
                .map(|f| f.path.trim_start_matches('/').to_string())
                .filter(|p| !p.contains("node_modules/") && !p.contains("/tests/") && !p.contains("/test/"))
                .collect(),
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    };

    if !paths.is_empty() {
        return Ok(paths);
    }

    // Fallback: try common default paths.
    let fallback = [
        "index.d.ts".to_string(),
        "package.json".to_string(), // parser tolerates — actually skipped
        "dist/index.d.ts".to_string(),
        "lib/index.d.ts".to_string(),
        "types/index.d.ts".to_string(),
    ];
    let mut confirmed = Vec::new();
    for path in &fallback {
        if !path.ends_with(".d.ts") {
            continue;
        }
        let check_url = format!("{}/{}@{}/{}", UNPKG_BASE, package, version, path);
        if let Ok(r) = client.head(&check_url).send().await {
            if r.status().is_success() {
                confirmed.push(path.clone());
            }
        }
    }
    Ok(confirmed)
}

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

fn list_cached_dts(raw_dir: &Path) -> Vec<PathBuf> {
    let raw_subdir = raw_dir.join("raw");
    let Ok(entries) = std::fs::read_dir(&raw_subdir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "ts")
                .unwrap_or(false)
        })
        .collect()
}

/// Resolve raw storage dir for a given package + version.
/// `~/.anubis/symbols/ts/<package>/<version>/`
pub fn raw_dir_for(package: &str, version: &str) -> PathBuf {
    let mut p = PathBuf::from(dirs_home());
    p.push(".anubis");
    p.push("symbols");
    p.push("ts");
    p.push(package);
    p.push(version);
    p
}

// Re-export parser entry for tests + symbols_cli.
pub use ts_parser::parse_dts;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_dir_path_includes_package_and_version() {
        let p = raw_dir_for("react", "18.2.0");
        let s = p.to_string_lossy();
        assert!(s.contains("ts"));
        assert!(s.contains("react"));
        assert!(s.contains("18.2.0"));
    }

    #[test]
    fn extract_version_from_real_unpkg_url() {
        let url = "https://unpkg.com/react@18.2.0/package.json";
        assert_eq!(
            extract_version_from_url(url, "react"),
            Some("18.2.0".to_string())
        );
    }

    #[test]
    fn extract_version_from_scoped_package() {
        let url = "https://unpkg.com/@types/react@18.2.0/package.json";
        assert_eq!(
            extract_version_from_url(url, "@types/react"),
            Some("18.2.0".to_string())
        );
    }

    #[test]
    fn extract_version_returns_none_for_unknown_url() {
        assert_eq!(extract_version_from_url("https://example.com", "react"), None);
    }

    #[test]
    fn is_file_fresh_returns_false_for_missing_file() {
        assert!(!is_file_fresh(Path::new("/nonexistent/anubis-test-xyz")));
    }

    #[test]
    fn user_agent_includes_version() {
        assert!(USER_AGENT.starts_with("anubis-daemon/"));
        assert!(USER_AGENT.contains("github.com/robbe1912/anubis-public"));
    }

    #[tokio::test]
    #[ignore = "requires network + unpkg access"]
    async fn fetch_real_react_dts_writes_files() {
        let result = fetch_dts("react", None).await;
        assert!(result.is_ok(), "fetch failed: {:?}", result.err());
        let r = result.unwrap();
        assert_eq!(r.package, "react");
        assert!(!r.version.is_empty());
        assert!(!r.raw_files.is_empty(), "should have written >=1 .d.ts");
    }
}
