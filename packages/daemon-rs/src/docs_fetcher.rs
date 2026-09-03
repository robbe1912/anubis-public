// docs_fetcher — fetch external documentation into ~/.anubis/docs/ for scanner.
//
// Strategies (cheapest-first per quota economics):
//   1. npm registry    — unlimited, README + types
//   2. GitHub API      — 5K/hr authed, README + docs/
//   3. Context7 API    — 200/10d anonymous per-IP OR 1K/mo with CONTEXT7_API_KEY
//   4. Website scrape  — single URL, html2markdown conversion
//   5. Local path      — recursive .md/.txt copy
//
// Output: ~/.anubis/docs/<slug>/<slug>.md (+ meta.json)
// Files use ## headings so scanner::extract_docs_section() can match terms.

use crate::config::config_dir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Source classification
// ---------------------------------------------------------------------------

/// Classified input source. Caller dispatches to the matching fetcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocSource {
    /// `owner/repo` — GitHub repository.
    GitHub { owner: String, repo: String },
    /// `name` or `@scope/name` — npm package.
    Npm { name: String },
    /// Bare name resolved via Context7 (last-resort registry).
    Context7 { name: String },
    /// `https://...` URL — single-page website scrape.
    Website { url: String },
    /// `./path` or `/path` — local directory copy.
    Local { path: PathBuf },
}

impl DocSource {
    /// Stable slug used as the on-disk directory name under ~/.anubis/docs/.
    pub fn slug(&self) -> String {
        match self {
            DocSource::GitHub { owner, repo } => slugify(&format!("{}-{}", owner, repo)),
            DocSource::Npm { name } => slugify(name),
            DocSource::Context7 { name } => slugify(name),
            DocSource::Website { url } => slugify_url(url),
            DocSource::Local { path } => {
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "local".to_string());
                slugify(&name)
            }
        }
    }
}

/// Detect source kind from raw user input.
///
/// Order matters: local paths and URLs are unambiguous; GitHub is `owner/repo`;
/// single tokens (with optional `@scope/`) are npm; everything else falls back
/// to Context7.
pub fn detect_source(input: &str) -> Result<DocSource, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty source".to_string());
    }

    // Website: starts with http:// or https://
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(DocSource::Website {
            url: trimmed.to_string(),
        });
    }

    // Local path: starts with ./ ../ / or ~
    if trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('/')
        || trimmed.starts_with('~')
        || trimmed == "."
        || trimmed == ".."
    {
        let expanded = expand_tilde(trimmed);
        return Ok(DocSource::Local {
            path: PathBuf::from(expanded),
        });
    }

    // Windows absolute path: drive letter prefix (C:\, D:\, ...)
    if trimmed.len() >= 3 {
        let bytes = trimmed.as_bytes();
        if bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
            && bytes[0].is_ascii_alphabetic()
        {
            return Ok(DocSource::Local {
                path: PathBuf::from(trimmed),
            });
        }
    }

    // GitHub: exactly one slash, no scheme, both sides non-empty, no leading @
    // e.g. "RtlZeroMemory/Rezi", "godotengine/godot"
    // NOT "@scope/pkg" (starts with @), NOT "owner/repo/sub" (multiple slashes)
    if !trimmed.starts_with('@') && trimmed.matches('/').count() == 1 {
        let mut parts = trimmed.splitn(2, '/');
        let owner = parts.next().unwrap_or("");
        let repo = parts.next().unwrap_or("");
        if !owner.is_empty() && !repo.is_empty() {
            let valid = |s: &str| {
                s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            };
            if valid(owner) && valid(repo) {
                return Ok(DocSource::GitHub {
                    owner: owner.to_string(),
                    repo: repo.to_string(),
                });
            }
        }
        return Err(format!("invalid GitHub reference: {}", trimmed));
    }

    // npm: starts with @ (scoped) OR is a single token matching npm name rules
    if trimmed.starts_with('@') {
        let after_at = &trimmed[1..];
        if after_at.matches('/').count() == 1 {
            let mut parts = after_at.splitn(2, '/');
            let scope = parts.next().unwrap_or("");
            let name = parts.next().unwrap_or("");
            let valid = |s: &str| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            };
            if valid(scope) && valid(name) {
                return Ok(DocSource::Npm {
                    name: trimmed.to_string(),
                });
            }
        }
        return Err(format!("invalid scoped npm package: {}", trimmed));
    }

    // Unscoped npm: no slashes, matches typical package name
    let is_unscoped_npm = !trimmed.contains('/')
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !trimmed.is_empty();
    if is_unscoped_npm {
        return Ok(DocSource::Npm {
            name: trimmed.to_string(),
        });
    }

    // Fallback: treat as Context7 lookup
    Ok(DocSource::Context7 {
        name: trimmed.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Path + slug helpers
// ---------------------------------------------------------------------------

/// Root directory for all fetched doc sets: ~/.anubis/docs/
pub fn docs_root() -> PathBuf {
    if let Ok(dir) = std::env::var("ANUBIS_DOCS_DIR") {
        return PathBuf::from(dir);
    }
    config_dir().join("docs")
}

/// Per-source directory: ~/.anubis/docs/<slug>/
pub fn doc_set_dir(slug: &str) -> PathBuf {
    docs_root().join(slug)
}

/// Convert arbitrary text to a filesystem-safe lowercase slug.
///
/// Rules: lowercase → replace runs of non-alphanumeric with `-` → trim leading/trailing `-`.
pub fn slugify(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_dash = true; // suppress leading dash
    for c in lower.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

/// Slugify a URL: strip scheme, replace separators.
pub fn slugify_url(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let no_query = stripped.split('?').next().unwrap_or(stripped);
    let no_frag = no_query.split('#').next().unwrap_or(no_query);
    let trimmed = no_frag.trim_end_matches('/');
    slugify(trimmed)
}

/// Expand leading `~` to the user's home directory (cross-platform).
fn expand_tilde(input: &str) -> String {
    if input.starts_with('~') {
        let home = crate::config::home_dir();
        let rest = &input[1..];
        let rest = rest.strip_prefix(std::path::MAIN_SEPARATOR).unwrap_or(rest);
        return home.join(rest).to_string_lossy().to_string();
    }
    input.to_string()
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// Per-doc-set metadata persisted as meta.json alongside the .md files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocMeta {
    /// Original user-provided source string (e.g. `RtlZeroMemory/Rezi`).
    pub source: String,
    /// Strategy that produced this doc set (e.g. `github`, `npm`, `context7`).
    pub strategy: String,
    /// RFC3339 fetch timestamp.
    pub fetched_at: String,
    /// Library / package version if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// File names written under this doc set (e.g. `["react.md"]`).
    pub files: Vec<String>,
}

const META_FILENAME: &str = "meta.json";

/// Write a doc set to ~/.anubis/docs/<slug>/.
///
/// `files` is a list of `(filename, content)` pairs. The slug directory is
/// created if missing. Any existing files in the slug dir are removed first
/// so a refresh produces a clean state.
pub fn write_doc_set(
    slug: &str,
    files: &[(String, String)],
    meta: &DocMeta,
) -> Result<PathBuf, String> {
    let dir = doc_set_dir(slug);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir_all failed: {}", e))?;

    // Clean previous file contents (refresh semantics). Don't touch subdirs.
    if dir.exists() {
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("read_dir failed: {}", e))? {
            let entry = entry.map_err(|e| format!("read_dir entry failed: {}", e))?;
            let path = entry.path();
            if path.is_file() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    for (name, content) in files {
        let path = dir.join(name);
        std::fs::write(&path, content).map_err(|e| format!("write {} failed: {}", name, e))?;
    }

    let meta_path = dir.join(META_FILENAME);
    let meta_json =
        serde_json::to_string_pretty(meta).map_err(|e| format!("serialize meta failed: {}", e))?;
    std::fs::write(&meta_path, meta_json).map_err(|e| format!("write meta failed: {}", e))?;

    Ok(dir)
}

/// Read meta.json for a slug. Returns Ok(None) if the dir or file is missing.
pub fn read_meta(slug: &str) -> Result<Option<DocMeta>, String> {
    let path = doc_set_dir(slug).join(META_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read meta failed: {}", e))?;
    let meta: DocMeta =
        serde_json::from_str(&raw).map_err(|e| format!("parse meta failed: {}", e))?;
    Ok(Some(meta))
}

/// List all installed doc sets by slug. Skips hidden cache dirs.
pub fn list_doc_sets() -> Vec<(String, Option<DocMeta>)> {
    let root = docs_root();
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let slug = entry.file_name().to_string_lossy().to_string();
        if slug.starts_with('.') {
            continue;
        }
        let meta = read_meta(&slug).unwrap_or(None);
        out.push((slug, meta));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Remove a doc set by slug. Returns Ok(false) if the dir didn't exist.
pub fn remove_doc_set(slug: &str) -> Result<bool, String> {
    let dir = doc_set_dir(slug);
    if !dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dir).map_err(|e| format!("remove_dir_all failed: {}", e))?;
    Ok(true)
}

/// Resolve a slug from any user input by detecting source then deriving slug.
pub fn slug_for_input(input: &str) -> Result<String, String> {
    let source = detect_source(input)?;
    Ok(source.slug())
}

/// Walk a doc set dir collecting `<filename, content>` for .md/.txt files.
/// Mirrors scanner::build_docs_index but scoped to one slug.
#[allow(dead_code)]
fn read_doc_set_files(slug: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let dir = doc_set_dir(slug);
    if !dir.exists() {
        return out;
    }
    walk_dir(&dir, &mut out);
    out
}

fn walk_dir(dir: &Path, out: &mut HashMap<String, String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, out);
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".md") || name.ends_with(".txt") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                out.insert(name, content);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fetching — strategies
// ---------------------------------------------------------------------------

/// Result of a successful fetch. Persisted via `persist_fetch_result`.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// Slug for the doc set directory.
    pub slug: String,
    /// Files to write: `(filename, content)`. Filenames must end in `.md`.
    pub files: Vec<(String, String)>,
    /// Strategy identifier persisted to meta.json (`npm`, `github`, ...).
    pub strategy: &'static str,
    /// Library / package version, if known.
    pub version: Option<String>,
}

/// HTTP client with anubis user-agent + sane timeout.
fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent("anubis-docs-fetcher")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client build failed: {}", e))
}

/// Current time as RFC3339 UTC.
fn now_rfc3339() -> String {
    use chrono::Utc;
    Utc::now().to_rfc3339()
}

/// Persist a FetchResult to ~/.anubis/docs/<slug>/ + meta.json,
/// then invalidate the scanner cache so the new docs are visible immediately.
pub fn persist_fetch_result(res: &FetchResult, source: &str) -> Result<PathBuf, String> {
    let meta = DocMeta {
        source: source.to_string(),
        strategy: res.strategy.to_string(),
        fetched_at: now_rfc3339(),
        version: res.version.clone(),
        files: res.files.iter().map(|(n, _)| n.clone()).collect(),
    };
    let dir = write_doc_set(&res.slug, &res.files, &meta)?;
    crate::scanner::invalidate_docs_cache();
    Ok(dir)
}

// ── Remote Worker adapters ────────────────────────────────────────────────

/// Fetch markdown for `library` at `version` from the anubis-docs Worker.
///
/// Thin adapter over `remote_docs::fetch_remote_docs` so callers (e.g. the
/// dashboard CLI) can stay decoupled from the remote_docs module shape.
/// Returns `None` on any error — network, non-200, empty body, oversize body.
pub async fn fetch_remote(library: &str, version: &str) -> Option<String> {
    crate::remote_docs::fetch_remote_docs(library, version).await
}

/// Resolve the latest version string for `library` from the Worker.
///
/// Thin adapter over `remote_docs::resolve_remote_latest`. Returns `None` on
/// any error — caller is expected to fall back to a local strategy.
pub async fn resolve_remote_latest(library: &str) -> Option<String> {
    crate::remote_docs::resolve_remote_latest(library).await
}

// ── npm registry ──────────────────────────────────────────────────────────

/// Fetch a package's README from npm registry.
/// Endpoint: GET https://registry.npmjs.org/<pkg> (URL-encode scoped `/`).
pub async fn fetch_npm(client: &reqwest::Client, name: &str) -> Result<FetchResult, String> {
    // URL-encode the package name's slash for scoped packages.
    let url_path: String = name.replace('/', "%2F");
    let url = format!("https://registry.npmjs.org/{}", url_path);

    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("npm request failed: {}", e))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(format!("npm package not found: {}", name));
    }
    if !resp.status().is_success() {
        return Err(format!("npm request returned {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("npm response parse failed: {}", e))?;

    // The registry returns full packument; we want latest dist-tags + version
    let latest_version = body
        .pointer("/dist-tags/latest")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let latest = match &latest_version {
        Some(v) => body.pointer(&format!("/versions/{}", v)),
        None => None,
    };

    // Prefer readme field on the version, fall back to top-level readme.
    let readme = latest
        .and_then(|v| v.get("readme"))
        .and_then(|v| v.as_str())
        .or_else(|| body.get("readme").and_then(|v| v.as_str()))
        .or_else(|| {
            // Some packuments only have readmeFilename
            body.get("readmeFilename").and_then(|v| v.as_str())
        })
        .unwrap_or("");

    if readme.trim().is_empty() {
        return Err(format!("npm package has no readme: {}", name));
    }

    let slug = slugify(name);
    let filename = format!("{}.md", slug);
    Ok(FetchResult {
        slug,
        files: vec![(filename, readme.to_string())],
        strategy: "npm",
        version: latest_version,
    })
}

// ── GitHub API ────────────────────────────────────────────────────────────

/// Optional GitHub personal access token from env (raises 5K/hr authed limit).
fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok()
        .filter(|s| !s.is_empty())
}

/// Maximum number of `docs/` files to download per repo.
const MAX_GITHUB_DOCS_FILES: usize = 20;

/// Fetch a repo's README + any .md files under `docs/` (capped).
pub async fn fetch_github(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
) -> Result<FetchResult, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        "application/vnd.github+json".parse().unwrap(),
    );
    if let Some(token) = github_token() {
        if let Ok(v) = format!("Bearer {}", token).parse() {
            headers.insert(reqwest::header::AUTHORIZATION, v);
        }
    }

    // 1. README (raw)
    let readme_url = format!("https://api.github.com/repos/{}/{}/readme", owner, repo);
    let readme_resp = client
        .get(&readme_url)
        .headers(headers.clone())
        .header(reqwest::header::ACCEPT, "application/vnd.github.raw+json")
        .send()
        .await
        .map_err(|e| format!("github readme request failed: {}", e))?;

    if readme_resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(format!("github repo not found: {}/{}", owner, repo));
    }
    if readme_resp.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(format!(
            "github rate-limited or forbidden (set GITHUB_TOKEN env to raise limit): {}/{}",
            owner, repo
        ));
    }
    if !readme_resp.status().is_success() {
        return Err(format!(
            "github readme request returned {}",
            readme_resp.status()
        ));
    }

    let readme = readme_resp
        .text()
        .await
        .map_err(|e| format!("github readme body failed: {}", e))?;

    let slug = slugify(&format!("{}-{}", owner, repo));
    let mut files: Vec<(String, String)> = Vec::new();
    let readme_name = format!("{}.md", slug);
    files.push((readme_name, readme));

    // 2. docs/ directory listing (best-effort)
    let docs_listing_url = format!(
        "https://api.github.com/repos/{}/{}/contents/docs",
        owner, repo
    );
    let docs_resp = client
        .get(&docs_listing_url)
        .headers(headers.clone())
        .send()
        .await;

    if let Ok(resp) = docs_resp {
        if resp.status().is_success() {
            if let Ok(arr) = resp.json::<serde_json::Value>().await {
                if let Some(entries) = arr.as_array() {
                    let mut md_count = 0;
                    for entry in entries {
                        if md_count >= MAX_GITHUB_DOCS_FILES {
                            break;
                        }
                        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let download_url = entry
                            .get("download_url")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if !name.ends_with(".md") || download_url.is_empty() {
                            continue;
                        }
                        if let Ok(file_resp) = client.get(download_url).send().await {
                            if file_resp.status().is_success() {
                                if let Ok(text) = file_resp.text().await {
                                    // Use a flat filename to keep scanner's filename-term matching working.
                                    let safe_name = slugify(name.trim_end_matches(".md"));
                                    files.push((format!("{}.md", safe_name), text));
                                    md_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(FetchResult {
        slug,
        files,
        strategy: "github",
        version: None,
    })
}

// ── Context7 ──────────────────────────────────────────────────────────────

const CONTEXT7_INDEX_PATH: &str = ".context7-index.json";

/// Optional Context7 API key from env (1K/mo per user). Anonymous = 200/10d per IP.
fn context7_key() -> Option<String> {
    std::env::var("CONTEXT7_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
}

fn context7_index_path() -> PathBuf {
    docs_root().join(CONTEXT7_INDEX_PATH)
}

/// Load the libraryId cache: `{ pkg_name -> library_id }`.
fn load_context7_index() -> HashMap<String, String> {
    let path = context7_index_path();
    let mut map = HashMap::new();
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(&raw) {
            map.extend(parsed);
        }
    }
    map
}

/// Persist the libraryId cache (best-effort; missing parent dir is OK).
fn save_context7_index(map: &HashMap<String, String>) {
    let path = context7_index_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(map) {
        let _ = std::fs::write(&path, json);
    }
}

/// Fetch docs via Context7.
///
/// Uses the libraryId cache to skip `/v2/libs/search` on repeat fetches.
/// Anonymous tier = 200/10d per IP. `CONTEXT7_API_KEY` env raises to 1K/mo per user.
pub async fn fetch_context7(client: &reqwest::Client, name: &str) -> Result<FetchResult, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::ACCEPT, "text/plain".parse().unwrap());
    if let Some(key) = context7_key() {
        if let Ok(v) = format!("Bearer {}", key).parse() {
            headers.insert(reqwest::header::AUTHORIZATION, v);
        }
    }

    // 1. Resolve libraryId (use cache if present)
    let mut index = load_context7_index();
    let library_id = match index.get(name) {
        Some(id) => id.clone(),
        None => {
            let search_url = format!(
                "https://context7.com/api/v2/libs/search?libraryName={}",
                urlencoding_encode(name)
            );
            let resp = client
                .get(&search_url)
                .headers(headers.clone())
                .send()
                .await
                .map_err(|e| format!("context7 search request failed: {}", e))?;

            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let retry = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                let msg = match retry {
                    Some(secs) if secs > 86400 => {
                        format!(
                            "Context7 quota exhausted, reset in ~{} days. Set CONTEXT7_API_KEY env var for 1,000 calls/month higher limit.",
                            secs / 86400
                        )
                    }
                    Some(secs) => format!(
                        "Context7 quota exhausted, retry after {}s. Set CONTEXT7_API_KEY for higher limit.",
                        secs
                    ),
                    None => "Context7 quota exhausted. Set CONTEXT7_API_KEY for higher limit.".to_string(),
                };
                return Err(msg);
            }
            if !resp.status().is_success() {
                return Err(format!("context7 search returned {}", resp.status()));
            }

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("context7 search parse failed: {}", e))?;

            let id = body
                .pointer("/results/0/id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("Context7 found no match for: {}", name))?
                .to_string();

            index.insert(name.to_string(), id.clone());
            save_context7_index(&index);
            id
        }
    };

    // 2. Fetch context as plain text
    let context_url = format!(
        "https://context7.com/api/v2/context?libraryId={}&topic={}",
        urlencoding_encode(&library_id),
        urlencoding_encode(name)
    );
    let resp = client
        .get(&context_url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| format!("context7 context request failed: {}", e))?;

    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(
            "Context7 quota exhausted during context fetch. Set CONTEXT7_API_KEY for higher limit."
                .to_string(),
        );
    }
    if !resp.status().is_success() {
        return Err(format!("context7 context returned {}", resp.status()));
    }

    let content = resp
        .text()
        .await
        .map_err(|e| format!("context7 body parse failed: {}", e))?;

    if content.trim().is_empty() {
        return Err(format!("Context7 returned empty content for: {}", name));
    }

    let slug = slugify(name);
    let filename = format!("{}.md", slug);
    Ok(FetchResult {
        slug,
        files: vec![(filename, content)],
        strategy: "context7",
        version: Some(library_id),
    })
}

/// Minimal URL-query encoder: percent-encode everything except `[A-Za-z0-9_.~-]`.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let c = *b;
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{:02X}", c));
        }
    }
    out
}

// ── Website ───────────────────────────────────────────────────────────────

/// Minimum length of converted markdown before treating it as a real page.
/// Below this we assume JS-rendered SPA with no static content.
const MIN_WEBSITE_MD_LEN: usize = 50;

/// Fetch a single URL, convert HTML → markdown.
pub async fn fetch_website(client: &reqwest::Client, url: &str) -> Result<FetchResult, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("website request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("website request returned {}", resp.status()));
    }

    let html = resp
        .text()
        .await
        .map_err(|e| format!("website body read failed: {}", e))?;

    let markdown = html2markdown::convert(&html);

    if markdown.trim().len() < MIN_WEBSITE_MD_LEN {
        return Err(format!(
            "website returned no usable content (likely JS-rendered SPA, {} bytes after convert). Use the GitHub source instead.",
            markdown.len()
        ));
    }

    let slug = slugify_url(url);
    let filename = format!("{}.md", slug);
    Ok(FetchResult {
        slug,
        files: vec![(filename, markdown)],
        strategy: "website",
        version: None,
    })
}

// ── Local path ────────────────────────────────────────────────────────────

/// Recursively copy `.md`/`.txt` files from a local path into a doc set.
pub fn fetch_local(path: &Path) -> Result<FetchResult, String> {
    if !path.exists() {
        return Err(format!("local path does not exist: {}", path.display()));
    }

    let mut collected: HashMap<String, String> = HashMap::new();
    if path.is_dir() {
        walk_dir(path, &mut collected);
    } else if path.is_file() {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "local.md".to_string());
        if name.ends_with(".md") || name.ends_with(".txt") {
            if let Ok(content) = std::fs::read_to_string(path) {
                collected.insert(name, content);
            }
        }
    }

    if collected.is_empty() {
        return Err(format!(
            "local path contains no .md/.txt files: {}",
            path.display()
        ));
    }

    // Derive slug from dir/file name
    let slug = path
        .file_name()
        .map(|s| slugify(&s.to_string_lossy()))
        .unwrap_or_else(|| "local".to_string());
    if slug.is_empty() {
        return Err(format!("cannot derive slug from path: {}", path.display()));
    }

    let mut files: Vec<(String, String)> = collected.into_iter().collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(FetchResult {
        slug,
        files,
        strategy: "local",
        version: None,
    })
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/// Dispatch to the matching fetcher based on `DocSource` variant.
///
/// Fetch order for `Npm` includes a Context7 fallback when npm misses — this is
/// the only auto-fallback; all other variants run their single strategy.
pub async fn fetch_source(source: &DocSource) -> Result<FetchResult, String> {
    let client = http_client()?;
    match source {
        DocSource::Npm { name } => match fetch_npm(&client, name).await {
            Ok(res) => Ok(res),
            Err(npm_err) => {
                // Fall back to Context7 only for npm — keeps Context7 quota predictable.
                eprintln!(
                    "[anubis] npm miss ({}), trying Context7 fallback...",
                    npm_err
                );
                fetch_context7(&client, name).await
            }
        },
        DocSource::GitHub { owner, repo } => fetch_github(&client, owner, repo).await,
        DocSource::Context7 { name } => fetch_context7(&client, name).await,
        DocSource::Website { url } => fetch_website(&client, url).await,
        DocSource::Local { path } => fetch_local(path),
    }
}

/// Convenience: detect source from raw input, fetch, persist to disk.
/// Returns the installed directory path on success.
pub async fn fetch_from_input(input: &str) -> Result<PathBuf, String> {
    let source = detect_source(input)?;
    let result = fetch_source(&source).await?;
    persist_fetch_result(&result, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── slugify ──────────────────────────────────────────────────────────

    #[test]
    fn slugify_lowercase_alnum() {
        assert_eq!(slugify("React"), "react");
        assert_eq!(slugify("ReactRouter"), "reactrouter");
    }

    #[test]
    fn slugify_replaces_non_alnum() {
        assert_eq!(slugify("@scope/pkg"), "scope-pkg");
        assert_eq!(slugify("foo bar baz"), "foo-bar-baz");
        assert_eq!(slugify("foo.bar_baz"), "foo-bar-baz");
    }

    #[test]
    fn slugify_trims_dashes() {
        assert_eq!(slugify("---foo---"), "foo");
        assert_eq!(slugify("..."), "");
        assert_eq!(slugify(""), "");
    }

    #[test]
    fn slugify_preserves_digits() {
        assert_eq!(slugify("react19"), "react19");
        assert_eq!(slugify("v2.0.1"), "v2-0-1");
    }

    // ── slugify_url ──────────────────────────────────────────────────────

    #[test]
    fn slugify_url_strips_scheme_and_query() {
        assert_eq!(slugify_url("https://example.com"), "example-com");
        assert_eq!(
            slugify_url("https://docs.python.org/3/library/os"),
            "docs-python-org-3-library-os"
        );
        assert_eq!(
            slugify_url("https://react.dev/learn?foo=bar"),
            "react-dev-learn"
        );
    }

    #[test]
    fn slugify_url_trims_trailing_slash() {
        assert_eq!(slugify_url("https://example.com/"), "example-com");
    }

    // ── detect_source ────────────────────────────────────────────────────

    #[test]
    fn detect_github_owner_repo() {
        let s = detect_source("godotengine/godot").unwrap();
        assert_eq!(
            s,
            DocSource::GitHub {
                owner: "godotengine".into(),
                repo: "godot".into()
            }
        );
    }

    #[test]
    fn detect_npm_unscoped() {
        let s = detect_source("react").unwrap();
        assert_eq!(
            s,
            DocSource::Npm {
                name: "react".into()
            }
        );
    }

    #[test]
    fn detect_npm_scoped() {
        let s = detect_source("@rezi-ui/core").unwrap();
        assert_eq!(
            s,
            DocSource::Npm {
                name: "@rezi-ui/core".into()
            }
        );
    }

    #[test]
    fn detect_website_http() {
        let s = detect_source("https://docs.python.org/3/").unwrap();
        assert_eq!(
            s,
            DocSource::Website {
                url: "https://docs.python.org/3/".into()
            }
        );
    }

    #[test]
    fn detect_local_unix_relative() {
        let s = detect_source("./docs").unwrap();
        assert_eq!(
            s,
            DocSource::Local {
                path: PathBuf::from("./docs")
            }
        );
    }

    #[test]
    fn detect_local_unix_absolute() {
        let s = detect_source("/home/user/docs").unwrap();
        assert_eq!(
            s,
            DocSource::Local {
                path: PathBuf::from("/home/user/docs")
            }
        );
    }

    #[test]
    fn detect_local_windows_drive() {
        let s = detect_source(r"C:\Users\foo\docs").unwrap();
        assert_eq!(
            s,
            DocSource::Local {
                path: PathBuf::from(r"C:\Users\foo\docs")
            }
        );
    }

    #[test]
    fn detect_empty_errors() {
        assert!(detect_source("").is_err());
        assert!(detect_source("   ").is_err());
    }

    #[test]
    fn detect_invalid_github_rejects_whitespace() {
        assert!(detect_source("foo bar/baz").is_err());
    }

    #[test]
    fn detect_github_rejects_multiple_slashes_falls_to_context7() {
        let s = detect_source("foo/bar/baz").unwrap();
        assert_eq!(
            s,
            DocSource::Context7 {
                name: "foo/bar/baz".into()
            }
        );
    }

    // ── slug from source ─────────────────────────────────────────────────

    #[test]
    fn slug_github() {
        let s = DocSource::GitHub {
            owner: "RtlZeroMemory".into(),
            repo: "Rezi".into(),
        };
        assert_eq!(s.slug(), "rtlzeromemory-rezi");
    }

    #[test]
    fn slug_npm_scoped() {
        let s = DocSource::Npm {
            name: "@rezi-ui/core".into(),
        };
        assert_eq!(s.slug(), "rezi-ui-core");
    }

    #[test]
    fn slug_website() {
        let s = DocSource::Website {
            url: "https://docs.python.org/3/".into(),
        };
        assert_eq!(s.slug(), "docs-python-org-3");
    }

    // ── DocMeta round-trip ───────────────────────────────────────────────

    #[test]
    fn meta_round_trip() {
        let tmp = std::env::temp_dir().join("anubis_docs_test_meta_round_trip");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let meta = DocMeta {
            source: "react".into(),
            strategy: "npm".into(),
            fetched_at: "2026-07-21T10:00:00Z".into(),
            version: Some("19.0.0".into()),
            files: vec!["react.md".into()],
        };
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let path = tmp.join("meta.json");
        std::fs::write(&path, &json).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: DocMeta = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.source, "react");
        assert_eq!(parsed.strategy, "npm");
        assert_eq!(parsed.version.as_deref(), Some("19.0.0"));
        assert_eq!(parsed.files, vec!["react.md".to_string()]);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── path helpers ─────────────────────────────────────────────────────

    #[test]
    fn docs_root_under_anubis_config() {
        let root = docs_root();
        assert!(root.ends_with("docs"));
        assert!(root.starts_with(config_dir()));
    }

    #[test]
    fn doc_set_dir_appends_slug() {
        let dir = doc_set_dir("react");
        assert!(dir.ends_with("react"));
        assert!(dir.starts_with(docs_root()));
    }

    #[test]
    fn slug_for_input_round_trip() {
        assert_eq!(slug_for_input("react").unwrap(), "react");
        assert_eq!(
            slug_for_input("RtlZeroMemory/Rezi").unwrap(),
            "rtlzeromemory-rezi"
        );
        assert_eq!(slug_for_input("@rezi-ui/core").unwrap(), "rezi-ui-core");
    }
}
