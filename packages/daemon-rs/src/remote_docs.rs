// remote_docs — HTTP client for the anubis-docs Worker.
//
// Client for a self-hostable docs Worker. The original Worker instance is retired;
// the protocol it spoke (unchanged) exposes:
//   GET /v1/docs/:lib/:ver   → markdown body
//   GET /v1/resolve/:lib     → JSON { "library", "version", "source" }
//
// Scanner calls `fetch_remote_docs` as a fallback when local docs miss; any
// network/HTTP/parse error returns `None` and the caller keeps falling back.
// License key (optional) is read from `ANUBIS_LICENSE_KEY` and sent as a
// Bearer token. Worker base URL is overridable via `ANUBIS_DOCS_URL`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const DEFAULT_WORKER_BASE_URL: &str = "https://docs.codeanubis.com";
const HTTP_TIMEOUT_SECS: u64 = 10;
const MAX_BODY_BYTES: usize = 1_048_576; // 1 MB
const USER_AGENT: &str = "anubis-daemon";
/// Disk-cache TTL — matches the Worker's `Cache-Control: max-age=86400`
/// so cache expiry and edge expiry stay aligned. 24 hours.
const REMOTE_CACHE_TTL_SECS: u64 = 86_400;
/// Monotonic counter for unique temp-file names across concurrent cache writes.
static WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch markdown for `library` at `version` from the Worker.
///
/// Returns `None` on any error — network, non-200 status, empty body, body
/// over `MAX_BODY_BYTES`. Never panics.
///
/// Disk-cache fast path: the most recent successful fetch within
/// `REMOTE_CACHE_TTL_SECS` is reused without hitting the network, halving
/// R2 reads and Worker CPU ms on repeat scans. Cache writes are best-effort
/// (any IO error is logged to stderr and swallowed).
pub async fn fetch_remote_docs(library: &str, version: &str) -> Option<String> {
    // 1. Disk cache fast path — return immediately on a fresh hit.
    if let Some(cached) = read_remote_cache(library, version) {
        return Some(cached);
    }

    // 2. Network fetch (existing logic).
    let base = worker_base_url();
    let encoded = url_encode_library(library);
    let url = format!("{}/v1/docs/{}/{}", base, encoded, url_encode_library(version));

    let body = http_get_text(&url).await?;
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return None;
    }

    // 3. Best-effort cache populate — silent on IO error.
    write_remote_cache(library, version, &body);

    // 4. Return body.
    Some(body)
}

/// Resolve the latest version string for `library` from the Worker.
///
/// Returns `None` on any error — network, non-200 status, malformed JSON,
/// missing `version` field. Never panics.
pub async fn resolve_remote_latest(library: &str) -> Option<String> {
    let base = worker_base_url();
    let url = format!("{}/v1/resolve/{}", base, url_encode_library(library));

    let body = http_get_text(&url).await?;
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_str(&body).ok()?;
    let version = parsed.get("version")?.as_str()?;
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

// ---------------------------------------------------------------------------
// Disk cache — 24h TTL under ~/.anubis/docs/.remote-cache/
// ---------------------------------------------------------------------------
//
// Layout:
//   ~/.anubis/docs/.remote-cache/<lib>-<ver>.md           <- markdown body
//   ~/.anubis/docs/.remote-cache/<lib>-<ver>.meta.json    <- {"fetched_at": <epoch_secs>}
//
// The directory is dot-prefixed so `scanner::build_docs_index` skips it
// (added explicitly in scanner.rs). Atomic writes use temp + rename so a
// crash mid-write never leaves a half-written body in place.

/// Cache root: `~/.anubis/docs/.remote-cache/`.
fn remote_cache_dir() -> PathBuf {
    crate::config::config_dir()
        .join("docs")
        .join(".remote-cache")
}

/// Filename-safe form of a library or version segment.
///
/// Strip a leading `@`, pass alphanumerics and `-_.` through, replace every
/// other char (including `/`) with `-`. So `@scope/pkg` → `scope-pkg`.
fn sanitize_cache_segment(s: &str) -> String {
    let stripped = s.strip_prefix('@').unwrap_or(s);
    let mut out = String::with_capacity(stripped.len());
    for c in stripped.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    out
}

/// Combined `<library>-<version>` stem shared by the .md and .meta.json files.
fn remote_cache_stem(library: &str, version: &str) -> String {
    format!(
        "{}-{}",
        sanitize_cache_segment(library),
        sanitize_cache_segment(version)
    )
}

/// Path to the cached markdown body for `(library, version)`.
fn remote_cache_path(library: &str, version: &str) -> PathBuf {
    remote_cache_dir().join(format!("{}.md", remote_cache_stem(library, version)))
}

/// Path to the cache metadata file (`{"fetched_at": <epoch_secs>}`).
fn remote_cache_meta_path(library: &str, version: &str) -> PathBuf {
    remote_cache_dir().join(format!("{}.meta.json", remote_cache_stem(library, version)))
}

/// Read a cached body if both files exist and the meta timestamp is within TTL.
///
/// Returns `None` on any IO error, malformed meta JSON, missing
/// `fetched_at` field, or expired timestamp. Never panics. Clock skew
/// (future timestamps) is treated as fresh via `saturating_sub`.
fn read_remote_cache(library: &str, version: &str) -> Option<String> {
    let body_path = remote_cache_path(library, version);
    let meta_path = remote_cache_meta_path(library, version);

    let content = std::fs::read_to_string(&body_path).ok()?;
    let meta_raw = std::fs::read_to_string(&meta_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&meta_raw).ok()?;
    let fetched_at = parsed.get("fetched_at")?.as_u64()?;
    let now = now_epoch_secs();
    if now.saturating_sub(fetched_at) >= REMOTE_CACHE_TTL_SECS {
        return None;
    }
    Some(content)
}

/// Persist a fetched body to the cache atomically (temp file + rename).
///
/// Best-effort: any IO error is logged to stderr and swallowed so a cache
/// failure never breaks the fetch flow.
fn write_remote_cache(library: &str, version: &str, content: &str) {
    if let Err(err) = try_write_remote_cache(library, version, content) {
        eprintln!(
            "[anubis] remote cache write failed for {}@{}: {}",
            library, version, err
        );
    }
}

/// Atomic-write implementation. Errors propagate as a human-readable string
/// so the public `write_remote_cache` can log them.
fn try_write_remote_cache(library: &str, version: &str, content: &str) -> Result<(), String> {
    let dir = remote_cache_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir_all: {}", e))?;

    let stem = remote_cache_stem(library, version);
    let body_final = dir.join(format!("{}.md", stem));
    let meta_final = dir.join(format!("{}.meta.json", stem));

    atomic_write(&body_final, content.as_bytes())?;
    let meta = serde_json::json!({ "fetched_at": now_epoch_secs() }).to_string();
    atomic_write(&meta_final, meta.as_bytes())?;

    Ok(())
}

/// Write `bytes` to `final_path` via a sibling temp file then rename. The
/// temp name embeds PID + a monotonic counter so concurrent writers do not
/// stomp each other's temp files. `std::fs::rename` atomically replaces an
/// existing destination on POSIX and on modern Windows (NTFS).
fn atomic_write(final_path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let pid = std::process::id();
    let counter = WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("cache");
    let tmp_path = final_path.with_file_name(format!("{}.tmp.{}.{}", base, pid, counter));

    std::fs::write(&tmp_path, bytes).map_err(|e| format!("write tmp: {}", e))?;
    std::fs::rename(&tmp_path, final_path).map_err(|e| {
        // Best-effort cleanup of the orphaned temp file before propagating.
        let _ = std::fs::remove_file(&tmp_path);
        format!("rename: {}", e)
    })
}

/// Current time as epoch seconds. Returns 0 if the system clock is before
/// UNIX_EPOCH (only possible on misconfigured hosts); a 0 timestamp makes a
/// fresh cache entry look expired on the next read, which is safe.
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Internal HTTP helpers
// ---------------------------------------------------------------------------

/// Worker base URL — env override `ANUBIS_DOCS_URL` wins, else default.
fn worker_base_url() -> String {
    std::env::var("ANUBIS_DOCS_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_WORKER_BASE_URL.to_string())
}

/// Optional license key from env (sent as `Authorization: Bearer <key>`).
fn license_key() -> Option<String> {
    std::env::var("ANUBIS_LICENSE_KEY")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Build a reqwest client with anubis UA + 10s timeout.
fn http_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .ok()
}

/// Issue a GET with optional Bearer auth, return response body as text on 200.
///
/// Returns `None` on connect failure, timeout, non-200, or body read error.
/// Enforces the global timeout via both the client builder and a wrapping
/// `tokio::time::timeout` belt-and-braces guard.
async fn http_get_text(url: &str) -> Option<String> {
    let client = http_client()?;

    let request = async {
        let mut req = client.get(url);
        if let Some(key) = license_key() {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", key)) {
                req = req.header(reqwest::header::AUTHORIZATION, v);
            }
        }
        let resp = req.send().await?;
        if resp.status() != reqwest::StatusCode::OK {
            return Ok::<Vec<u8>, reqwest::Error>(Vec::new());
        }
        // Read the full body and cap at MAX_BODY_BYTES — Worker payloads are
        // well under 1MB markdown so this is bounded by the timeout if a
        // misbehaving endpoint streams gigabytes at us.
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    };

    let outcome = tokio::time::timeout(Duration::from_secs(HTTP_TIMEOUT_SECS), request).await;
    match outcome {
        Ok(Ok(bytes)) if !bytes.is_empty() && bytes.len() <= MAX_BODY_BYTES => {
            Some(bytes_to_string_lossy(&bytes))
        }
        _ => None,
    }
}

/// Lossy UTF-8 conversion (defensive against malformed Worker output).
fn bytes_to_string_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// URL-encode a library or version segment.
///
/// Library names like `@scope/pkg` need `@` and `/` encoded so they survive
/// path-segment parsing. Keep this minimal — alphanumerics, `-`, `_`, `.`,
/// `~` pass through (RFC 3986 unreserved set).
fn url_encode_library(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for &b in name.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── worker_base_url ──────────────────────────────────────────────────

    #[test]
    #[test]
    fn worker_base_url_defaults_when_env_unset() {
        let _g = SERIAL_GUARD.lock();
        let prev = std::env::var("ANUBIS_DOCS_URL").ok();
        std::env::remove_var("ANUBIS_DOCS_URL");
        assert_eq!(worker_base_url(), DEFAULT_WORKER_BASE_URL);
        match prev {
            Some(v) => std::env::set_var("ANUBIS_DOCS_URL", v),
            None => std::env::remove_var("ANUBIS_DOCS_URL"),
        }
    }

    #[test]
    fn worker_base_url_ignores_empty_env() {
        let _g = SERIAL_GUARD.lock();
        let prev = std::env::var("ANUBIS_DOCS_URL").ok();
        std::env::set_var("ANUBIS_DOCS_URL", "");
        assert_eq!(worker_base_url(), DEFAULT_WORKER_BASE_URL);
        match prev {
            Some(v) => std::env::set_var("ANUBIS_DOCS_URL", v),
            None => std::env::remove_var("ANUBIS_DOCS_URL"),
        }
    }

    // ── license_key ──────────────────────────────────────────────────────

    #[test]
    fn license_key_none_when_unset() {
        let _g = SERIAL_GUARD.lock();
        let prev = std::env::var("ANUBIS_LICENSE_KEY").ok();
        std::env::remove_var("ANUBIS_LICENSE_KEY");
        assert!(license_key().is_none());
        match prev {
            Some(v) => std::env::set_var("ANUBIS_LICENSE_KEY", v),
            None => std::env::remove_var("ANUBIS_LICENSE_KEY"),
        }
    }

    #[test]
    fn license_key_none_when_empty() {
        let _g = SERIAL_GUARD.lock();
        let prev = std::env::var("ANUBIS_LICENSE_KEY").ok();
        std::env::set_var("ANUBIS_LICENSE_KEY", "");
        assert!(license_key().is_none());
        match prev {
            Some(v) => std::env::set_var("ANUBIS_LICENSE_KEY", v),
            None => std::env::remove_var("ANUBIS_LICENSE_KEY"),
        }
    }

    #[test]
    fn license_key_some_when_set() {
        let _g = SERIAL_GUARD.lock();
        let prev = std::env::var("ANUBIS_LICENSE_KEY").ok();
        std::env::set_var("ANUBIS_LICENSE_KEY", "anubis-test-key");
        assert_eq!(license_key().as_deref(), Some("anubis-test-key"));
        match prev {
            Some(v) => std::env::set_var("ANUBIS_LICENSE_KEY", v),
            None => std::env::remove_var("ANUBIS_LICENSE_KEY"),
        }
    }

    // ── url_encode_library ───────────────────────────────────────────────

    #[test]
    fn url_encode_keeps_unreserved() {
        assert_eq!(url_encode_library("react"), "react");
        assert_eq!(url_encode_library("lodash-es"), "lodash-es");
        assert_eq!(url_encode_library("pkg.name_v2"), "pkg.name_v2");
        assert_eq!(url_encode_library("a~b"), "a~b");
    }

    #[test]
    fn url_encode_scoped_package() {
        // @scope/pkg → %40scope%2Fpkg
        assert_eq!(url_encode_library("@scope/pkg"), "%40scope%2Fpkg");
    }

    #[test]
    fn url_encode_version() {
        assert_eq!(url_encode_library("18.2.0"), "18.2.0");
        assert_eq!(url_encode_library("^1.2.3"), "%5E1.2.3");
        assert_eq!(url_encode_library("next"), "next");
    }

    // ── bytes_to_string_lossy ────────────────────────────────────────────

    #[test]
    fn bytes_to_string_lossy_handles_valid_utf8() {
        let bytes = b"hello world".to_vec();
        assert_eq!(bytes_to_string_lossy(&bytes), "hello world");
    }

    #[test]
    fn bytes_to_string_lossy_replaces_invalid_utf8() {
        // 0xFF is invalid as a UTF-8 lead byte — should become U+FFFD, not panic.
        let bytes = vec![b'a', 0xFF, b'b'];
        let s = bytes_to_string_lossy(&bytes);
        assert!(s.starts_with('a'));
        assert!(s.ends_with('b'));
        assert!(s.contains('\u{FFFD}'));
    }

    // ── http_client ──────────────────────────────────────────────────────

    #[test]
    fn http_client_builds_without_panic() {
        // Build a client just to confirm the builder config is valid. We don't
        // issue a request here — that path is exercised by integration tests.
        let client = http_client();
        assert!(client.is_some());
    }

    // ── disk-cache helpers ──────────────────────────────────────────────
    //
    // Tests that touch HOME/USERPROFILE hold SERIAL_GUARD because env vars
    // are process-global and parallel test runs would race on `dirs_home()`.

    /// Process-wide lock — any test mutating USERPROFILE/HOME holds this for
    /// its full body.
    static SERIAL_GUARD: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn lock() -> parking_lot::MutexGuard<'static, ()> {
        SERIAL_GUARD.lock()
    }

    /// RAII env override that sets BOTH USERPROFILE and HOME (so the test
    /// works on Windows + Unix) and restores prior values on drop.
    struct HomeGuard {
        prev_userprofile: Option<std::ffi::OsString>,
        prev_home: Option<std::ffi::OsString>,
    }

    impl HomeGuard {
        fn set(value: &str) -> Self {
            let prev_userprofile = std::env::var_os("USERPROFILE");
            let prev_home = std::env::var_os("HOME");
            std::env::set_var("USERPROFILE", value);
            std::env::set_var("HOME", value);
            Self {
                prev_userprofile,
                prev_home,
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
            match &self.prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    /// Per-test scratch dir under `std::env::temp_dir()`. Cleanup on drop.
    struct TmpDir(std::path::PathBuf);

    impl TmpDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("anubis_remote_cache_test_{}", name));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── sanitize_cache_segment / remote_cache_path ──────────────────────

    #[test]
    fn remote_cache_path_sanitizes_scoped_library() {
        // @scope/pkg + latest → scope-pkg-latest.md
        let path = remote_cache_path("@scope/pkg", "latest");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("scope-pkg-latest.md")
        );
    }

    #[test]
    fn remote_cache_path_strips_at_prefix() {
        // @foo + 1.0.0 → foo-1.0.0.md
        let path = remote_cache_path("@foo", "1.0.0");
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some("foo-1.0.0.md")
        );
    }

    // ── read_remote_cache ───────────────────────────────────────────────

    #[test]
    fn read_remote_cache_returns_none_when_missing() {
        let _serial = lock();
        let tmp = TmpDir::new("read_missing");
        let _home = HomeGuard::set(&tmp.path().to_string_lossy());

        let result = read_remote_cache("react", "1.0.0");
        assert!(
            result.is_none(),
            "expected None when no cache files exist, got {:?}",
            result
        );
    }

    #[test]
    fn read_remote_cache_returns_content_when_fresh() {
        let _serial = lock();
        let tmp = TmpDir::new("read_fresh");
        let _home = HomeGuard::set(&tmp.path().to_string_lossy());

        write_remote_cache("react", "1.0.0", "# react body");
        let result = read_remote_cache("react", "1.0.0");
        assert_eq!(result.as_deref(), Some("# react body"));
    }

    #[test]
    fn read_remote_cache_returns_none_when_expired() {
        let _serial = lock();
        let tmp = TmpDir::new("read_expired");
        let _home = HomeGuard::set(&tmp.path().to_string_lossy());

        // Write a fresh cache, then rewrite the meta with a 25h-old timestamp.
        write_remote_cache("react", "1.0.0", "body");
        let meta_path = remote_cache_meta_path("react", "1.0.0");
        let twenty_five_hours_ago =
            now_epoch_secs().saturating_sub(REMOTE_CACHE_TTL_SECS + 3_600);
        let meta = serde_json::json!({ "fetched_at": twenty_five_hours_ago }).to_string();
        std::fs::write(&meta_path, &meta).unwrap();

        let result = read_remote_cache("react", "1.0.0");
        assert!(result.is_none(), "expected None when cache is expired");
    }

    #[test]
    fn read_remote_cache_returns_none_when_meta_corrupt() {
        let _serial = lock();
        let tmp = TmpDir::new("read_corrupt_meta");
        let _home = HomeGuard::set(&tmp.path().to_string_lossy());

        write_remote_cache("react", "1.0.0", "body");
        let meta_path = remote_cache_meta_path("react", "1.0.0");
        std::fs::write(&meta_path, b"not json").unwrap();

        let result = read_remote_cache("react", "1.0.0");
        assert!(
            result.is_none(),
            "expected None when meta JSON is malformed, got {:?}",
            result
        );
    }

    // ── write_remote_cache ──────────────────────────────────────────────

    #[test]
    fn write_remote_cache_creates_files() {
        let _serial = lock();
        let tmp = TmpDir::new("write_creates");
        let _home = HomeGuard::set(&tmp.path().to_string_lossy());

        write_remote_cache("react", "1.0.0", "## body");

        let body_path = remote_cache_path("react", "1.0.0");
        let meta_path = remote_cache_meta_path("react", "1.0.0");
        assert!(
            body_path.exists(),
            "body file should exist at {}",
            body_path.display()
        );
        assert!(
            meta_path.exists(),
            "meta file should exist at {}",
            meta_path.display()
        );

        // Meta must parse and expose a numeric fetched_at.
        let meta_raw = std::fs::read_to_string(&meta_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&meta_raw).unwrap();
        let fetched_at = parsed
            .get("fetched_at")
            .and_then(|v| v.as_u64())
            .expect("fetched_at present and numeric");
        let now = now_epoch_secs();
        // Within a 60s window to absorb test runner latency.
        assert!(
            fetched_at <= now && fetched_at + 60 >= now,
            "fetched_at {} should be ~= now {}",
            fetched_at,
            now
        );
    }

    #[test]
    fn write_remote_cache_silent_on_io_error() {
        let _serial = lock();
        // Make HOME point at an existing file so `create_dir_all` under it
        // fails (parent is not a directory). write_remote_cache must not panic.
        let marker = std::env::temp_dir().join("anubis_remote_cache_test_silent_marker");
        if std::fs::write(&marker, "x").is_err() { return; }
        let _home = HomeGuard::set(&marker.to_string_lossy());

        let result = std::panic::catch_unwind(|| {
            write_remote_cache("react", "1.0.0", "body");
        });
        assert!(
            result.is_ok(),
            "write_remote_cache must not panic on IO error"
        );

        let _ = std::fs::remove_file(&marker);
    }
}
