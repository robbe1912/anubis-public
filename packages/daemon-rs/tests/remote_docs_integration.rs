// Integration tests for remote_docs — HTTP client for the anubis-docs Worker.
//
// All tests use `wiremock::MockServer` to spin up a real TCP listener that
// impersonates the Worker, so they are `#[ignore]`-gated. Run with:
//
//     cargo test --test remote_docs_integration -- --ignored
//
// Or a single one:
//
//     cargo test --test remote_docs_integration fetch_remote_docs_returns_body_on_200 -- --ignored
//
// Each test sets `ANUBIS_DOCS_URL` to point at its mock server. Tests are
// serialized through `SERIAL_GUARD` because env vars are process-global and
// parallel runs would race on `ANUBIS_DOCS_URL` / `ANUBIS_LICENSE_KEY`.
//
// Every `fetch_remote_docs` test also isolates HOME/USERPROFILE via
// `CacheIsolation` so the 24h disk cache does not leak between tests (or
// into the developer's real `~/.anubis/docs/.remote-cache/`).

use anubis_daemon::remote_docs;
use std::sync::{Mutex, MutexGuard};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Process-wide lock — every test in this binary acquires it for its full
/// body so env-var mutation cannot race with another ignored test.
static SERIAL_GUARD: Mutex<()> = Mutex::new(());

/// Acquire the serialization lock. Poisond mutex is recovered into inner.
fn lock() -> MutexGuard<'static, ()> {
    SERIAL_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// RAII guard that restores an env var to its prior value (or unsets it).
struct EnvGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvGuard {
    /// Set `key` to `value`, restoring the prior value on drop.
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }

    /// Remove `key`, restoring the prior value on drop.
    fn remove(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

/// RAII env override that sets BOTH USERPROFILE and HOME (so the test works
/// on Windows + Unix) and restores prior values on drop.
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

/// Isolate the 24h disk cache to a per-test throwaway temp dir.
///
/// Creates a unique temp dir, points HOME/USERPROFILE at it (so cache writes
/// land there instead of the developer's real `~/.anubis/`), and tears down
/// both the env override and the dir on drop. Every `fetch_remote_docs`
/// integration test must hold one of these so prior cache writes cannot
/// leak into the next test.
struct CacheIsolation {
    tmp: std::path::PathBuf,
    _home: HomeGuard,
}

impl CacheIsolation {
    fn new(test_name: &str) -> Self {
        let tmp = std::env::temp_dir()
            .join(format!("anubis_remote_cache_integration_{}", test_name));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create temp dir for cache isolation");
        let home = HomeGuard::set(&tmp.to_string_lossy());
        Self { tmp, _home: home }
    }
}

impl Drop for CacheIsolation {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

// ── fetch_remote_docs ─────────────────────────────────────────────────────

#[tokio::test]
#[ignore] // spins up a TCP listener
async fn fetch_remote_docs_returns_body_on_200() {
    let _serial = lock();
    let _cache = CacheIsolation::new("returns_body_on_200");
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/docs/react/18.2.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string("## react\nbody"))
        .mount(&server)
        .await;

    let result = remote_docs::fetch_remote_docs("react", "18.2.0").await;
    assert_eq!(result.as_deref(), Some("## react\nbody"));
}

#[tokio::test]
#[ignore]
async fn fetch_remote_docs_returns_none_on_404() {
    let _serial = lock();
    let _cache = CacheIsolation::new("returns_none_on_404");
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/docs/does-not-exist/1.0.0"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let result = remote_docs::fetch_remote_docs("does-not-exist", "1.0.0").await;
    assert!(result.is_none(), "expected None on 404, got {:?}", result);
}

#[tokio::test]
#[ignore]
async fn fetch_remote_docs_returns_none_on_connection_refused() {
    let _serial = lock();
    let _cache = CacheIsolation::new("returns_none_on_connection_refused");
    // Point at a port that is virtually guaranteed to refuse the connection.
    // 127.0.0.1:1 is reserved and unbindable on every common OS.
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", "http://127.0.0.1:1");

    let result = remote_docs::fetch_remote_docs("react", "18.2.0").await;
    assert!(result.is_none(), "expected None on conn refused, got {:?}", result);
}

#[tokio::test]
#[ignore]
async fn fetch_remote_docs_returns_none_on_500() {
    let _serial = lock();
    let _cache = CacheIsolation::new("returns_none_on_500");
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/docs/broken/1.0.0"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let result = remote_docs::fetch_remote_docs("broken", "1.0.0").await;
    assert!(result.is_none());
}

#[tokio::test]
#[ignore]
async fn fetch_remote_docs_returns_none_on_empty_body() {
    let _serial = lock();
    let _cache = CacheIsolation::new("returns_none_on_empty_body");
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/docs/empty/1.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let result = remote_docs::fetch_remote_docs("empty", "1.0.0").await;
    assert!(result.is_none(), "empty body should map to None");
}

#[tokio::test]
#[ignore]
async fn fetch_remote_docs_encodes_scoped_library_name() {
    let _serial = lock();
    let _cache = CacheIsolation::new("encodes_scoped_library_name");
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    // @scope/pkg must be URL-encoded on the path.
    Mock::given(method("GET"))
        .and(path("/v1/docs/%40scope%2Fpkg/1.0.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string("body"))
        .mount(&server)
        .await;

    let result = remote_docs::fetch_remote_docs("@scope/pkg", "1.0.0").await;
    assert_eq!(result.as_deref(), Some("body"));
}

// ── resolve_remote_latest ─────────────────────────────────────────────────
//
// `resolve_remote_latest` does not touch the disk cache, so no
// `CacheIsolation` is required for these tests.

#[tokio::test]
#[ignore]
async fn resolve_remote_latest_returns_version_on_200() {
    let _serial = lock();
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    let body = serde_json::json!({
        "library": "react",
        "version": "18.2.0",
        "source": "npm",
    });
    Mock::given(method("GET"))
        .and(path("/v1/resolve/react"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let result = remote_docs::resolve_remote_latest("react").await;
    assert_eq!(result.as_deref(), Some("18.2.0"));
}

#[tokio::test]
#[ignore]
async fn resolve_remote_latest_returns_none_on_404() {
    let _serial = lock();
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/resolve/does-not-exist"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let result = remote_docs::resolve_remote_latest("does-not-exist").await;
    assert!(result.is_none());
}

#[tokio::test]
#[ignore]
async fn resolve_remote_latest_returns_none_on_malformed_json() {
    let _serial = lock();
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    Mock::given(method("GET"))
        .and(path("/v1/resolve/react"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;

    let result = remote_docs::resolve_remote_latest("react").await;
    assert!(result.is_none());
}

#[tokio::test]
#[ignore]
async fn resolve_remote_latest_returns_none_on_missing_version_field() {
    let _serial = lock();
    let server = MockServer::start().await;
    let _guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    // JSON parses but the `version` field is absent.
    let body = serde_json::json!({ "library": "react", "source": "npm" });
    Mock::given(method("GET"))
        .and(path("/v1/resolve/react"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let result = remote_docs::resolve_remote_latest("react").await;
    assert!(result.is_none());
}

// ── Authorization header (optional Bearer) ────────────────────────────────

#[tokio::test]
#[ignore]
async fn fetch_remote_docs_sends_bearer_when_license_key_set() {
    let _serial = lock();
    let _cache = CacheIsolation::new("sends_bearer_when_license_key_set");
    let server = MockServer::start().await;
    let _url_guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());
    let _key_guard = EnvGuard::set("ANUBIS_LICENSE_KEY", "anubis-test-key");

    Mock::given(method("GET"))
        .and(path("/v1/docs/react/18.2.0"))
        .and(header("authorization", "Bearer anubis-test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let result = remote_docs::fetch_remote_docs("react", "18.2.0").await;
    assert_eq!(result.as_deref(), Some("ok"));
}

#[tokio::test]
#[ignore]
async fn fetch_remote_docs_works_without_license_key() {
    let _serial = lock();
    let _cache = CacheIsolation::new("works_without_license_key");
    let server = MockServer::start().await;
    let _url_guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());
    // Explicitly clear any inherited license key.
    let _key_guard = EnvGuard::remove("ANUBIS_LICENSE_KEY");

    Mock::given(method("GET"))
        .and(path("/v1/docs/react/18.2.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let result = remote_docs::fetch_remote_docs("react", "18.2.0").await;
    assert_eq!(result.as_deref(), Some("ok"));
}

// ── disk cache (24h TTL under ~/.anubis/docs/.remote-cache/) ──────────────

/// Second consecutive call within TTL must be served from disk cache — the
/// Worker mock is mounted with `expect(1)` so a second HTTP hit fails the
/// test. Validates the cache fast path end-to-end under a real TCP listener.
#[tokio::test]
#[ignore]
async fn fetch_remote_docs_serves_second_call_from_disk_cache() {
    let _serial = lock();
    let _cache = CacheIsolation::new("serves_second_call_from_disk_cache");
    let server = MockServer::start().await;
    let _url_guard = EnvGuard::set("ANUBIS_DOCS_URL", &server.uri());

    // Mock must be hit exactly once — the second fetch goes through cache.
    Mock::given(method("GET"))
        .and(path("/v1/docs/react/18.2.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string("## cached body"))
        .expect(1)
        .mount(&server)
        .await;

    // First call: cold cache → network.
    let first = remote_docs::fetch_remote_docs("react", "18.2.0").await;
    assert_eq!(first.as_deref(), Some("## cached body"));

    // Second call: warm cache → no HTTP. wiremock verifies call count on
    // MockServer drop; exceeding `expect(1)` fails the test at end-of-scope.
    let second = remote_docs::fetch_remote_docs("react", "18.2.0").await;
    assert_eq!(
        second.as_deref(),
        Some("## cached body"),
        "second call must be served from disk cache"
    );
}
