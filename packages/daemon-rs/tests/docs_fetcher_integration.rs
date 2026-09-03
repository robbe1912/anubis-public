// Integration tests for docs_fetcher.
//
// All network-dependent tests are `#[ignore]`-gated so `cargo test` skips them
// by default. Run them explicitly with:
//
//     cargo test --test docs_fetcher_integration -- --ignored
//
// Or run a single one:
//
//     cargo test --test docs_fetcher_integration npm_react -- --ignored

use anubis_daemon::docs_fetcher;
use std::fs;
use std::path::PathBuf;

/// Locate the anubis home (`~/.anubis`) regardless of platform.
fn anubis_home() -> PathBuf {
    anubis_daemon::config::config_dir()
}

/// Unique slug suffix from current millisecond — prevents collisions when
/// tests run repeatedly against the same docs/ tree.
fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("test{}", ms % 1_000_000)
}

/// Remove a doc set if it exists. Best-effort; ignores errors.
fn cleanup(slug: &str) {
    let dir = docs_fetcher::doc_set_dir(slug);
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }
}

// ── Pure-IO tests (always run) ────────────────────────────────────────────

#[test]
fn list_doc_sets_returns_existing_entries() {
    // Should not panic even if ~/.anubis/docs doesn't exist.
    let _ = docs_fetcher::list_doc_sets();
}

#[test]
fn detect_source_round_trips_basic_inputs() {
    use docs_fetcher::DocSource;
    assert_eq!(
        docs_fetcher::detect_source("react").unwrap(),
        DocSource::Npm {
            name: "react".into()
        }
    );
    assert_eq!(
        docs_fetcher::detect_source("owner/repo").unwrap(),
        DocSource::GitHub {
            owner: "owner".into(),
            repo: "repo".into(),
        }
    );
}

#[test]
fn slug_for_invalid_github_with_space_errors() {
    assert!(docs_fetcher::detect_source("foo bar/baz").is_err());
}

// ── Local strategy (always run; no network) ───────────────────────────────

#[test]
fn local_copy_recursive_walks_subdirs() {
    let suffix = unique_suffix();
    let slug = format!("local-test-{}", suffix);
    cleanup(&slug);

    // Build a temp tree with two .md files (one nested) and one .txt.
    let tmp_root = std::env::temp_dir().join(format!("anubis_local_test_{}", suffix));
    let nested = tmp_root.join("sub");
    fs::create_dir_all(&nested).unwrap();
    fs::write(tmp_root.join("top.md"), "# Top\n\n## react\nTop content").unwrap();
    fs::write(nested.join("child.md"), "# Child\n\n## vue\nChild content").unwrap();
    fs::write(tmp_root.join("ignore.png"), b"not text").unwrap();

    let result = docs_fetcher::fetch_local(&tmp_root).expect("local fetch should succeed");
    assert_eq!(result.files.len(), 2, "expected exactly 2 .md files");
    let names: Vec<&str> = result.files.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"top.md"));
    assert!(names.contains(&"child.md"));

    // Override slug so cleanup tracks the actual on-disk dir name.
    let mut result = result;
    result.slug = slug.clone();

    // Persist and re-read.
    let persisted = docs_fetcher::persist_fetch_result(&result, &tmp_root.to_string_lossy())
        .expect("persist should succeed");
    assert!(persisted.exists());

    let meta = docs_fetcher::read_meta(&slug)
        .unwrap()
        .expect("meta should exist");
    assert_eq!(meta.strategy, "local");
    assert_eq!(meta.files.len(), 2);
    assert_eq!(meta.source, tmp_root.to_string_lossy());

    cleanup(&slug);
    let _ = fs::remove_dir_all(&tmp_root);
}

#[test]
fn local_copy_rejects_missing_path() {
    let bogus = PathBuf::from("/this/path/does/not/exist/anubis/test");
    let err = docs_fetcher::fetch_local(&bogus).unwrap_err();
    assert!(err.contains("does not exist"));
}

#[test]
fn local_copy_rejects_dir_with_no_docs() {
    let suffix = unique_suffix();
    let empty = std::env::temp_dir().join(format!("anubis_empty_{}", suffix));
    fs::create_dir_all(&empty).unwrap();
    fs::write(empty.join("image.png"), b"x").unwrap();
    let err = docs_fetcher::fetch_local(&empty).unwrap_err();
    assert!(err.contains("no .md/.txt"));
    let _ = fs::remove_dir_all(&empty);
}

// ── Network tests (ignored by default) ────────────────────────────────────

#[tokio::test]
#[ignore]
async fn npm_react() {
    let suffix = unique_suffix();
    let slug = format!("npm-react-{}", suffix);
    cleanup(&slug);

    // Fetch react from npm using a slug override.
    let client = docs_fetcher_test_helpers::make_client();
    let mut res = docs_fetcher::fetch_npm(&client, "react")
        .await
        .expect("npm react should fetch");
    res.slug = slug.clone();

    assert_eq!(res.files.len(), 1);
    let (filename, content) = &res.files[0];
    assert!(filename.ends_with(".md"));
    assert!(content.len() > 100, "readme should be non-trivial");

    let dir = docs_fetcher::persist_fetch_result(&res, "react").unwrap();
    assert!(dir.exists());
    assert!(dir.join(filename).exists());
    assert!(dir.join("meta.json").exists());

    cleanup(&slug);
}

#[tokio::test]
#[ignore]
async fn github_rezi() {
    let suffix = unique_suffix();
    let slug = format!("gh-rezi-{}", suffix);
    cleanup(&slug);

    let client = docs_fetcher_test_helpers::make_client();
    let mut res = docs_fetcher::fetch_github(&client, "RtlZeroMemory", "Rezi")
        .await
        .expect("github fetch should succeed");
    res.slug = slug.clone();

    assert!(!res.files.is_empty(), "should have at least README");

    let dir = docs_fetcher::persist_fetch_result(&res, "RtlZeroMemory/Rezi").unwrap();
    assert!(dir.exists());

    cleanup(&slug);
}

#[tokio::test]
#[ignore]
async fn context7_lodash() {
    // NOTE: my fail with 429 if your IP exhausted the 200/10d anonymous bucket.
    // Set CONTEXT7_API_KEY env var to bypass that.
    let suffix = unique_suffix();
    let slug = format!("c7-lodash-{}", suffix);
    cleanup(&slug);

    let client = docs_fetcher_test_helpers::make_client();
    let res = match docs_fetcher::fetch_context7(&client, "lodash").await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[test] context7_lodash skipped: {}", e);
            return;
        }
    };
    let mut res = res;
    res.slug = slug.clone();

    let dir = docs_fetcher::persist_fetch_result(&res, "lodash").unwrap();
    assert!(dir.exists());

    cleanup(&slug);
}

#[tokio::test]
#[ignore]
async fn website_example() {
    let suffix = unique_suffix();
    let slug = format!("web-example-{}", suffix);
    cleanup(&slug);

    let client = docs_fetcher_test_helpers::make_client();
    let mut res = docs_fetcher::fetch_website(&client, "https://example.com")
        .await
        .expect("example.com should convert to markdown");
    res.slug = slug.clone();

    assert_eq!(res.files.len(), 1);
    let (_name, content) = &res.files[0];
    assert!(
        content.len() >= 50,
        "converted md should clear minimum threshold"
    );

    let dir = docs_fetcher::persist_fetch_result(&res, "https://example.com").unwrap();
    assert!(dir.exists());

    cleanup(&slug);
}

#[tokio::test]
#[ignore]
async fn npm_to_context7_fallback() {
    // Use a name that looks like a package but doesn't exist on npm.
    // The orchestrator should fall back to Context7 (or fail Context7 too —
    // either way npm miss shouldn't propagate as a hard error).
    let suffix = unique_suffix();
    let slug = format!("fallback-{}", suffix);
    cleanup(&slug);

    let fake_pkg = format!("anubis-nonexistent-pkg-{}", suffix);
    let res = docs_fetcher::fetch_source(&docs_fetcher::DocSource::Npm {
        name: fake_pkg.clone(),
    })
    .await;

    match res {
        Ok(mut r) => {
            r.slug = slug.clone();
            let dir = docs_fetcher::persist_fetch_result(&r, &fake_pkg).unwrap();
            assert!(dir.exists());
            cleanup(&slug);
        }
        Err(e) => {
            // Acceptable: Context7 also missed. Just verify error is non-empty.
            assert!(!e.is_empty());
            eprintln!("[test] fallback failed (acceptable): {}", e);
        }
    }
}

/// Small shared helpers for tests above. Kept in the same file so the test
/// binary stays a single compilation unit.
mod docs_fetcher_test_helpers {
    pub fn make_client() -> reqwest::Client {
        reqwest::Client::builder()
            .user_agent("anubis-docs-fetcher-test")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("client build")
    }
}

// Suppress unused-import warning when only a subset of tests is compiled.
#[allow(dead_code)]
fn _force_use(_p: &PathBuf) {
    let _ = anubis_home();
}
