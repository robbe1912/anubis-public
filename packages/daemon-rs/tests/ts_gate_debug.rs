//! Fast integration test: full scan_response on known-false TS samples.
//! Debugs the wrapper→forge→warnings chain in seconds, not 10-min benchmarks.

use anubis_daemon::scanner::{scan_response, ScanContext};

fn ctx_for(project_root: &std::path::Path) -> ScanContext {
    ScanContext {
        project_root: project_root.to_string_lossy().to_string(),
        logic_model: std::env::var("DELULU_LLM_MODEL").unwrap_or_default(),
        llm_base_url: std::env::var("DELULU_LLM_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:11434/v1".into()),
        llm_api_key: String::new(), // no L3 — deterministic layers only
        llm_extra_headers: Vec::new(),
        request_class: String::new(),
        language: "typescript".into(),
        cancel: tokio_util::sync::CancellationToken::new(),
    }
}

/// Scaffold exactly like the benchmark does (package.json + node_modules junction).
fn scaffold(root: &std::path::Path) {
    let _ = std::fs::write(root.join("package.json"), r#"{"name":"bench","private":true}"#);
    let nm = root.join("node_modules");
    let _ = std::fs::create_dir_all(&nm);
    let global_ts = std::path::PathBuf::from(
        std::process::Command::new("cmd")
            .args(["/c", "npm", "root -g"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default(),
    )
    .join("typescript");
    if global_ts.is_dir() {
        let dst = nm.join("typescript");
        if !dst.exists() {
            let _ = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&dst)
                .arg(&global_ts)
                .output();
        }
    }
}

#[tokio::test]
async fn ts_array_sum_full_scan_warns() {
    let root = tempfile::tempdir().expect("tempdir");
    scaffold(root.path());
    let content = "```typescript\nconst total = [1, 2, 3].sum();\nconsole.log(total);\n```\n\nComputes the sum of the array as 6 using the built-in Array.prototype.sum method.\n";
    let ctx = ctx_for(root.path());
    let result = scan_response(content, &ctx).await;
    eprintln!("WARNINGS: {:#?}", result.warnings);
    eprintln!("DETAILS: {:#?}", result.details);
    assert!(
        !result.warnings.is_empty(),
            "array_sum must be caught: wrapper provably returns TS2339 for .sum()"
    );
}

#[tokio::test]
async fn rust_unwrap_or_bare_snippet_full_scan_warns() {
    let root = tempfile::tempdir().expect("tempdir");
    // Bare snippet (no fn main) — mirrors benchmark corpus exactly.
    // rustc parse-fails on top-level `let` unless the gate wraps it.
    let content = "```rust\nlet n: usize = 5;\nlet v = n.unwrap_or(0);\nprintln!(\"{}\", v);\n```\n\nReturns 5 from unwrap_or because n already holds a value.\n";
    let mut ctx = ctx_for(root.path());
    ctx.language = "rust".into();
    let result = scan_response(content, &ctx).await;
    eprintln!("RUST WARNINGS: {:#?}", result.warnings);
    assert!(
        !result.warnings.is_empty(),
            "bare unwrap_or snippet must be caught: rustc E0599 fires when wrapped in fn main (manually verified)"
    );
}
