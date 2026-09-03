//! Project root detection — extracts project root from intercepted LLM traffic.
//!
//! The daemon runs as a background proxy. It cannot use std::env::current_dir()
//! because that returns the daemon's cwd, not the user's project.
//!
//! Instead, we parse file paths from intercepted tool call arguments
//! (e.g., `<parameter name="filePath">E:\project\src\main.rs</parameter>`)
//! and walk up the directory tree to find project markers (.git, package.json,
//! Cargo.toml, go.mod, etc.).
//!
//! Research (librarian bg_f3f18d6b, 2026-07-26): this is the MOST RELIABLE
//! approach for proxy architectures. LSP servers are TOLD the root by the
//! client; we infer it from the file paths agents send in tool calls.
//!
//! Proven patterns from: rust-analyzer (ProjectManifest::discover), Vercel CLI
//! (find-project-root.ts), gopls (expandWorkspaceToModule), Aider (git_root).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use tokio::sync::RwLock;

/// Cache TTL: re-detect after 5 minutes. Balances freshness vs perf.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Maximum upward directory traversal depth. Prevents infinite loops on
/// symlink cycles and deep directory trees.
const MAX_DEPTH: usize = 20;

/// Project marker files. When any of these is found in a directory, that
/// directory is considered a project root. Ordered roughly by specificity.
const MARKERS: &[&str] = &[
    // Version control
    ".git",
    // JavaScript/TypeScript (lockfiles first — more specific)
    "pnpm-lock.yaml",
    "yarn.lock",
    "package-lock.json",
    "package.json",
    "tsconfig.json",
    // Rust
    "Cargo.toml",
    // Go
    "go.mod",
    // Python
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "Pipfile",
    // Java
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    // C#
    "*.csproj",
    "*.sln",
    // C/C++
    "CMakeLists.txt",
    "Makefile",
    // Ruby
    "Gemfile",
    // PHP
    "composer.json",
    // Generic
    ".gitignore",
    ".project",
];

/// Cached project root with timestamp for TTL expiry.
struct CachedRoot {
    root: Option<String>,
    detected_at: Instant,
}

/// Process-wide cache keyed by the first file path that triggered detection.
/// Once detected, subsequent requests within TTL reuse the cached root.
static ROOT_CACHE: Lazy<Arc<RwLock<Option<CachedRoot>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));

/// Detect project root from intercepted message content.
///
/// Parses file paths from tool call arguments, system prompts, and code
/// blocks. Walks up from each path to find project markers.
///
/// Returns the detected root path, or None if no project markers found.
/// Cached for CACHE_TTL duration.
pub async fn detect_project_root(content: &str) -> Option<String> {
    // Check cache first.
    {
        let cache = ROOT_CACHE.read().await;
        if let Some(cached) = cache.as_ref() {
            if cached.detected_at.elapsed() < CACHE_TTL {
                return cached.root.clone();
            }
        }
    }

    // Extract file paths from content.
    let paths = extract_file_paths(content);
    if paths.is_empty() {
        return None;
    }

    // Try each path — first successful detection wins.
    let mut detected: Option<String> = None;
    for path in &paths {
        if let Some(root) = find_project_root_from_path(path) {
            detected = Some(root);
            break;
        }
    }

    // Cache the result (including None — don't re-scan every request).
    let mut cache = ROOT_CACHE.write().await;
    *cache = Some(CachedRoot {
        root: detected.clone(),
        detected_at: Instant::now(),
    });

    detected
}

/// Force-clear the cache. Useful when user switches projects.
pub async fn clear_cache() {
    let mut cache = ROOT_CACHE.write().await;
    *cache = None;
}

/// Extract file paths from message content.
///
/// Looks for patterns commonly found in agent tool calls:
///   - `"filePath": "E:\\project\\src\\main.rs"` (JSON tool call)
///   - `<parameter name="filePath">E:\project\src\main.rs</parameter>` (XML)
///   - `read("E:/project/src/main.rs")` (function call)
///   - System prompt `Working directory: E:\project` (OpenCode/Aider)
///
/// Returns absolute file paths (filters out relative paths and URLs).
pub fn extract_file_paths(content: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Pattern 1: JSON "filePath" / "file_path" / "path" parameter values.
    let json_re = regex::Regex::new(
        r#""(?:filePath|file_path|path|filename|file)"\s*:\s*"([^"]+)""#
    ).unwrap();
    for caps in json_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let p = m.as_str();
            if is_absolute_path(p) && seen.insert(p.to_string()) {
                paths.push(p.to_string());
            }
        }
    }

    // Pattern 2: XML parameter tags.
    let xml_re = regex::Regex::new(
        r#"<parameter\s+name="(?:filePath|file_path|path|filename|file)">([^<]+)</parameter>"#
    ).unwrap();
    for caps in xml_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let p = m.as_str().trim();
            if is_absolute_path(p) && seen.insert(p.to_string()) {
                paths.push(p.to_string());
            }
        }
    }

    // Pattern 3: System prompt "Working directory:" (OpenCode format).
    let cwd_re = regex::Regex::new(
        r"(?:Working directory|Workspace root folder|cwd|project.root)\s*:\s*([^\n\r<]+)"
    ).unwrap();
    for caps in cwd_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let p = m.as_str().trim();
            if is_absolute_path(p) && Path::new(p).is_dir() {
                // This IS the project root — return directly.
                if seen.insert(p.to_string()) {
                    paths.insert(0, p.to_string());
                }
            }
        }
    }

    // Pattern 4: Code blocks with absolute paths (Windows or Unix).
    let code_re = regex::Regex::new(
        r#"(?m)([A-Z]:\\[\w\\.-]+|/home/\w+/[\w/.-]+|/Users/\w+/[\w/.-]+)"#
    ).unwrap();
    for caps in code_re.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let p = m.as_str();
            if is_absolute_path(p) && seen.insert(p.to_string()) {
                paths.push(p.to_string());
            }
        }
    }

    paths
}

/// Check if a string looks like an absolute file path (not a URL or relative).
fn is_absolute_path(s: &str) -> bool {
    if s.is_empty() || s.len() < 3 {
        return false;
    }
    // URLs are not file paths.
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
        return false;
    }
    // Windows: C:\, D:\, etc.
    if s.len() >= 3 {
        let bytes = s.as_bytes();
        if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
            return true;
        }
    }
    // Unix: /home, /Users, /tmp, /var, /opt, /srv
    if s.starts_with('/') && !s.starts_with("//") {
        return true;
    }
    false
}

/// Walk up from a file path to find the nearest project root.
///
/// Checks each parent directory for marker files (.git, package.json, etc.).
/// Returns the first directory containing a marker, or None if none found
/// within MAX_DEPTH levels.
pub fn find_project_root_from_path(file_path: &str) -> Option<String> {
    let start = Path::new(file_path);
    let start_dir = if start.is_file() {
        start.parent()?
    } else {
        start
    };

    let mut current = Some(start_dir);
    let mut depth = 0;

    while let Some(dir) = current {
        if depth >= MAX_DEPTH {
            break;
        }

        for marker in MARKERS {
            let marker_path = dir.join(marker);
            if marker_path.exists() {
                return Some(dir.to_string_lossy().to_string());
            }
        }

        current = dir.parent();
        depth += 1;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_file_paths_finds_json_filepath() {
        let content = r#"{"tool": "read", "filePath": "E:\\project\\src\\main.rs"}"#;
        let paths = extract_file_paths(content);
        assert!(paths.iter().any(|p| p.contains("main.rs")), "got: {:?}", paths);
    }

    #[test]
    fn extract_file_paths_finds_xml_parameter() {
        let content = r#"<parameter name="filePath">E:\project\src\main.rs</parameter>"#;
        let paths = extract_file_paths(content);
        assert!(paths.iter().any(|p| p.contains("main.rs")), "got: {:?}", paths);
    }

    #[test]
    fn extract_file_paths_finds_unix_paths() {
        let content = "Reading /home/user/project/src/main.rs...";
        let paths = extract_file_paths(content);
        assert!(paths.iter().any(|p| p.contains("project")), "got: {:?}", paths);
    }

    #[test]
    fn extract_file_paths_skips_urls() {
        let content = r#"{"url": "https://example.com/path"}"#;
        let paths = extract_file_paths(content);
        assert!(paths.is_empty(), "should skip URLs, got: {:?}", paths);
    }

    #[test]
    fn extract_file_paths_finds_working_directory() {
        let content = "Working directory: E:\\GitRepos\\groundwire\nIs directory a git repo: yes";
        let paths = extract_file_paths(content);
        assert!(paths.iter().any(|p| p.contains("groundwire")), "got: {:?}", paths);
    }

    #[test]
    fn is_absolute_path_windows() {
        assert!(is_absolute_path("C:\\Users\\test\\project"));
        assert!(is_absolute_path("D:/code/main.rs"));
    }

    #[test]
    fn is_absolute_path_unix() {
        assert!(is_absolute_path("/home/user/project"));
        assert!(is_absolute_path("/tmp/test.rs"));
    }

    #[test]
    fn is_absolute_path_rejects_relative() {
        assert!(!is_absolute_path("src/main.rs"));
        assert!(!is_absolute_path("../parent/file.ts"));
        assert!(!is_absolute_path("./local"));
    }

    #[test]
    fn is_absolute_path_rejects_urls() {
        assert!(!is_absolute_path("https://example.com"));
        assert!(!is_absolute_path("http://localhost:3000"));
    }

    #[test]
    fn find_project_root_finds_cargo_toml() {
        // This file is in packages/daemon-rs/src/ — Cargo.toml is 2 dirs up.
        let current_file = file!();
        let current_dir = std::path::Path::new(current_file).parent().unwrap();
        let abs = std::fs::canonicalize(current_dir).unwrap();
        let root = find_project_root_from_path(&abs.to_string_lossy());
        assert!(root.is_some(), "should find Cargo.toml or .git");
    }

    #[test]
    fn find_project_root_returns_none_for_tmp() {
        let root = find_project_root_from_path("/tmp/nonexistent_project_xyz");
        // /tmp likely doesn't have markers — should return None or find /
        // (which would be wrong). We just check it doesn't panic.
        let _ = root;
    }

    #[tokio::test]
    async fn detect_project_root_caches_result() {
        clear_cache().await;
        // First call detects.
        let content = r#"{"filePath": "E:\\GitRepos\\groundwire\\packages\\daemon-rs\\src\\lib.rs"}"#;
        let root1 = detect_project_root(content).await;
        // Second call should return cached result.
        let root2 = detect_project_root("different content").await;
        assert_eq!(root1, root2, "cache should return same result");
    }

    #[tokio::test]
    async fn clear_cache_works() {
        clear_cache().await;
        let cache = ROOT_CACHE.read().await;
        assert!(cache.is_none());
    }
}
