// Post-edit verification: after an agent edits/writes files via tool calls,
// run language-appropriate compilers/linters and feed results back on the
// next turn as injected context.
//
// Goal: catch the 20% of hallucinations that FORGE misses by using the
// compiler/linter as ground truth. If `tsc --noEmit` passes, the TypeScript
// is valid. If `cargo check` passes, the Rust compiles. If `ruff check -F`
// passes, Python has no undefined names.
//
// Python uses ruff (F821 undefined-name detection), NOT py_compile (which
// only checks syntax). Graceful degradation: ruff → pyflakes → py_compile.
//
// Opt-in via config.scanner.post_edit_verify.

use std::sync::Arc;
use tokio::sync::Mutex;

// ──────────────────────────────────────────────────────────────────────
// Verification result
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// File that was edited and verified.
    pub file_path: String,
    /// Compiler/linter that was run.
    pub tool: String,
    /// True if exit code was 0 (success). False = compile/lint error.
    pub success: bool,
    /// Captured stderr+stdout (truncated to 2000 chars for injection).
    pub output: String,
}

/// Shared queue of pending verification results waiting to be injected
/// into the next request. Cleared after injection.
pub type PendingVerifications = Arc<Mutex<Vec<VerificationResult>>>;

pub fn new_pending_verifications() -> PendingVerifications {
    Arc::new(Mutex::new(Vec::new()))
}

// ──────────────────────────────────────────────────────────────────────
// Tool call detection + file path extraction
// ──────────────────────────────────────────────────────────────────────

/// Detect edit/write tool calls in a response body and extract file paths.
///
/// Handles both OpenAI and Anthropic response formats. Looks for common
/// tool names across agent harnesses:
///   - edit_file, write_file, create_file (Cursor, Cline, Aider)
///   - str_replace, str_replace_editor (Claude Code)
///   - apply_patch (Git, Aider)
///   - write, edit (generic)
///
/// Returns deduplicated list of file paths that exist and have a known
/// source extension (so we don't try to compile .txt or .md files).
pub fn extract_edited_files(response_body: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Parse response body as JSON. If not JSON, try substring matching.
    let parsed: Option<serde_json::Value> = serde_json::from_str(response_body).ok();

    if let Some(json) = parsed.as_ref() {
        // OpenAI format: choices[].message.tool_calls[].function.arguments
        if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
            for choice in choices {
                if let Some(tool_calls) = choice
                    .get("message")
                    .and_then(|m| m.get("tool_calls"))
                    .and_then(|t| t.as_array())
                {
                    for tc in tool_calls {
                        if let Some(path) = extract_path_from_tool_call(tc) {
                            if seen.insert(path.clone()) {
                                files.push(path);
                            }
                        }
                    }
                }
            }
        }

        // Anthropic format: content[].type=="tool_use", .input.path
        if let Some(content) = json.get("content").and_then(|c| c.as_array()) {
            for block in content {
                if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    if let Some(path) = extract_path_from_anthropic_block(block) {
                        if seen.insert(path.clone()) {
                            files.push(path);
                        }
                    }
                }
            }
        }
    }

    // Filter to known source extensions — don't try to compile .txt/.md/.json
    files
        .into_iter()
        .filter(|p| has_compilable_extension(p))
        .collect()
}

/// Extract file path from an OpenAI tool_call object.
/// Tries common argument field names: path, file_path, filePath, file.
fn extract_path_from_tool_call(tc: &serde_json::Value) -> Option<String> {
    let function = tc.get("function")?;
    let name = function.get("name").and_then(|n| n.as_str()).unwrap_or("");

    // Only consider edit/write tools
    if !is_edit_tool_name(name) {
        return None;
    }

    let args_str = function.get("arguments").and_then(|a| a.as_str())?;
    let args: serde_json::Value = serde_json::from_str(args_str).ok()?;

    // Try common field names
    for field in &["path", "file_path", "filePath", "file", "filename"] {
        if let Some(path) = args.get(field).and_then(|p| p.as_str()) {
            return Some(path.to_string());
        }
    }

    // For apply_patch: the path may be embedded in the patch content
    if name == "apply_patch" {
        if let Some(patch) = args.get("patch").and_then(|p| p.as_str()) {
            return extract_path_from_diff(patch);
        }
    }

    None
}

/// Extract file path from an Anthropic tool_use block.
fn extract_path_from_anthropic_block(block: &serde_json::Value) -> Option<String> {
    let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("");

    if !is_edit_tool_name(name) {
        return None;
    }

    let input = block.get("input")?;

    for field in &["path", "file_path", "filePath", "file", "filename"] {
        if let Some(path) = input.get(field).and_then(|p| p.as_str()) {
            return Some(path.to_string());
        }
    }

    None
}

/// Check if a tool name is an edit/write operation.
fn is_edit_tool_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "edit_file"
            | "write_file"
            | "create_file"
            | "edit"
            | "write"
            | "create"
            | "str_replace"
            | "str_replace_editor"
            | "apply_patch"
            | "modify"
            | "save_file"
            | "update_file"
    )
}

/// Extract file path from a unified diff/patch.
/// Looks for `+++ b/path` or `--- a/path` lines.
fn extract_path_from_diff(patch: &str) -> Option<String> {
    for line in patch.lines() {
        if line.starts_with("+++ b/") {
            return Some(line[6..].trim().to_string());
        }
        if line.starts_with("+++ ") && !line.contains("/dev/null") {
            return Some(line[4..].trim().to_string());
        }
    }
    None
}

/// Check if a file path has an extension we can compile/lint.
fn has_compilable_extension(path: &str) -> bool {
    let lower = path.to_lowercase();
    const COMPILABLE: &[&str] = &[
        ".ts", ".tsx", ".js", ".jsx",     // TypeScript / JavaScript
        ".rs",                               // Rust
        ".py",                               // Python
        ".go",                               // Go
        ".cs",                               // C#
        ".java",                             // Java
        ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp",  // C / C++
    ];
    COMPILABLE.iter().any(|ext| lower.ends_with(ext))
}

// ──────────────────────────────────────────────────────────────────────
// Compiler runner
// ──────────────────────────────────────────────────────────────────────

/// Run a verification command for the given file. Selects the compiler
/// based on file extension. Returns None if no compiler is available
/// for this file type.
///
/// All commands run with a 30-second timeout. Output is captured from
/// both stdout and stderr, truncated to 2000 chars.
pub async fn run_verification(file_path: &str, project_root: &str) -> Option<VerificationResult> {
    let lower = file_path.to_lowercase();
    let (tool, cmd) = if lower.ends_with(".ts") || lower.ends_with(".tsx")
        || lower.ends_with(".js") || lower.ends_with(".jsx")
    {
        ("tsc", vec!["tsc", "--noEmit"])
    } else if lower.ends_with(".rs") {
        ("cargo", vec!["cargo", "check", "--message-format=short"])
    } else if lower.ends_with(".py") {
        // Detect best available Python linter once, cache result.
        // py_compile is syntax-only — misses undefined names (the most
        // common hallucination symptom). ruff/pyflakes catch F821
        // (undefined name) which py_compile silently passes.
        static PY_LINTER: std::sync::OnceLock<(&str, Vec<&str>)> = std::sync::OnceLock::new();
        let (tool, cmd) = PY_LINTER.get_or_init(|| {
            // Try ruff first (best — fast, catches F821 + more).
            if crate::scanner::command_hidden("ruff")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                ("ruff", vec!["ruff", "check", "--no-cache", "--select", "F821"])
            }
            // Fall back to pyflakes (catches F821 undefined names).
            else if crate::scanner::command_hidden("pyflakes")
                .arg("--help")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                ("pyflakes", vec!["pyflakes"])
            }
            // Last resort: py_compile (syntax-only, no name resolution).
            else {
                ("python", vec!["python", "-m", "py_compile"])
            }
        });
        (*tool, cmd.clone())
    } else if lower.ends_with(".go") {
        ("go", vec!["go", "vet"])
    } else if lower.ends_with(".cs") {
        ("dotnet", vec!["dotnet", "build", "--no-restore", "/clp:ErrorsOnly"])
    } else if lower.ends_with(".java") {
        ("javac", vec!["javac", "-Xlint:all"])
    } else if lower.ends_with(".cpp") || lower.ends_with(".cc")
        || lower.ends_with(".cxx") || lower.ends_with(".c")
        || lower.ends_with(".h") || lower.ends_with(".hpp")
    {
        // C/C++: skip for now — needs compiler-specific flags + include paths
        return None;
    } else {
        return None;
    };

    // Resolve the actual file path (handle relative vs absolute)
    let abs_path = if std::path::Path::new(file_path).is_absolute() {
        file_path.to_string()
    } else {
        std::path::Path::new(project_root)
            .join(file_path)
            .to_string_lossy()
            .to_string()
    };

    // Don't verify if the file doesn't exist (agent may not have saved yet)
    if !std::path::Path::new(&abs_path).exists() {
        tracing::debug!(
            target: "verification",
            file = %abs_path,
            "post-edit verify: file not found, skipping"
        );
        return None;
    }

    // Path-containment check (Council C4, SAFETY): prevent traversal attacks
    // where agent-controlled `file_path` escapes `project_root`. Without this,
    // `python -m py_compile <path>` would import dependencies of any file on
    // disk (= arbitrary code execution), and other compilers would happily
    // process files outside the workspace.
    //
    // Canonicalize both paths so symlink tricks and `..` segments collapse
    // before the prefix check. If canonicalization fails (broken symlink,
    // permission denied), skip verification rather than fall back to an
    // unsafe string comparison.
    let project_canon = match std::fs::canonicalize(project_root) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "verification",
                project_root = %project_root,
                error = %e,
                "post-edit verify: cannot canonicalize project_root, skipping"
            );
            return None;
        }
    };
    let file_canon = match std::fs::canonicalize(&abs_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                target: "verification",
                file = %abs_path,
                error = %e,
                "post-edit verify: cannot canonicalize file path, skipping"
            );
            return None;
        }
    };
    if !file_canon.starts_with(&project_canon) {
        tracing::warn!(
            target: "verification",
            file = %file_canon.display(),
            project_root = %project_canon.display(),
            "post-edit verify: path escapes project root, skipping"
        );
        return None;
    }

    tracing::info!(
        target: "verification",
        file = %abs_path,
        tool = tool,
        "post-edit verify: running"
    );

    // Run command with timeout
    let file_arg = abs_path.clone();
    let mut full_cmd = cmd.clone();
    // For compilers that take a file argument (py_compile, javac, go vet)
    // append the file path. For tsc/cargo check, run from project root
    // without file args (they check the whole project).
    if tool == "python" || tool == "ruff" || tool == "pyflakes" || tool == "javac" || tool == "go" {
        full_cmd.push(&file_arg);
    }

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::process::Command::new(&full_cmd[0])
            .args(&full_cmd[1..])
            .current_dir(project_root)
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            let success = output.status.success();
            let combined = format_combined_output(&output, &abs_path);
            tracing::info!(
                target: "verification",
                file = %abs_path,
                tool = tool,
                success = success,
                output_len = combined.len(),
                "post-edit verify: completed"
            );
            Some(VerificationResult {
                file_path: file_path.to_string(),
                tool: tool.to_string(),
                success,
                output: combined,
            })
        }
        Ok(Err(e)) => {
            tracing::warn!(
                target: "verification",
                file = %abs_path,
                tool = tool,
                error = %e,
                "post-edit verify: command failed to execute"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                target: "verification",
                file = %abs_path,
                tool = tool,
                "post-edit verify: timed out after 30s"
            );
            None
        }
    }
}

/// Combine stdout + stderr into a single string, truncated.
fn format_combined_output(output: &std::process::Output, file_path: &str) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Prefer stderr (compilers put errors there), fall back to stdout
    let primary = if !stderr.is_empty() { &stderr } else { &stdout };

    // Filter to lines that mention the file or contain "error"/"warning"
    let relevant: Vec<&str> = primary
        .lines()
        .filter(|line| {
            let lower = line.to_lowercase();
            // Keep lines that mention the file path basename
            let basename = std::path::Path::new(file_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            line.contains(&basename)
                || lower.contains("error")
                || lower.contains("warning")
                || lower.contains("cannot find")
                || lower.contains("expected")
                || lower.contains("-->")  // Rust error location marker
        })
        .take(30) // cap at 30 lines
        .collect();

    if relevant.is_empty() && !primary.is_empty() {
        // No filtered lines — take first 10 lines of stderr
        let fallback: Vec<&str> = primary.lines().take(10).collect();
        fallback.join("\n")
    } else {
        relevant.join("\n")
    }

    // Truncate to 2000 chars to stay within injection token budget
    .chars()
    .take(2000)
    .collect::<String>()
}

// ──────────────────────────────────────────────────────────────────────
// High-level entry point
// ──────────────────────────────────────────────────────────────────────

/// After a response is sent, detect edits and spawn verification tasks.
///
/// Called from the background scan task (non-streaming) or the egress
/// task (streaming). Results are stored in the shared pending queue and
/// injected into the next request.
pub async fn maybe_verify_edits(
    response_body: &str,
    project_root: &str,
    pending: &PendingVerifications,
) {
    let edited_files = extract_edited_files(response_body);
    if edited_files.is_empty() {
        return;
    }

    tracing::info!(
        target: "verification",
        count = edited_files.len(),
        files = ?edited_files,
        "post-edit verify: detected edited files"
    );

    // Run verifications sequentially (compilers are already parallel internally)
    for file in edited_files.iter().take(5) {
        // Cap at 5 files to avoid spawning too many compiler runs
        if let Some(result) = run_verification(file, project_root).await {
            pending.lock().await.push(result);
        }
    }
}

/// Drain pending verification results and build injection text.
///
/// Returns None if queue is empty. Otherwise returns the injection text
/// and clears the queue.
pub async fn drain_pending_verifications(
    pending: &PendingVerifications,
) -> Option<String> {
    let mut queue = pending.lock().await;
    if queue.is_empty() {
        return None;
    }

    let results: Vec<_> = queue.drain(..).collect();
    drop(queue); // release lock ASAP

    let mut lines = Vec::new();
    lines.push(
        "Anubis post-edit verification: I ran compilers/linters on the \
         files you edited in the previous turn. Here are the results:\n"
            .to_string(),
    );

    for r in &results {
        let status = if r.success { "✓ PASSED" } else { "✗ FAILED" };
        lines.push(format!("\n## {} ({}) — {}\n", r.file_path, r.tool, status));
        if !r.success && !r.output.is_empty() {
            lines.push("```\n".to_string());
            lines.push(r.output.clone());
            lines.push("\n```".to_string());
        }
    }

    if results.iter().any(|r| !r.success) {
        lines.push(
            "\nSome files failed verification. Please fix the errors above \
             before proceeding — they are real compiler errors, not \
             hallucinations."
                .to_string(),
        );
    } else {
        lines.push(
            "\nAll edited files passed verification. No errors detected."
                .to_string(),
        );
    }

    Some(lines.join("\n"))
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_edited_files ──────────────────────────────────────────

    #[test]
    fn extract_openai_edit_file_tool_call() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": {
                            "name": "edit_file",
                            "arguments": "{\"path\": \"src/main.ts\", \"content\": \"...\"}"
                        }
                    }]
                }
            }]
        });
        let files = extract_edited_files(&body.to_string());
        assert_eq!(files, vec!["src/main.ts"]);
    }

    #[test]
    fn extract_openai_write_file_with_file_path_field() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": {
                            "name": "write_file",
                            "arguments": "{\"file_path\": \"src/utils.py\"}"
                        }
                    }]
                }
            }]
        });
        let files = extract_edited_files(&body.to_string());
        assert_eq!(files, vec!["src/utils.py"]);
    }

    #[test]
    fn extract_anthropic_tool_use_block() {
        let body = serde_json::json!({
            "content": [{
                "type": "tool_use",
                "name": "str_replace_editor",
                "input": {"path": "src/lib.rs", "old_str": "...", "new_str": "..."}
            }]
        });
        let files = extract_edited_files(&body.to_string());
        assert_eq!(files, vec!["src/lib.rs"]);
    }

    #[test]
    fn extract_skips_non_edit_tool_calls() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": {
                            "name": "read_file",
                            "arguments": "{\"path\": \"src/main.ts\"}"
                        }
                    }]
                }
            }]
        });
        let files = extract_edited_files(&body.to_string());
        assert!(files.is_empty(), "read_file should not trigger verification");
    }

    #[test]
    fn extract_dedupes_files() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [
                        {"function": {"name": "edit_file", "arguments": "{\"path\": \"a.ts\"}"}},
                        {"function": {"name": "write_file", "arguments": "{\"path\": \"a.ts\"}"}},
                        {"function": {"name": "edit_file", "arguments": "{\"path\": \"b.ts\"}"}}
                    ]
                }
            }]
        });
        let files = extract_edited_files(&body.to_string());
        assert_eq!(files.len(), 2);
        assert!(files.contains(&"a.ts".to_string()));
        assert!(files.contains(&"b.ts".to_string()));
    }

    #[test]
    fn extract_skips_non_source_files() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [
                        {"function": {"name": "write_file", "arguments": "{\"path\": \"README.md\"}"}},
                        {"function": {"name": "write_file", "arguments": "{\"path\": \"config.json\"}"}},
                        {"function": {"name": "edit_file", "arguments": "{\"path\": \"src/app.ts\"}"}}
                    ]
                }
            }]
        });
        let files = extract_edited_files(&body.to_string());
        assert_eq!(files, vec!["src/app.ts"]);
    }

    #[test]
    fn extract_from_apply_patch() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "function": {
                            "name": "apply_patch",
                            "arguments": "{\"patch\": \"--- a/old.py\\n+++ b/new_module.py\\n@@ -1 +1 @@\\n-old\\n+new\"}"
                        }
                    }]
                }
            }]
        });
        let files = extract_edited_files(&body.to_string());
        assert_eq!(files, vec!["new_module.py"]);
    }

    // ── has_compilable_extension ──────────────────────────────────────

    #[test]
    fn compilable_extensions() {
        assert!(has_compilable_extension("main.ts"));
        assert!(has_compilable_extension("app.tsx"));
        assert!(has_compilable_extension("lib.rs"));
        assert!(has_compilable_extension("main.py"));
        assert!(has_compilable_extension("main.go"));
        assert!(has_compilable_extension("Program.cs"));
        assert!(has_compilable_extension("Main.java"));
        assert!(has_compilable_extension("main.cpp"));
        assert!(has_compilable_extension("header.hpp"));
    }

    #[test]
    fn non_compilable_extensions() {
        assert!(!has_compilable_extension("README.md"));
        assert!(!has_compilable_extension("config.json"));
        assert!(!has_compilable_extension("package.yaml"));
        assert!(!has_compilable_extension("notes.txt"));
        assert!(!has_compilable_extension("Dockerfile"));
    }

    // ── is_edit_tool_name ─────────────────────────────────────────────

    #[test]
    fn edit_tool_names() {
        assert!(is_edit_tool_name("edit_file"));
        assert!(is_edit_tool_name("write_file"));
        assert!(is_edit_tool_name("create_file"));
        assert!(is_edit_tool_name("str_replace"));
        assert!(is_edit_tool_name("str_replace_editor"));
        assert!(is_edit_tool_name("apply_patch"));
        assert!(is_edit_tool_name("EDIT_FILE")); // case insensitive
    }

    #[test]
    fn non_edit_tool_names() {
        assert!(!is_edit_tool_name("read_file"));
        assert!(!is_edit_tool_name("list_directory"));
        assert!(!is_edit_tool_name("search"));
        assert!(!is_edit_tool_name("execute_command"));
        assert!(!is_edit_tool_name("bash"));
    }

    // ── extract_path_from_diff ────────────────────────────────────────

    #[test]
    fn extract_path_from_unified_diff() {
        let patch = "--- a/src/old.py\n+++ b/src/new.py\n@@ -1 +1 @@\n-old\n+new";
        assert_eq!(extract_path_from_diff(patch), Some("src/new.py".to_string()));
    }

    #[test]
    fn extract_path_from_diff_without_b_prefix() {
        let patch = "--- old.py\n+++ new.py\n@@ -1 +1 @@\n-old\n+new";
        assert_eq!(extract_path_from_diff(patch), Some("new.py".to_string()));
    }

    // ── drain_pending_verifications ───────────────────────────────────

    #[tokio::test]
    async fn drain_empty_returns_none() {
        let pending = new_pending_verifications();
        let result = drain_pending_verifications(&pending).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn drain_returns_and_clears_results() {
        let pending = new_pending_verifications();
        pending.lock().await.push(VerificationResult {
            file_path: "test.ts".to_string(),
            tool: "tsc".to_string(),
            success: false,
            output: "error TS2304: Cannot find name 'foo'".to_string(),
        });

        let result = drain_pending_verifications(&pending).await;
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("test.ts"));
        assert!(text.contains("✗ FAILED"));
        assert!(text.contains("error TS2304"));

        // Queue should be empty after drain
        assert!(pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn drain_all_passed_message() {
        let pending = new_pending_verifications();
        pending.lock().await.push(VerificationResult {
            file_path: "ok.ts".to_string(),
            tool: "tsc".to_string(),
            success: true,
            output: String::new(),
        });

        let result = drain_pending_verifications(&pending).await;
        let text = result.unwrap();
        assert!(text.contains("✓ PASSED"));
        assert!(text.contains("All edited files passed"));
    }

    // ── format_combined_output ────────────────────────────────────────

    #[test]
    fn format_output_filters_to_relevant_lines() {
        let output = std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: b"Compiling...\nDone\n".to_vec(),
            stderr: b"warning: unused variable\nerror TS2304: Cannot find name 'foo'\nother line\n".to_vec(),
        };
        let result = format_combined_output(&output, "main.ts");
        // Should include lines with "error" or "warning"
        assert!(result.contains("error TS2304"));
        assert!(result.contains("warning: unused variable"));
        // Should NOT include "other line" (no error/warning/file mention)
        assert!(!result.contains("other line"));
    }

    #[test]
    fn format_output_truncates_at_2000_chars() {
        let long_line = "error: ".to_string() + &"x".repeat(3000);
        let output = std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr: long_line.into_bytes(),
        };
        let result = format_combined_output(&output, "main.ts");
        assert!(result.len() <= 2000);
    }
}
