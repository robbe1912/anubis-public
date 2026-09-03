//! Compiler-based code verification.
//!
//! Uses installed language tools (clangd, rustc, go vet, dotnet, pyright)
//! to verify generated code. Each tool runs on a temp file and produces
//! diagnostics that are parsed into warnings.
//!
//! Design: compiler diagnostics are ADDITIVE to FORGE. They run after FORGE
//! and before L3. If a tool is not installed, skip silently.
//!
//! See `.omo/plans/lsp-integration.md` for the full design.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

/// Maximum code size to send to compiler (avoid timeout on huge files).
pub(crate) const MAX_CODE_SIZE: usize = 50_000;

/// Detect whether a binary is available on PATH.
/// Returns the path if found, None otherwise.
pub(crate) fn find_binary(name: &str) -> Option<PathBuf> {
    let finder = if cfg!(windows) { "where" } else { "which" };
    let mut cmd = crate::scanner::command_hidden(finder);
    cmd.arg(name)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(PathBuf::from(line))
    }
}

/// Write code to a temp file. Returns the file path.
/// Caller is responsible for cleanup.
fn write_temp_file(code: &str, extension: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join("anubis-compiler-check");
    std::fs::create_dir_all(&dir).ok()?;
    let id = uuid_v4_simple();
    let path = dir.join(format!("anubis_{}.{}", id, extension));
    std::fs::write(&path, code).ok()?;
    Some(path)
}

/// Simple UUID v4 generator (no external dependency).
pub(crate) fn uuid_v4_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:016x}", nanos)
}

/// Extract backtick-quoted tokens from existing FORGE warnings to avoid
/// duplicate warnings from the compiler.
pub fn extract_forge_tokens(forge_warnings: &[String]) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for w in forge_warnings {
        let mut iter = w.split('`');
        iter.next(); // skip first (before first backtick)
        while let Some(token) = iter.next() {
            if !token.is_empty() && token.len() < 100 {
                tokens.insert(token.to_lowercase());
            }
            iter.next(); // skip separator
        }
    }
    tokens
}

/// Run a command with timeout and return stdout+stderr.
pub(crate) async fn run_with_timeout(
    binary: &Path,
    args: &[&str],
    cwd: Option<&Path>,
    timeout_secs: u64,
) -> Option<(String, String)> {
    let mut cmd = crate::scanner::command_hidden_tokio(&binary.to_string_lossy());
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    cmd.kill_on_drop(true); // CRITICAL: kill child process when timeout cancels future.
                            // Without this, orphaned ruff/tsc/rustc processes lock files on Windows.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        cmd.output(),
    )
    .await
    .ok()?
    .ok()?;

    let stdout = String::from_utf8_lossy(&result.stdout).to_string();
    let stderr = String::from_utf8_lossy(&result.stderr).to_string();
    Some((stdout, stderr))
}

// ─── Language-specific diagnostic parsing ───────────────────────────

/// Parse clangd/gcc/clang stderr for errors and warnings.
/// Format: `file.cpp:line:col: error: message` or `file.cpp:line:col: warning: message`
fn parse_c_cpp_diagnostics(
    output: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let keep_keywords = [
        "undeclared", "not found", "no member", "undefined", "cannot find",
        "has no", "incomplete type", "not declared", "use of undeclared",
        "no method", "no field", "unknown type",
    ];
    let skip_keywords = [
        "unused", "format ", "Wformat", "pedantic", "-W",
        // POSIX headers not available on Windows. When clang can't find
        // regex.h, it cascades into 8+ "undeclared identifier" errors for
        // regex_t/regcomp/regexec/regfree/regerror/REG_NOSUB. Suppress all
        // of them — on Linux where regex.h exists, clang compiles fine and
        // these diagnostics never appear, so the skip is a no-op there.
        "regex.h", "'regex_t'", "'regcomp'", "'regexec'", "'regfree'",
        "'regerror'", "'reg_nosub'", "'regex'",
    ];

    for line in output.lines() {
        let lower = line.to_lowercase();
        // Match both standard format (error:/warning:) and clangd log format (E[...]/W[...]).
        let is_diag = lower.contains("error:")
            || lower.contains("warning:")
            || line.starts_with("E[")
            || line.starts_with("W[");
        if !is_diag {
            continue;
        }
        // Skip style/unused diagnostics.
        if skip_keywords.iter().any(|kw| lower.contains(kw)) {
            continue;
        }
        // Keep only relevant diagnostics.
        if !keep_keywords.iter().any(|kw| lower.contains(kw)) {
            continue;
        }
        // Extract the identifier from the message (usually in quotes or after 'identifier').
        let ident = extract_identifier_from_clangd_msg(line);
        if let Some(ref id) = ident {
            if forge_tokens.contains(&id.to_lowercase()) {
                continue; // Already flagged by FORGE.
            }
        }
        // Clean up the message.
        let cleaned = clean_clangd_line(line);
        if !cleaned.is_empty() {
            warnings.push(format!("compiler: {}", cleaned));
        }
    }
    warnings
}

fn extract_identifier_from_clangd_msg(line: &str) -> Option<String> {
    // Look for 'identifier' or quoted names in clangd messages.
    // Examples: "use of undeclared identifier 'foo'"
    //          "no member named 'bar' in 'T'"
    for segment in line.split('\'').skip(1).step_by(2) {
        if !segment.is_empty() && segment.len() < 100 {
            return Some(segment.to_string());
        }
    }
    None
}

fn clean_clangd_line(line: &str) -> String {
    // clangd log format: "E[timestamp] [error_code] Line N: message"
    if line.starts_with("E[") || line.starts_with("W[") {
        // Extract the message after "Line N: ".
        if let Some(line_pos) = line.find("Line ") {
            let rest = &line[line_pos..];
            if let Some(colon_pos) = rest.find(": ") {
                return rest[colon_pos + 2..].trim().to_string();
            }
        }
        // Fallback: strip E[timestamp] prefix and return rest.
        if let Some(close_bracket) = line.find("] ") {
            return line[close_bracket + 2..].trim().to_string();
        }
    }
    // Standard format: remove file path prefix.
    if let Some(pos) = line.find("error:") {
        return line[pos..].trim().to_string();
    }
    if let Some(pos) = line.find("warning:") {
        return line[pos..].trim().to_string();
    }
    line.trim().to_string()
}

/// Parse Go vet output.
/// Format: `file.go:line: message`
fn parse_go_diagnostics(
    output: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let keep_keywords = [
        "undefined", "cannot", "not enough", "too many", "mismatched",
        "does not", "no field", "not used",
    ];

    for line in output.lines() {
        let lower = line.to_lowercase();
        if !keep_keywords.iter().any(|kw| lower.contains(kw)) {
            continue;
        }
        // Extract identifier (often after colon).
        let cleaned = line.trim();
        if cleaned.is_empty() {
            continue;
        }
        warnings.push(format!("compiler: {}", cleaned));
    }
    // Dedup.
    warnings.dedup();
    warnings
}

/// Parse rustc stderr for errors.
/// Format: `error[E0xxx]: message`
fn parse_rust_diagnostics(
    output: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    // Skip import/module resolution errors (E0433, E0432) — these are FPs
    // in single-file mode where external crates aren't available.
    let skip_codes = ["E0433", "E0432"];
    let keep_keywords = [
        "no method", "no field", "unresolved", "mismatched type",
        "expected", "no variant", "not a known",
    ];

    for line in output.lines() {
        let lower = line.to_lowercase();
        if !lower.contains("error[") && !lower.contains("error:") {
            continue;
        }
        // Skip single-file FPs: can't resolve external crates without Cargo.toml.
        if skip_codes.iter().any(|code| line.contains(code)) {
            continue;
        }
        if !keep_keywords.iter().any(|kw| lower.contains(kw)) {
            continue;
        }
        let cleaned = line.trim();
        if !cleaned.is_empty() {
            warnings.push(format!("compiler: {}", cleaned));
        }
    }
    warnings
}

/// Parse C# dotnet build output (MSBuild format).
/// Format: `file.cs(line,col): error CSxxxx: message`
fn parse_csharp_diagnostics(
    output: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    // CS error codes we care about (name/type/member resolution).
    let keep_codes = [
        "CS0103", // name does not exist
        "CS0234", // namespace type does not exist
        "CS0246", // type not found
        "CS0117", // no static member
        "CS1061", // no member on type
        "CS1503", // type mismatch
        "CS0122", // inaccessible
        "CS7036", // no overload
        "CS8403", // method with managed type
    ];

    for line in output.lines() {
        let upper = line.to_uppercase();
        if !keep_codes.iter().any(|code| upper.contains(code)) {
            continue;
        }
        // Extract the message after `error CSxxxx:`.
        if let Some(pos) = line.find(": error ") {
            let msg_start = line[pos + 9..].find(':').map(|p| pos + 9 + p + 2);
            if let Some(start) = msg_start {
                let msg = line[start..].trim();
                if !msg.is_empty() {
                    warnings.push(format!("compiler: CS error: {}", msg));
                }
            }
        }
    }
    warnings
}

// ─── Public API ─────────────────────────────────────────────────────

/// Verify code using available compiler tools.
/// Returns additional warnings (additive to FORGE).
///
/// `language` = detected language tag (cpp, c, csharp, rust, go, python, gdscript).
/// `code` = code content to verify.
/// `forge_tokens` = identifiers already flagged by FORGE (for dedup).
pub async fn verify_with_compiler(
    language: &str,
    code: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    if code.len() > MAX_CODE_SIZE {
        return Vec::new();
    }

    let raw = match language {
        "cpp" | "c" => verify_c_cpp(code, forge_tokens).await,
        "csharp" => verify_csharp(code, forge_tokens).await,
        "rust" => verify_rust(code, forge_tokens).await,
        "go" => verify_go(code, forge_tokens).await,
        "python" => verify_python(code, forge_tokens).await,
        "gdscript" => verify_godot_tcp(code, forge_tokens).await,
        _ => Vec::new(),
    };

    // Dedup exact duplicate warning strings (two-pass scan can produce dupes).
    let mut seen = std::collections::HashSet::new();
    raw.into_iter()
        .filter(|w| seen.insert(w.clone()))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// Output-prediction execution gate (L2.7)
//
// Catches the shortest, most evasive hallucination class: claims that
// predict a program's output ("Prints 4.", "Logs true.", "Prints [3, 1, 2]
// since sorting returns a fresh array"). These are under every extractor's
// 12-char minimum and carry no identifiers — deterministic layers see
// nothing, L3 judges guess. But the claim is mechanically checkable: RUN
// the code and compare stdout.
//
// Fail-open by construction: a warning is emitted ONLY on a clean exit
// with non-empty stdout that clearly lacks the predicted literal. Parse
// errors, timeouts, missing interpreters, empty output → silent.
// ─────────────────────────────────────────────────────────────────────────

/// Max code size for execution (bounding blast radius + latency).
const EXEC_GATE_MAX_CODE: usize = 2_000;
/// Wall-clock budget per execution.
const EXEC_GATE_TIMEOUT_SECS: u64 = 5;

/// Extract the predicted literal from an output-prediction sentence.
/// Shapes: `Prints 4.` / `Logs true.` / `Outputs "done".` /
/// `Prints [3, 1, 2] since ...` / `prints 3.5.`
/// Returns the predicted token (string form) or None.
fn extract_predicted_output(claim: &str) -> Option<String> {
    use std::sync::OnceLock;
    static PRED_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = PRED_RE.get_or_init(|| {
        // Verb + predicted literal: bracketed list, quoted string, number
        // (int/float), or boolean/null literal. Trailing prose ignored.
        regex::Regex::new(
            r#"(?i)\b(?:prints?|logs?|outputs?)\s+(\[[^\]]*\]|"[^"]*"|-?\d+(?:\.\d+)?|true|false|null|none)"#,
        )
        .unwrap()
    });
    let caps = re.captures(claim)?;
    let tok = caps.get(1)?.as_str().to_string();
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

/// Run `code` under the language interpreter and compare stdout against the
/// predicted literal. Emits at most one output-mismatch warning.
pub async fn verify_output_prediction(
    content: &str,
    language: &str,
    code: &str,
) -> Vec<String> {
    // BLOCKER-1 hardening: executing model-controlled code is RCE-by-design.
    // Double opt-in only — config `scanner.execution_gate: true` AND env
    // ANUBIS_EXECUTION_GATE=1. Every default axis is OFF.
    if !crate::config::execution_gate_enabled() {
        return Vec::new();
    }
    if code.is_empty() || code.len() > EXEC_GATE_MAX_CODE {
        return Vec::new();
    }
    // Infinite-loop shapes can emit unbounded stdout within the timeout
    // (memory-blowup guard, audit finding). Snippets that print a single
    // predicted literal don't loop forever.
    if code.contains("while (true)")
        || code.contains("while(true)")
        || code.contains("while True:")
        || code.contains("while True")
        || code.contains("while 1:")
        || code.contains("while 1")
        || code.contains("for (;;)")
        || code.contains("for(;;)")
    {
        return Vec::new();
    }

    // Interpreter selection. Java/Rust/Go need compile steps (latency +
    // toolchain variance) — out of scope for this gate.
    let (binary, ext): (&str, &str) = match language {
        "python" => ("python", "py"),
        "javascript" | "typescript" => ("node", "js"),
        _ => return Vec::new(),
    };
    let interpreter = match find_binary(binary) {
        Some(b) => b,
        None => return Vec::new(),
    };

    // Prediction window: only prose AFTER the last code fence. Output
    // claims describe the snippet they follow; searching the whole
    // response cross-matches unrelated prose (audit FP trace).
    let window: &str = match content.rfind("```") {
        Some(i) => {
            let line_end = content[i..]
                .find('\n')
                .map(|e| i + e)
                .unwrap_or(content.len());
            &content[line_end..]
        }
        None => content,
    };
    let code_lines: std::collections::HashSet<&str> = code.lines().collect();
    let prose: Vec<&str> = window
        .lines()
        .filter(|l| !code_lines.contains(l) && !l.trim_start().starts_with("```"))
        .collect();
    let prose = prose.join("\n");
    let predicted = match extract_predicted_output(&prose) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let temp = match write_temp_file(code, ext) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let out = match run_with_timeout(
        interpreter.as_path(),
        &[temp.to_string_lossy().as_ref()],
        None,
        EXEC_GATE_TIMEOUT_SECS,
    )
    .await
    {
        Some(o) => o,
        None => return Vec::new(),
    };

    // Clean exit + non-empty stdout required.
    let actual = out.0.trim().to_string();
    if actual.is_empty() || !out.1.is_empty() {
        return Vec::new();
    }

    // Mismatch test: predicted literal appears in actual output (loose,
    // case-insensitive substring) → verified. Otherwise → hallucinated
    // output claim.
    let pred_cmp = predicted.trim_matches(|c| c == '"' || c == '[' || c == ']').to_lowercase();
    if actual.to_lowercase().contains(&pred_cmp) {
        return Vec::new();
    }

    let shown_actual: String = actual.chars().take(60).collect();
    vec![format!(
        "output-mismatch: claim predicts `{predicted}` but executing the code outputs `{shown_actual}`"
    )]
}

async fn verify_c_cpp(
    code: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let clangd = find_binary("clangd");
    let extension = if code.contains("class ") || code.contains("std::") {
        "cpp"
    } else {
        "c"
    };

    if let Some(binary) = clangd {
        let temp = match write_temp_file(code, extension) {
            Some(p) => p,
            None => return Vec::new(),
        };
        let temp_str = temp.to_string_lossy().to_string();
        let check_arg = format!("--check={}", temp_str);
        let result = run_with_timeout(
            &binary,
            &[&check_arg],
            None,
            15,
        )
        .await;
        let _ = std::fs::remove_file(&temp);
        if let Some((stdout, stderr)) = result {
            let output = format!("{}\n{}", stdout, stderr);
            return parse_c_cpp_diagnostics(&output, forge_tokens);
        }
    }

    // Fallback: g++/clang++ -fsyntax-only.
    for compiler in &["g++", "clang++", "gcc", "clang"] {
        if let Some(binary) = find_binary(compiler) {
            let temp = match write_temp_file(code, extension) {
                Some(p) => p,
                None => return Vec::new(),
            };
            let temp_str = temp.to_string_lossy().to_string();
            let result = run_with_timeout(
                &binary,
                &["-fsyntax-only", "-Wall", &temp_str],
                None,
                10,
            )
            .await;
            let _ = std::fs::remove_file(&temp);
            if let Some((_, stderr)) = result {
                return parse_c_cpp_diagnostics(&stderr, forge_tokens);
            }
        }
    }

    Vec::new()
}

/// Wrap a bare Rust snippet (`let x = ...;` at top level) in `fn main(){}`
/// so rustc reaches type-checking instead of parse-failing. `use` statements
/// stay outside the wrapper. No-op when the code already has item-level
/// definitions (fn/struct/enum/impl/trait/static/const/mod).
pub(crate) fn wrap_bare_rust_snippet(code: String) -> String {
    if code.trim().is_empty()
        || code.lines().any(|l| {
            let t = l.trim_start();
            // Item-level definitions — including visibility-qualified forms
            // like `pub(crate) fn` / `pub(super) struct` (overfit-audit
            // guard: bare `fn `-prefix check would mis-wrap those).
            let item_kw = |tt: &str| {
                tt.starts_with("fn ")
                    || tt.starts_with("struct ")
                    || tt.starts_with("enum ")
                    || tt.starts_with("impl ")
                    || tt.starts_with("trait ")
                    || tt.starts_with("static ")
                    || tt.starts_with("const ")
                    || tt.starts_with("mod ")
            };
            if let Some(rest) = t.strip_prefix("pub") {
                let rest = rest.trim_start();
                if let Some(close) = rest.find(')') {
                    if rest.starts_with('(') {
                        return item_kw(rest[close + 1..].trim_start());
                    }
                }
                item_kw(rest)
            } else {
                item_kw(t)
            }
        })
    {
        return code;
    }
    let uses: Vec<&str> = code
        .lines()
        .filter(|l| l.trim_start().starts_with("use "))
        .collect();
    let body: Vec<&str> = code
        .lines()
        .filter(|l| !l.trim_start().starts_with("use "))
        .collect();
    // Overfit-audit guard: `?` propagation outside fn main() is a compile
    // error; rustdoc-style Result wrapping keeps the snippet compiling so
    // the E-codes we surface are the snippet's own, not wrapper artifacts.
    let body_joined = body.join("\n");
    let wrapped_body = if body_joined.contains('?') {
        format!("fn main() {{\n    let __r: Result<(), Box<dyn std::error::Error>> = (|| {{\n        {}\n        Ok(())\n    }})();\n    let _ = __r;\n}}\n", body_joined)
    } else {
        format!("fn main() {{\n{}\n}}\n", body_joined)
    };
    format!("{}\n{}", uses.join("\n"), wrapped_body)
}

async fn verify_rust(
    code: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let rustc = match find_binary("rustc") {
        Some(p) => p,
        None => return Vec::new(),
    };
    // Wrap bare snippets so rustc type-checks instead of parse-failing —
    // parse errors here emit noise warnings that break the downstream
    // compiler-gate symbol intersection.
    let wrapped = wrap_bare_rust_snippet(code.to_string());
    let temp = match write_temp_file(&wrapped, "rs") {
        Some(p) => p,
        None => return Vec::new(),
    };
    let temp_str = temp.to_string_lossy().to_string();
    let result = run_with_timeout(
        &rustc,
        &["--emit=mir", "-o", "/dev/null", &temp_str],
        None,
        10,
    )
    .await;
    let _ = std::fs::remove_file(&temp);
    if let Some((_, stderr)) = result {
        return parse_rust_diagnostics(&stderr, forge_tokens);
    }
    Vec::new()
}

async fn verify_go(
    code: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let go = match find_binary("go") {
        Some(p) => p,
        None => return Vec::new(),
    };
    let temp = match write_temp_file(code, "go") {
        Some(p) => p,
        None => return Vec::new(),
    };
    let temp_str = temp.to_string_lossy().to_string();
    let result = run_with_timeout(
        &go,
        &["vet", &temp_str],
        None,
        10,
    )
    .await;
    let _ = std::fs::remove_file(&temp);
    if let Some((stdout, stderr)) = result {
        let output = format!("{}\n{}", stdout, stderr);
        return parse_go_diagnostics(&output, forge_tokens);
    }
    Vec::new()
}

async fn verify_csharp(
    code: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let dotnet = match find_binary("dotnet") {
        Some(p) => p,
        None => return Vec::new(),
    };
    let dir = std::env::temp_dir().join("anubis-compiler-check").join(format!("cs_{}", uuid_v4_simple()));
    if std::fs::create_dir_all(&dir).is_err() {
        return Vec::new();
    };

    // Write .csproj directly with EF Core packages (if needed) + Library output.
    // Using OutputType=Library avoids CS5001 (no Main method) errors when the
    // user's code has class definitions without an entry point.
    let code_lower = code.to_lowercase();
    let needs_ef = code_lower.contains("dbcontext")
        || code_lower.contains("dbset")
        || code_lower.contains("entityframework")
        || code_lower.contains("entityframeworkcore")
        || code_lower.contains("system.data.entity");

    let ef_refs = if needs_ef {
        r#"
    <ItemGroup>
      <PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0.11" />
      <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="8.0.11" />
    </ItemGroup>"#
    } else {
        ""
    };

    // Auto-inject PackageReferences from `using X;` directives for third-party packages.
    // Without this, dotnet build generates CS0246 for MediatR, Serilog, Polly, etc.
    let mut auto_refs = String::new();
    let using_re = regex::Regex::new(r"\busing\s+([A-Za-z][\w.]*)\s*;").unwrap();
    let mut seen_pkgs: Vec<String> = Vec::new();
    for caps in using_re.captures_iter(code) {
        let ns = caps.get(1).unwrap().as_str();
        // Skip BCL (in .NET SDK)
        if ns.starts_with("System") || ns == "Microsoft.NETCore"
            || ns == "Microsoft.AspNetCore" || ns.starts_with("Microsoft.AspNetCore.")
        {
            continue;
        }
        let pkg = ns.split('.').next().unwrap_or(ns).to_string();
        if !seen_pkgs.contains(&pkg) {
            seen_pkgs.push(pkg.clone());
            auto_refs.push_str(&format!(
                r#"<PackageReference Include="{}" Version="*" />"#,
                pkg
            ));
        }
    }
    // Framework-specific detection
    let code_lower = code.to_lowercase();
    if code_lower.contains("ilogger") || code_lower.contains("logcontext") {
        if !seen_pkgs.contains(&"Serilog".to_string()) {
            auto_refs.push_str(r#"<PackageReference Include="Serilog" Version="*" />"#);
        }
        auto_refs.push_str(r#"<PackageReference Include="Microsoft.Extensions.Logging.Abstractions" Version="*" />"#);
    }
    let auto_item_group = if auto_refs.is_empty() {
        String::new()
    } else {
        format!("\n    <ItemGroup>{}</ItemGroup>", auto_refs)
    };

    let csproj = format!(
        r#"<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <OutputType>Library</OutputType>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
  </PropertyGroup>{}{}
</Project>"#,
        ef_refs, &auto_item_group
    );
    if std::fs::write(dir.join("csproj.xml"), &csproj).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Vec::new();
    }

    // Split by "// File:" markers — each block is a self-contained .cs file.
    // This avoids CS1529/CS8803 from concatenating multiple files.
    let blocks = split_by_file_markers(code);
    for (i, block) in blocks.iter().enumerate() {
        let filename = format!("Block{}.cs", i);
        let _ = std::fs::write(dir.join(&filename), block);
    }
    let _ = std::fs::remove_file(dir.join("Program.cs"));

    // Create a minimal .csproj so dotnet can find the project.
    let dir_name = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "anubis-check".to_string());
    let proj_name = format!("{}.csproj", dir_name);
    let csproj_path = dir.join(&proj_name);
    if std::fs::write(&csproj_path, &csproj).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Vec::new();
    }

    // Restore + build — pass explicit project path to avoid cwd resolution issues.
    let csproj_str = csproj_path.to_string_lossy().into_owned();

    // Restore + build — pass explicit project path to avoid cwd resolution issues.
    let _ = run_with_timeout(&dotnet, &["restore", &csproj_str], None, 60).await;
    let result = run_with_timeout(
        &dotnet,
        &["build", "--no-restore", &csproj_str],
        None,
        30,
    )
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    if let Some((stdout, stderr)) = result {
        let output = format!("{}\n{}", stdout, stderr);
        return parse_csharp_diagnostics(&output, forge_tokens);
    }
    Vec::new()
}

/// C# negative compiler FP gate.
///
/// Runs `dotnet build` with auto-injected PackageReferences from `using` directives.
/// Returns `Some(set)` where set = genuinely unresolved symbols (FORGE ∩ dotnet).
/// FORGE warnings for symbols NOT in set are false positives → suppress.
/// Returns `None` when dotnet unavailable or gate skipped → don't suppress (conservative).
///
/// Architecture: Oracle Approach 1 — compiler as negative oracle (FP suppressor).
/// Unlike additive verify_csharp, this INVERTS output: symbols the compiler resolves
/// successfully → their FORGE warnings are false positives → suppress them.
pub(crate) async fn csharp_compiler_gate(
    code: &str,
    forge_warnings: &[String],
) -> Option<HashSet<String>> {
    // HIGH-3 hardening (go-public-graveyard): auto-restoring NuGet packages
    // derived from response `using` lines downloads attacker-influenced
    // packages and runs their MSBuild targets on the scanner host — a second
    // RCE-by-default surface. Gated behind the same double-opt-in master
    // switch as the exec gate. Default: gate returns None (no suppression,
    // no package download — conservative pass-through).
    if !crate::config::execution_gate_enabled() {
        return None;
    }

    let forge_symbols = extract_forge_tokens(forge_warnings);
    let run_as_primary = forge_symbols.is_empty();

    let dotnet = find_binary("dotnet")?;

    // Parse `using X.Y.Z;` for third-party NuGet packages
    let using_re = regex::Regex::new(r"\busing\s+([A-Za-z][\w.]*)\s*;").ok()?;
    let mut packages: Vec<String> = Vec::new();
    for caps in using_re.captures_iter(code) {
        let ns = caps.get(1)?.as_str();
        // Skip BCL (in .NET SDK)
        if ns.starts_with("System") || ns == "Microsoft.NETCore"
            || ns == "Microsoft.AspNetCore" || ns.starts_with("Microsoft.AspNetCore.")
        {
            continue;
        }
        // NuGet package ID: root namespace segment
        let pkg = ns.split('.').next().unwrap_or(ns);
        if !packages.contains(&pkg.to_string()) {
            packages.push(pkg.to_string());
        }
    }

    // Generate .csproj with auto-injected PackageReferences
    let mut refs = String::new();
    for pkg in &packages {
        refs.push_str(&format!(
            r#"<PackageReference Include="{}" Version="*" />"#,
            pkg
        ));
    }
    // Common framework detection
    let code_lower = code.to_lowercase();
    if code_lower.contains("dbcontext") || code_lower.contains("entityframework") {
        refs.push_str(r#"<PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0.11" /><PackageReference Include="Microsoft.EntityFrameworkCore.InMemory" Version="8.0.11" />"#);
    }
    if code_lower.contains("ilogger") || code_lower.contains("logcontext") {
        refs.push_str(r#"<PackageReference Include="Microsoft.Extensions.Logging.Abstractions" Version="*" /><PackageReference Include="Serilog" Version="*" /><PackageReference Include="Serilog.Extensions.Logging" Version="*" />"#);
    }
    if code_lower.contains("iservicecollection") || code_lower.contains("addmediatr") {
        refs.push_str(r#"<PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="*" />"#);
    }

    let csproj = format!(
        r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <OutputType>Library</OutputType>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>{}</ItemGroup>
</Project>"#,
        refs
    );

    // Create temp project
    let dir = std::env::temp_dir()
        .join("anubis-csharp-gate")
        .join(format!("gate_{}", uuid_v4_simple()));
    std::fs::create_dir_all(&dir).ok()?;

    let dir_name = dir.file_name()?.to_string_lossy().to_string();
    let csproj_path = dir.join(format!("{}.csproj", dir_name));
    std::fs::write(&csproj_path, &csproj).ok()?;

    // Write code blocks
    let blocks = split_by_file_markers(code);
    for (i, block) in blocks.iter().enumerate() {
        let _ = std::fs::write(dir.join(format!("Block{}.cs", i)), block);
    }

    let csproj_str = csproj_path.to_string_lossy().into_owned();

    // dotnet restore (90s — first restore downloads packages) + build (30s)
    let _ = run_with_timeout(&dotnet, &["restore", &csproj_str], None, 90).await;
    let result = run_with_timeout(&dotnet, &["build", "--no-restore", &csproj_str], None, 30).await;

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);

    let (stdout, stderr) = result?;
    let combined = format!("{}\n{}", stdout, stderr);

    // Parse genuinely unresolved symbols from CS diagnostics
    let mut unresolved = HashSet::new();
    for re_str in &[r"CS0103.*?'([^']+)'", r"CS0246.*?'([^']+)'"] {
        if let Ok(re) = regex::Regex::new(re_str) {
            for caps in re.captures_iter(&combined) {
                if let Some(m) = caps.get(1) {
                    unresolved.insert(m.as_str().to_string());
                }
            }
        }
    }

    // Intersection: symbols flagged by BOTH FORGE AND dotnet → genuine hallucinations
    let genuine: HashSet<String> = if run_as_primary { unresolved.clone() } else { forge_symbols.intersection(&unresolved).cloned().collect() };

    tracing::info!(
        target: "compiler_gate",
        forge = forge_symbols.len(),
        unresolved_by_dotnet = unresolved.len(),
        genuine = genuine.len(),
        "C# compiler gate: {} of {} FORGE warnings are genuine",
        genuine.len(),
        forge_symbols.len()
    );

    Some(genuine)
}

/// Python negative compiler FP gate.
///
/// Runs `pyright --outputjson` on the code. Pyright is used instead of ruff
/// because ruff's F821 (undefined-name) rule is structurally blind to the
/// dominant Python hallucination patterns:
///   - Hallucinated attributes on modules/objects (`pd.read_cvs`,
///     `obj.fabricated_method`) — ruff treats these as valid syntax.
///   - Hallucinated imports (`import nonexistent_module_xyz`) — ruff emits
///     F401 (imported but unused), never validating module existence.
///
/// Pyright catches all three categories via:
///   - `reportAttributeAccessIssue` — hallucinated method/attribute on typed obj
///   - `reportUndefinedVariable` — bare undefined name
///   - `reportMissingImports` — module not resolvable
///
/// Returns `Some(set)` of genuinely unresolved symbols. In FP-suppression
/// mode (FORGE had warnings) returns `FORGE ∩ pyright`. In primary mode
/// (FORGE empty) returns all pyright-detected hallucinations as new warnings.
/// Returns `None` when pyright is unavailable → don't suppress (conservative).
///
/// Architecture mirrors `csharp_compiler_gate`: compiler as negative oracle.
pub(crate) async fn python_compiler_gate(
    code: &str,
    forge_warnings: &[String],
) -> Option<HashSet<String>> {
    let forge_symbols: HashSet<String> = forge_warnings
        .iter()
        .flat_map(|w| extract_warning_symbols(w))
        .collect();
    let run_as_primary = forge_symbols.is_empty();

    let pyright = find_binary("pyright")?;
    let temp = write_temp_file(code, "py")?;
    let temp_str = temp.to_string_lossy().to_string();

    let result = run_with_timeout(
        &pyright,
        &["--outputjson", &temp_str],
        None,
        15,
    )
    .await;

    let _ = std::fs::remove_file(&temp);

    let (stdout, _stderr) = result?;
    let unresolved = parse_pyright_hallucinations(&stdout, run_as_primary);

    // FP-suppression: intersect with FORGE symbols. extract_warning_symbols
    // lowercases both sides; pyright output is lowercased to match.
    let genuine: HashSet<String> = if run_as_primary {
        unresolved.clone()
    } else {
        unresolved
            .iter()
            .filter(|s| forge_symbols.contains(&s.to_lowercase()))
            .cloned()
            .collect()
    };

    tracing::info!(
        target: "compiler_gate",
        mode = if run_as_primary { "primary" } else { "fp-suppression" },
        forge = forge_symbols.len(),
        unresolved_by_pyright = unresolved.len(),
        genuine = genuine.len(),
        "Python compiler gate: {} of {} FORGE warnings are genuine",
        genuine.len(),
        forge_symbols.len()
    );

    Some(genuine)
}

/// Parse pyright `--outputjson` output and extract hallucinated symbols.
///
/// `primary_mode = true`: only high-precision rules (skip `reportMissingImports`
/// to avoid FP storm when local env lacks third-party packages — e.g. CI
/// without pandas installed would FP on every `import pandas`).
///
/// `primary_mode = false` (FP-suppression): include `reportMissingImports`
/// since FORGE-flagged imports need confirmation; intersection handles
/// any noise.
fn parse_pyright_hallucinations(stdout: &str, primary_mode: bool) -> HashSet<String> {
    let parsed: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => return HashSet::new(),
    };

    // High-precision rules: catch hallucinated methods + variables regardless
    // of env. Safe to emit in primary mode (no intersection filter).
    let primary_rules: &[&str] = &[
        "reportAttributeAccessIssue", // hallucinated method/attribute
        "reportUndefinedVariable",    // bare undefined name
    ];
    // FP-suppression rules: also include import-resolution diagnostics. These
    // depend on local env (third-party packages installed) — only safe to
    // consult when intersecting against FORGE's flagged symbol set.
    let suppression_rules: &[&str] = &[
        "reportAttributeAccessIssue",
        "reportUndefinedVariable",
        "reportMissingImports",
        "reportMissingModuleSource",
    ];
    let active = if primary_mode {
        primary_rules
    } else {
        suppression_rules
    };

    let mut out: HashSet<String> = HashSet::new();
    let diagnostics = match parsed.get("generalDiagnostics").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return out,
    };
    for diag in diagnostics {
        let severity = diag
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if severity != "error" {
            continue;
        }
        let rule = diag.get("rule").and_then(|v| v.as_str()).unwrap_or("");
        if !active.contains(&rule) {
            continue;
        }
        let message = diag
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(sym) = extract_first_quoted_symbol(message) {
            out.insert(sym);
        }
    }
    out
}

/// Extract the first double-quoted identifier from a pyright message.
///
/// Pyright messages reliably quote the offending symbol first:
///   - `"read_cvs" is not a known attribute of module "pandas"`
///   - `"foo" is not defined`
///   - `Import "nonexistent_module_xyz" could not be resolved`
///   - `Cannot access attribute "fabricated_method" for class "dict[str, int]"\n  Attribute "fabricated_method" is unknown`
///
/// Returns the first quoted token (the offending symbol). Subsequent quotes
/// are types/qualifiers, not the symbol under inspection.
fn extract_first_quoted_symbol(message: &str) -> Option<String> {
    let re = regex::Regex::new(r#""([^"]+)""#).ok()?;
    re.captures(message)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Go negative compiler FP gate.
///
/// Two-stage verification:
///   1. `go vet <file>` — catches undefined functions/methods/vars.
///   2. `go list -m <pkg>@latest` — catches hallucinated import paths that
///      `go vet` cannot reach (vet bails with "cannot find module providing
///      package X" which the existing regex does not match).
///
/// Returns `Some(set)` of genuinely unresolved symbols + import paths
/// (FORGE ∩ {vet ∪ list}). FORGE warnings for symbols NOT in the set are
/// false positives → suppress. Returns `None` when go is unavailable or the
/// gate is skipped → don't suppress (conservative).
///
/// Architecture mirrors `csharp_compiler_gate`: compiler as negative oracle.
pub(crate) async fn go_compiler_gate(
    code: &str,
    forge_warnings: &[String],
) -> Option<HashSet<String>> {
    let forge_symbols = extract_forge_tokens(forge_warnings);
    let run_as_primary = forge_symbols.is_empty();

    let go = find_binary("go")?;
    let temp = write_temp_file(code, "go")?;
    let temp_str = temp.to_string_lossy().to_string();

    // Run vet and import check concurrently — they touch independent go
    // subsystems (vet = local AST, list = module proxy) so total latency
    // is max(vet, list) rather than sum. Important because the gate has a
    // 3s outer timeout (mod.rs::compiler_gate_timeout).
    let imports = crate::scanner::go_introspect::parse_go_imports(code);
    // Hold the args in `let` bindings: futures returned below borrow them,
    // and inline array literals would be dropped before tokio::join! polls.
    let vet_args: [&str; 2] = ["vet", temp_str.as_str()];
    let (vet_result, list_unresolved) = tokio::join!(
        run_with_timeout(&go, &vet_args, None, 15),
        verify_go_imports_via_list(&go, &imports),
    );

    let _ = std::fs::remove_file(&temp);

    let mut unresolved: HashSet<String> = HashSet::new();

    if let Some((stdout, stderr)) = vet_result {
        let combined = format!("{}\n{}", stdout, stderr);
        // Parse two forms emitted by go vet:
        //   `path:line:col: undefined: <symbol>`
        //   `path:line:col: cannot find symbol "<symbol>"`
        if let Ok(re) = regex::Regex::new(r"undefined:\s*([A-Za-z_][A-Za-z0-9_]*)") {
            for caps in re.captures_iter(&combined) {
                if let Some(m) = caps.get(1) {
                    unresolved.insert(m.as_str().to_string());
                }
            }
        }
        if let Ok(re) = regex::Regex::new(r#"cannot find symbol "([A-Za-z_][A-Za-z0-9_]*)""#) {
            for caps in re.captures_iter(&combined) {
                if let Some(m) = caps.get(1) {
                    unresolved.insert(m.as_str().to_string());
                }
            }
        }
        // Arity errors: `not enough arguments in call to pkg.Fn` /
        // `too many arguments in call to pkg.Fn` — deterministic compile-
        // time hallucination evidence (real API, wrong usage). Capture the
        // full qualified call target; the intersection step matches on the
        // tail segment either way (extract_warning_symbols emits bare names).
        if let Ok(re) = regex::Regex::new(
            r"(?:not enough|too many) arguments in call to ([A-Za-z_][A-Za-z0-9_.]*)",
        ) {
            for caps in re.captures_iter(&combined) {
                if let Some(m) = caps.get(1) {
                    let qualified = m.as_str();
                    // Store both the full qualified name and the bare tail
                    // (SplitN vs strings.SplitN) — the warning-side symbol
                    // extractor emits bare names, so the tail is what
                    // intersects in suppression mode.
                    unresolved.insert(qualified.to_string());
                    if let Some(tail) = qualified.rsplit('.').next() {
                        unresolved.insert(tail.to_string());
                    }
                }
            }
        }
    }
    // `go list` detected hallucinated third-party import paths. These never
    // surface through vet's regex (vet's "cannot find module" message has
    // a different shape). Merged here so the intersection step below picks
    // them up like any other symbol.
    unresolved.extend(list_unresolved);

    // Intersection (case-sensitive — both sides preserve source casing).
    // Both modes return the full vet-confirmed set. Suppression semantics
    // at the caller are unchanged (retain keeps FORGE warnings whose symbols
    // the compiler confirms missing), and the caller now also surfaces
    // compiler-confirmed symbols FORGE never flagged (arity errors etc.) -
    // the old forge-intersection silently buried that evidence class.
    let genuine: HashSet<String> = unresolved.clone();

    tracing::info!(
        target: "compiler_gate",
        forge = forge_symbols.len(),
        unresolved_by_go = unresolved.len(),
        genuine = genuine.len(),
        "Go compiler gate: {} of {} FORGE warnings are genuine",
        genuine.len(),
        forge_symbols.len()
    );

    Some(genuine)
}

/// Verify Go import paths via `go list`.
///
/// `go vet` on a module-less temp file produces "cannot find module
/// providing package X" for third-party imports — that error shape is
/// NOT captured by the existing `undefined:` / `cannot find symbol`
/// regexes, so hallucinated imports slip through (50% recall on Go).
///
/// Two batched `go list` calls cover both import classes:
///   - **No-dot imports** (stdlib-shaped): `go list -e <pkgs>` resolves
///     from GOROOT. Catches fakes like `fakepackagexyz` that look like
///     stdlib but aren't.
///   - **Dot imports** (third-party): `go list -m -e <pkg>@latest` queries
///     proxy.golang.org without needing a go.mod. Catches fakes like
///     `github.com/totally/fake/pkg`.
///
/// Both calls use `-e` (continue on error) plus a Go template that prints
/// `<path> OK` or `<path> FAIL` per import. Exit code is always 0 with `-e`.
///
/// Returns the set of import paths that failed resolution. Empty set
/// when `go list` is unavailable, times out, or finds nothing to check
/// (conservative — never produces false positives).
async fn verify_go_imports_via_list(
    go: &Path,
    imports: &[(String, String)],
) -> HashSet<String> {
    let (stdlib, third_party): (Vec<&str>, Vec<&str>) = imports
        .iter()
        .map(|(_, path)| path.as_str())
        .partition(|p| !p.contains('.'));

    let mut unresolved = HashSet::new();

    // Stdlib-shaped imports: resolve against GOROOT.
    if !stdlib.is_empty() {
        let args: Vec<&str> = ["list", "-e", "-f", "{{.ImportPath}} {{if .Error}}FAIL{{else}}OK{{end}}"]
            .into_iter()
            .chain(stdlib.iter().copied())
            .collect();
        if let Some((stdout, _)) = run_with_timeout(go, &args, None, 5).await {
            unresolved.extend(parse_go_list_fail_lines(&stdout));
        }
    }

    // Third-party imports: resolve against module proxy.
    if !third_party.is_empty() {
        let queries: Vec<String> = third_party
            .iter()
            .map(|p| format!("{}@latest", p))
            .collect();
        let args: Vec<&str> = ["list", "-m", "-e", "-f", "{{.Path}} {{if .Error}}FAIL{{else}}OK{{end}}"]
            .into_iter()
            .chain(queries.iter().map(|s| s.as_str()))
            .collect();
        if let Some((stdout, _)) = run_with_timeout(go, &args, None, 10).await {
            unresolved.extend(parse_go_list_fail_lines(&stdout));
        }
    }

    unresolved
}

/// Parse `go list -m -e -f '{{.Path}} {{if .Error}}FAIL{{else}}OK{{end}}'` output.
///
/// Each line is `<import-path> OK` (resolved) or `<import-path> FAIL`
/// (proxy 404 / git fetch failed → hallucinated). Returns the FAIL paths.
///
/// Extracted as a pure helper for unit testing — the actual `go list`
/// invocation requires network access and a real Go toolchain.
fn parse_go_list_fail_lines(stdout: &str) -> HashSet<String> {
    let mut unresolved = HashSet::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(path) = line.strip_suffix(" FAIL") {
            if !path.is_empty() {
                unresolved.insert(path.to_string());
            }
        }
    }
    unresolved
}

/// Consolidate all `using X.Y.Z;` statements to the top of the code.
/// Prevents CS1529 when multiple code blocks (each with their own usings)
/// are concatenated into a single file.
/// Split concatenated code by `// File:` markers into separate compilation units.
/// Each block is a self-contained C# file — avoids structural errors from
/// concatenating multiple files with different using/namespace layouts.
pub(crate) fn split_by_file_markers(code: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Vec<&str> = Vec::new();

    for line in code.lines() {
        if line.trim().starts_with("// File:") || line.trim().starts_with("// file:") {
            if !current.is_empty() {
                blocks.push(current.join("\n"));
                current.clear();
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        blocks.push(current.join("\n"));
    }
    if blocks.is_empty() {
        blocks.push(code.to_string());
    }
    blocks
}

async fn verify_python(
    code: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    // Pyright only. py_compile was removed — it does syntax checking only,
    // so hallucinated names (e.g. pandas.read_cvs()) are VALID SYNTAX and
    // pass silently. SyntaxError output is pure noise (prose leak, Unicode
    // chars), and NameError is dead code (py_compile can't emit runtime
    // errors). Zero recall lost, FPs eliminated. See Oracle bg_6c231628.
    let pyright = find_binary("pyright");
    if let Some(binary) = pyright {
        let temp = match write_temp_file(code, "py") {
            Some(p) => p,
            None => return Vec::new(),
        };
        let temp_str = temp.to_string_lossy().to_string();
        let result = run_with_timeout(&binary, &[&temp_str], None, 10).await;
        let _ = std::fs::remove_file(&temp);
        if let Some((stdout, _)) = result {
            return parse_pyright_diagnostics(&stdout, forge_tokens);
        }
    }
    Vec::new()
}

fn parse_pyright_diagnostics(
    output: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let keep_keywords = [
        "undefined", "cannot find", "not defined", "incompatible",
        "Cannot access", "is not defined", "unknown",
    ];

    for line in output.lines() {
        let lower = line.to_lowercase();
        if !lower.contains("error") && !lower.contains("warning") {
            continue;
        }
        if !keep_keywords.iter().any(|kw| lower.contains(&kw.to_lowercase())) {
            continue;
        }
        let cleaned = line.trim();
        if !cleaned.is_empty() {
            warnings.push(format!("compiler: {}", cleaned));
        }
    }
    warnings
}

/// Connect to running Godot editor LSP on TCP port 6005.
/// If editor is not running, return empty (graceful skip).
async fn verify_godot_tcp(
    code: &str,
    forge_tokens: &HashSet<String>,
) -> Vec<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Try connecting to Godot LSP.
    let mut stream = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect("127.0.0.1:6005"),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return Vec::new(), // Editor not running — skip.
    };

    // Write code to temp .gd file.
    let temp = match write_temp_file(code, "gd") {
        Some(p) => p,
        None => return Vec::new(),
    };
    let uri = format!("file://{}", temp.to_string_lossy());

    // LSP initialize request.
    let init_msg = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"capabilities":{{}},"processId":null,"rootUri":null}}}}"#
    );
    let init_with_headers = format!(
        "Content-Length: {}\r\n\r\n{}",
        init_msg.len(),
        init_msg
    );
    if stream.write_all(init_with_headers.as_bytes()).await.is_err() {
        let _ = std::fs::remove_file(&temp);
        return Vec::new();
    }

    // Read initialize response (with timeout).
    let mut buf = vec![0u8; 8192];
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await;

    // Send didOpen.
    let escaped_code = code.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r");
    let did_open = format!(
        r#"{{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{{"textDocument":{{"uri":"{}","languageId":"gdscript","version":1,"text":"{}"}}}}}}"#,
        uri,
        escaped_code
    );
    let did_open_with_headers = format!(
        "Content-Length: {}\r\n\r\n{}",
        did_open.len(),
        did_open
    );
    if stream.write_all(did_open_with_headers.as_bytes()).await.is_err() {
        let _ = std::fs::remove_file(&temp);
        return Vec::new();
    }

    // Read diagnostics (LSP sends textDocument/publishDiagnostics notification).
    let mut full_response = String::new();
    let read_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let remaining = read_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                    full_response.push_str(text);
                }
            }
            _ => break,
        }
        // Check if we got diagnostics.
        if full_response.contains("publishDiagnostics") {
            break;
        }
    }

    let _ = std::fs::remove_file(&temp);

    // Parse LSP diagnostics from response.
    parse_godot_lsp_diagnostics(&full_response)
}

fn parse_godot_lsp_diagnostics(response: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    let keep_keywords = [
        "undeclared", "not defined", "no method", "Function",
        "identifier", "not found", "Invalid",
    ];

    // LSP diagnostics are JSON. Find "message" fields in diagnostic objects.
    // Simple extraction: look for "message":"..." pairs.
    let mut in_message = false;
    let mut current_msg = String::new();
    let mut depth = 0;

    for (i, ch) in response.char_indices() {
        if !in_message {
            // Look for "message":"
            if response[i..].starts_with("\"message\":\"") {
                in_message = true;
                depth = 0;
                // Skip past the opening.
                // Will start collecting from next char after the opening quote.
            }
        } else {
            if ch == '\\' {
                // Skip next char (escape).
                continue;
            }
            if ch == '"' && depth == 0 {
                // End of message string.
                let lower = current_msg.to_lowercase();
                if keep_keywords.iter().any(|kw| lower.contains(&kw.to_lowercase())) {
                    warnings.push(format!("compiler: Godot LSP: {}", current_msg));
                }
                current_msg.clear();
                in_message = false;
            } else {
                current_msg.push(ch);
            }
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clangd_undeclared_identifier() {
        let output = "test.cpp:5:3: error: use of undeclared identifier 'foo'";
        let tokens = HashSet::new();
        let warnings = parse_c_cpp_diagnostics(output, &tokens);
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("undeclared"));
        assert!(warnings[0].contains("foo"));
    }

    #[test]
    fn test_parse_clangd_log_format() {
        let output = "E[18:49:31.520] [no_member] Line 13: no member named 'push_back' in 'std::queue<Task>'";
        let tokens = HashSet::new();
        let warnings = parse_c_cpp_diagnostics(output, &tokens);
        assert!(!warnings.is_empty(), "should catch clangd log format");
        assert!(warnings[0].contains("no member"), "should contain 'no member'");
        assert!(warnings[0].contains("push_back"), "should contain identifier");
    }

    #[test]
    fn test_parse_clangd_no_member() {
        let output = "test.cpp:10:5: error: no member named 'get' in 'std::optional<Task>'";
        let tokens = HashSet::new();
        let warnings = parse_c_cpp_diagnostics(output, &tokens);
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("no member"));
    }

    #[test]
    fn test_parse_clangd_skips_unused_warning() {
        let output = "test.cpp:3:7: warning: unused variable 'x' [-Wunused-variable]";
        let tokens = HashSet::new();
        let warnings = parse_c_cpp_diagnostics(output, &tokens);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_clangd_dedup_with_forge() {
        let output = "test.cpp:5:3: error: use of undeclared identifier 'foo'";
        let mut tokens = HashSet::new();
        tokens.insert("foo".to_string());
        let warnings = parse_c_cpp_diagnostics(output, &tokens);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_rustc_no_field() {
        let output = "error[E0609]: no field `await` on type `impl Future<Output = Result<(), Error>>`";
        let tokens = HashSet::new();
        let warnings = parse_rust_diagnostics(output, &tokens);
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("no field"));
    }

    #[test]
    fn test_parse_rustc_skips_crate_resolution() {
        let output = "error[E0433]: cannot find crate `sqlx` in this scope";
        let tokens = HashSet::new();
        let warnings = parse_rust_diagnostics(output, &tokens);
        assert!(warnings.is_empty(), "should skip crate resolution FPs");
    }

    #[test]
    fn test_parse_go_undefined() {
        let output = "./test.go:5:2: undefined: someFunction";
        let tokens = HashSet::new();
        let warnings = parse_go_diagnostics(output, &tokens);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_parse_go_list_fail_lines_marks_hallucinated_imports() {
        let stdout = "\
github.com/sirupsen/logrus OK
github.com/fake/nonexistent/pkg FAIL
golang.org/x/sync OK
github.com/another/fake FAIL
";
        let unresolved = parse_go_list_fail_lines(stdout);
        assert_eq!(unresolved.len(), 2);
        assert!(unresolved.contains("github.com/fake/nonexistent/pkg"));
        assert!(unresolved.contains("github.com/another/fake"));
    }

    #[test]
    fn test_parse_go_list_fail_lines_empty_or_all_ok() {
        assert!(parse_go_list_fail_lines("").is_empty());
        let all_ok = "fmt OK\ngolang.org/x/sync OK\n";
        assert!(parse_go_list_fail_lines(all_ok).is_empty());
    }

    #[test]
    fn test_parse_go_list_fail_lines_ignores_path_ending_in_FAIL() {
        // Regression guard: a real package path could in theory end with
        // "FAIL" — extremely unlikely, but the suffix-strip is the contract.
        // Document the behavior: such a path with no OK marker is flagged.
        // For OK lines, the suffix must be exactly " OK" or " FAIL".
        let stdout = "github.com/weird/FAIL OK\n";
        let unresolved = parse_go_list_fail_lines(stdout);
        assert!(unresolved.is_empty(), "OK-suffixed lines are not flagged");
    }

    #[tokio::test]
    #[ignore = "requires go toolchain + network; run with --ignored"]
    async fn go_compiler_gate_catches_fake_third_party_import() {
        // End-to-end smoke: hallucinated third-party import path must be
        // flagged. Covers the original bug — go vet's "cannot find module"
        // error shape slipped through the existing regex.
        let code = "package main\n\nimport (\n\t\"fmt\"\n\t\"github.com/totally/fake/library\"\n)\n\nfunc main() {\n\tfmt.Println(\"hi\")\n}\n";
        let genuine = go_compiler_gate(code, &[]).await.expect("gate ran");
        assert!(
            genuine.contains("github.com/totally/fake/library"),
            "expected hallucinated import in {:?}",
            genuine
        );
    }

    #[tokio::test]
    #[ignore = "requires go toolchain; run with --ignored"]
    async fn go_compiler_gate_catches_fake_stdlib_shaped_import() {
        // Hallucinated no-dot import (`fakepackagexyz`) — looks like stdlib
        // but isn't. Stdlib-batch `go list` flags it.
        let code = "package main\n\nimport \"fakepackagexyz\"\n\nfunc main() {\n\tfakepackagexyz.Function()\n}\n";
        let genuine = go_compiler_gate(code, &[]).await.expect("gate ran");
        assert!(
            genuine.contains("fakepackagexyz"),
            "expected hallucinated import in {:?}",
            genuine
        );
    }

    #[tokio::test]
    #[ignore = "requires go toolchain; run with --ignored"]
    async fn go_compiler_gate_no_fp_on_valid_stdlib() {
        // TN case: valid stdlib imports must not be flagged.
        let code = "package main\n\nimport (\n\t\"fmt\"\n\t\"strings\"\n)\n\nfunc main() {\n\tfmt.Println(strings.ToUpper(\"hi\"))\n}\n";
        let genuine = go_compiler_gate(code, &[]).await.expect("gate ran");
        assert!(
            genuine.is_empty(),
            "valid stdlib imports should not be flagged, got {:?}",
            genuine
        );
    }

    #[test]
    fn test_parse_csharp_cs0103() {
        let output = "Program.cs(15,10): error CS0103: The name 'ControllerBase' does not exist in the current context";
        let tokens = HashSet::new();
        let warnings = parse_csharp_diagnostics(output, &tokens);
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("CS"));
    }

    #[test]
    fn test_parse_csharp_skips_cs0169() {
        let output = "Program.cs(10,5): warning CS0169: The field 'x' is never used";
        let tokens = HashSet::new();
        let warnings = parse_csharp_diagnostics(output, &tokens);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_extract_forge_tokens() {
        let forge = vec![
            "hallucinated-import: `foo` not found".to_string(),
            "hallucinated-method: `bar.get`".to_string(),
        ];
        let tokens = extract_forge_tokens(&forge);
        assert!(tokens.contains("foo"));
        assert!(tokens.contains("bar.get"));
    }

    #[test]
    fn test_write_temp_file_creates_file() {
        let code = "int main() { return 0; }";
        let path = write_temp_file(code, "c").expect("should write temp file");
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, code);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_extract_first_quoted_symbol_attribute_access() {
        let msg = r#""read_cvs" is not a known attribute of module "pandas""#;
        assert_eq!(
            extract_first_quoted_symbol(msg).as_deref(),
            Some("read_cvs")
        );
    }

    #[test]
    fn test_extract_first_quoted_symbol_undefined_variable() {
        let msg = r#""foo" is not defined"#;
        assert_eq!(extract_first_quoted_symbol(msg).as_deref(), Some("foo"));
    }

    #[test]
    fn test_extract_first_quoted_symbol_missing_import() {
        let msg = r#"Import "nonexistent_module_xyz" could not be resolved"#;
        assert_eq!(
            extract_first_quoted_symbol(msg).as_deref(),
            Some("nonexistent_module_xyz")
        );
    }

    #[test]
    fn test_extract_first_quoted_symbol_multiline_message() {
        // pyright emits multi-line messages for reportAttributeAccessIssue
        let msg = "Cannot access attribute \"fabricated_method\" for class \"dict[str, int]\"\n  Attribute \"fabricated_method\" is unknown";
        assert_eq!(
            extract_first_quoted_symbol(msg).as_deref(),
            Some("fabricated_method")
        );
    }

    #[test]
    fn test_extract_first_quoted_symbol_no_quotes() {
        assert!(extract_first_quoted_symbol("no quotes here").is_none());
    }

    #[test]
    fn test_parse_pyright_hallucinations_attribute_access() {
        let stdout = r#"{
            "version":"1.1.411",
            "generalDiagnostics":[
                {"severity":"error","message":"\"read_cvs\" is not a known attribute of module \"pandas\"","rule":"reportAttributeAccessIssue"}
            ]
        }"#;
        let out = parse_pyright_hallucinations(stdout, true);
        assert!(out.contains("read_cvs"), "expected read_cvs in {:?}", out);
    }

    #[test]
    fn test_parse_pyright_hallucinations_undefined_var() {
        let stdout = r#"{
            "version":"1.1.411",
            "generalDiagnostics":[
                {"severity":"error","message":"\"foo\" is not defined","rule":"reportUndefinedVariable"}
            ]
        }"#;
        let out = parse_pyright_hallucinations(stdout, true);
        assert!(out.contains("foo"));
    }

    #[test]
    fn test_parse_pyright_primary_skips_missing_imports() {
        // Primary mode must NOT emit reportMissingImports (env-specific FP).
        let stdout = r#"{
            "version":"1.1.411",
            "generalDiagnostics":[
                {"severity":"error","message":"Import \"pandas\" could not be resolved","rule":"reportMissingImports"}
            ]
        }"#;
        let out = parse_pyright_hallucinations(stdout, true);
        assert!(out.is_empty(), "primary mode must skip missing-imports: {:?}", out);
    }

    #[test]
    fn test_parse_pyright_suppression_includes_missing_imports() {
        let stdout = r#"{
            "version":"1.1.411",
            "generalDiagnostics":[
                {"severity":"error","message":"Import \"nonexistent_module_xyz\" could not be resolved","rule":"reportMissingImports"}
            ]
        }"#;
        let out = parse_pyright_hallucinations(stdout, false);
        assert!(out.contains("nonexistent_module_xyz"));
    }

    #[test]
    fn test_parse_pyright_skips_warnings_and_infos() {
        let stdout = r#"{
            "version":"1.1.411",
            "generalDiagnostics":[
                {"severity":"warning","message":"\"x\" is unused","rule":"reportUnusedVariable"},
                {"severity":"information","message":"\"y\" stuff","rule":"reportAttributeAccessIssue"}
            ]
        }"#;
        let out = parse_pyright_hallucinations(stdout, true);
        assert!(out.is_empty(), "warnings/info must be skipped: {:?}", out);
    }

    #[test]
    fn test_parse_pyright_invalid_json_returns_empty() {
        let out = parse_pyright_hallucinations("not json at all", true);
        assert!(out.is_empty());
    }

    // ---- GDScript check-only subprocess gate ----

    #[test]
    fn test_strip_ansi_removes_color_codes() {
        // Godot emits ANSI even when stderr is piped — prefix matching must
        // run on the stripped form.
        assert_eq!(
            strip_ansi("\x1b[31;1mSCRIPT ERROR: Parse Error: boom\x1b[0m"),
            "SCRIPT ERROR: Parse Error: boom"
        );
        assert_eq!(strip_ansi("plain line"), "plain line");
        assert_eq!(strip_ansi("multi \x1b[1;35mcode\x1b[0m mid"), "multi code mid");
    }

    #[tokio::test]
    #[ignore = "requires godot binary on PATH; run with --ignored"]
    async fn godot_check_only_detects_invalid_operands_primary() {
        // Ground truth (Godot 4.7): String * int →
        // SCRIPT ERROR: Parse Error: Invalid operands "String" and "int" for "*" operator.
        let code = "extends Node\n\nvar status: String = \"ok\"\n\nfunc _ready() -> void:\n    var count: int = 5\n    print(status * count)\n";
        let genuine = verify_godot_check_only(code, &HashSet::new(), true)
            .await
            .expect("godot binary present");
        assert!(
            !genuine.is_empty(),
            "String * int misuse must surface in primary mode, got: {genuine:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires godot binary on PATH; run with --ignored"]
    async fn godot_check_only_detects_undeclared_identifier_primary() {
        // Ground truth (Godot 4.7):
        // SCRIPT ERROR: Parse Error: Identifier "x" not declared in the current scope.
        let code = "extends Node\n\nfunc _ready() -> void:\n    print(undefined_thing_xyz)\n";
        let genuine = verify_godot_check_only(code, &HashSet::new(), true)
            .await
            .expect("godot binary present");
        assert!(
            genuine.contains("undefined_thing_xyz"),
            "undeclared identifier must surface in primary mode, got: {genuine:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires godot binary on PATH; run with --ignored"]
    async fn godot_check_only_suppression_mode_confirms_forge_symbol() {
        let code = "extends Node\n\nfunc _ready() -> void:\n    print(undefined_thing_xyz)\n";
        let forge = HashSet::from(["undefined_thing_xyz".to_string()]);
        let genuine = verify_godot_check_only(code, &forge, false)
            .await
            .expect("godot binary present");
        assert!(
            genuine.contains("undefined_thing_xyz"),
            "FORGE-flagged identifier must be confirmed by compiler, got: {genuine:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires godot binary on PATH; run with --ignored"]
    async fn godot_check_only_clean_script_clears_forge_warnings() {
        let code = "extends Node\n\nfunc _ready() -> void:\n    print(\"hello\")\n";
        let forge = HashSet::from(["made_up_method".to_string()]);
        let genuine = verify_godot_check_only(code, &forge, false)
            .await
            .expect("godot binary present");
        assert!(
            genuine.is_empty(),
            "clean parse must clear all FORGE warnings, got: {genuine:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires godot binary on PATH; run with --ignored"]
    async fn godot_check_only_primary_excludes_type_mismatch_errors() {
        // Ground truth (Godot 4.7, Godot-3-style connect args):
        // SCRIPT ERROR: Parse Error: Invalid argument for "connect()" function: ...
        // Arg-type errors fire on real APIs with wrong arg types — FP trap in
        // primary mode, excluded by design (mirrors rust gate skipping E0308).
        let code = "extends Node\n\nfunc _ready() -> void:\n    var t = Timer.new()\n    t.connect(\"timeout\", self, \"_on_timeout\")\n";
        let genuine = verify_godot_check_only(code, &HashSet::new(), true)
            .await
            .expect("godot binary present");
        assert!(
            genuine.is_empty(),
            "arg-type errors must not surface in primary mode, got: {genuine:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires godot binary on PATH; run with --ignored"]
    async fn gdscript_gate_falls_through_to_check_only_when_editor_down() {
        // TCP :6005 probe fails without a running editor → old behavior was
        // skip (None). The gate must now produce a verdict via the
        // check-only subprocess arm instead of returning None.
        let code = "extends Node\n\nfunc _ready() -> void:\n    print(undefined_thing_xyz)\n";
        let genuine = gdscript_compiler_gate(code, &[]).await;
        assert!(
            genuine.is_some(),
            "gate must produce a verdict (check-only fallback), got None"
        );
    }
}


pub(crate) fn extract_warning_symbols(warning: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    // Backtick-quoted (possibly dotted). Split on '.' to catch `foo.bar` as
    // both the compound and its parts.
    for s in crate::scanner::lsp_gate::extract_backtick_symbols(warning) {
        out.insert(s.to_lowercase());
        for part in s.split('.') {
            if !part.is_empty() {
                out.insert(part.to_lowercase());
            }
        }
    }
    // Non-backtick: prefix: IDENT.IDENT() — ...
    // Take text between first ": " and the next " —" or "(", extract IDENTs.
    if let Some(colon_pos) = warning.find(": ") {
        let rest = &warning[colon_pos + 2..];
        let end = rest
            .find(" —")
            .or_else(|| rest.find('('))
            .unwrap_or(rest.len());
        let symbol_part = &rest[..end];
        let re = regex::Regex::new(r"[A-Za-z_]\w*").unwrap();
        for m in re.find_iter(symbol_part) {
            out.insert(m.as_str().to_lowercase());
        }
    }
    // Single-quoted symbols: TS diagnostics use 'sym' quoting —
    // "TS2339 — Property 'sum' does not exist on type 'number[]'."
    // The " — " guard above stops at the em-dash so the message body (which
    // carries the real symbol) is never scanned by the non-backtick branch.
    //
    // GUARD (overfit-audit): skip quotes in TYPE position — "on type 'X'" /
    // "of type 'X'" name the RECEIVER TYPE, not the hallucinated symbol.
    // Capturing them pollutes the symbol set (e.g. 'Document' from
    // "on type 'Document'") and can false-retain warnings whose forge
    // symbols coincidentally match the type name.
    let re_q = regex::Regex::new(r"'([A-Za-z_][A-Za-z0-9_]*)'").unwrap();
    for cap in re_q.captures_iter(warning) {
        let m = cap.get(0).unwrap();
        let before = &warning[..m.start()];
        if before.ends_with("on type ") || before.ends_with("of type ") {
            continue;
        }
        let s = cap[1].to_string();
        out.insert(s.to_lowercase());
        for part in s.split('.') {
            if !part.is_empty() {
                out.insert(part.to_lowercase());
            }
        }
    }
    out
}

fn extract_rust_code(content: &str) -> String {
    let mut code = String::new();
    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !in_block {
            // Open fence: ```rust, ```rs, or bare ``` followed by rust code.
            if trimmed.starts_with("```")
                && (trimmed == "```"
                    || trimmed.starts_with("```rust")
                    || trimmed.starts_with("```rs"))
            {
                in_block = true;
            }
        } else if trimmed.starts_with("```") {
            in_block = false;
            code.push('\n');
        } else {
            code.push_str(line);
            code.push('\n');
        }
    }
    if code.is_empty() {
        content.to_string()
    } else {
        code
    }
}

pub(crate) async fn rust_compiler_gate(
    code: &str,
    forge_warnings: &[String],
    project_root: &str,
) -> Option<HashSet<String>> {
    let forge_symbols: HashSet<String> = forge_warnings
        .iter()
        .flat_map(|w| extract_warning_symbols(w))
        .collect();
    // PRIMARY MODE: when FORGE has no warnings, run compiler as primary
    // detector. Return ALL unresolved symbols, not just intersection.
    let run_as_primary = forge_symbols.is_empty();

    // ADAPTIVE DEPENDENCY CONTEXT: when the project has a Cargo.toml (real
    // project with resolved external crates), E0432/E0433 from rustc on the
    // single-file snippet reliably indicate hallucinated imports — capture
    // them all. When there's no Cargo.toml (bare benchmark skeleton or
    // ad-hoc snippet), external-crate E0432/E0433 fire for every `use sqlx`
    // / `use tokio` etc. because they're not in the single-file compilation
    // context — filter to stdlib paths only to avoid FP storm.
    let has_cargo_toml = !project_root.is_empty()
        && std::path::Path::new(project_root).join("Cargo.toml").exists();

    let rustc = find_binary("rustc")?;

    let rust_code = extract_rust_code(code);
    // Bare snippets (`let n: usize = 5;` at top level) parse-fail rustc
    // before type-checking — wrap via shared helper (see verify_rust).
    let rust_code = wrap_bare_rust_snippet(rust_code);
    let work_dir = std::env::temp_dir()
        .join("anubis-rust-gate")
        .join(format!("gate_{}", uuid_v4_simple()));
    std::fs::create_dir_all(&work_dir).ok()?;
    let in_path = work_dir.join("anubis_check.rs");
    if std::fs::write(&in_path, rust_code.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&work_dir);
        return None;
    }

    let in_str = in_path.to_string_lossy().to_string();
    let result = run_with_timeout(
        &rustc,
        &["--crate-type", "lib", "--emit=metadata", &in_str],
        Some(&work_dir),
        15,
    )
    .await;

    let _ = std::fs::remove_dir_all(&work_dir);

    let (_, stderr) = result?;

    // Capture genuine unresolved symbol codes. Include E0432/E0433 for
    // stdlib paths (std::, core::, alloc::) — these catch fabricated
    // stdlib types/imports. External crate E0432/E0433 noise is filtered
    // by the primary-mode intersection logic (symbols must be real words).
    let capture_codes = ["E0425", "E0426", "E0432", "E0433", "E0061", "E0599", "E0609", "E0277", "E0382"];
    // Uncoded errors (no [Exxxx]) that indicate hallucinated symbols.
    // rustc emits these as plain "error:" without a code bracket.
    let uncoded_patterns = [
        "cannot find macro",
        "cannot find function",
        "cannot find type",
        "cannot find value",
        "cannot find attribute",
        "expected one of", // macro expansion failures
    ];

    // No bail-out: multi-file responses (markdown with ```rust fences joined
    // by `// File:` markers) can produce 50+ cascade errors from missing
    // crate paths, but the genuine error codes (E0425/E0426/E0599/E0609)
    // remain reliable. Intersection with FORGE symbols filters cascade noise.
    let stdlib_prefixes = ["std::", "core::", "alloc::"];
    let mut unresolved: HashSet<String> = HashSet::new();
    for line in stderr.lines() {
        let has_code = capture_codes.iter().any(|c| line.contains(c));
        let has_uncoded = uncoded_patterns.iter().any(|p| line.contains(p));
        if !has_code && !has_uncoded {
            continue;
        }
        // In primary mode (FORGE had no warnings), E0432/E0433 fire for every
        // external crate import (sqlx, tokio, axum) because they're not in the
        // single-file compilation context. When a Cargo.toml is present at the
        // project root, external crates resolve via Cargo, so remaining
        // E0432/E0433 are genuine hallucinations — capture them all. When there
        // is no Cargo.toml (bare skeleton), filter to stdlib paths only — that's
        // where real hallucinations live without producing FP noise.
        // In FP-suppression mode, the FORGE intersection handles filtering.
        if run_as_primary && !has_cargo_toml
            && (line.contains("E0432") || line.contains("E0433"))
        {
            let is_stdlib = stdlib_prefixes.iter().any(|p| line.contains(p));
            if !is_stdlib {
                continue;
            }
        }
        for sym in crate::scanner::lsp_gate::extract_backtick_symbols(line) {
            unresolved.insert(sym.to_lowercase());
        }
    }

    // In primary mode, return ALL compiler-detected unresolved symbols.
    // In FP-suppression mode, return intersection (FORGE-flagged AND compiler-confirmed).
    let genuine: HashSet<String> = if run_as_primary {
        unresolved
    } else {
        forge_symbols.intersection(&unresolved).cloned().collect()
    };

    tracing::info!(
        target: "compiler_gate",
        mode = if run_as_primary { "primary" } else { "fp-suppression" },
        forge = forge_symbols.len(),
        unresolved_by_rustc = genuine.len(),
        genuine = genuine.len(),
        has_cargo_toml,
        project_root,
        "Rust compiler gate complete",
    );

    Some(genuine)
}



pub(crate) async fn c_cpp_compiler_gate(
    code: &str,
    forge_warnings: &[String],
) -> Option<HashSet<String>> {
    let forge_symbols: HashSet<String> = extract_forge_tokens(forge_warnings);
    let run_as_primary = forge_symbols.is_empty();

    // Require at least one C/C++ compiler to be available.
    let compiler_available = find_binary("clangd").is_some()
        || find_binary("clang").is_some()
        || find_binary("clang++").is_some()
        || find_binary("gcc").is_some()
        || find_binary("g++").is_some();
    if !compiler_available {
        return None;
    }

    // Empty forge_tokens — we want ALL compiler-reported unresolved symbols,
    // not the intersection-filtered set that verify_c_cpp would return.
    let empty_set = HashSet::new();
    let diagnostics = verify_c_cpp(code, &empty_set).await;
    if diagnostics.is_empty() {
        // Compiler accepted everything (or produced only filtered/skipped
        // diagnostics). Treat all FORGE warnings as FPs.
        tracing::info!(
            target: "compiler_gate",
            forge = forge_symbols.len(),
            "C/C++ compiler gate: compiler accepted code, all FORGE warnings look like FPs"
        );
        return Some(HashSet::new());
    }

    // Re-extract identifiers from compiler diagnostics. verify_c_cpp returns
    // lines prefixed with "compiler: "; extract_identifier_from_clangd_msg
    // pulls single-quoted identifiers from clang/gcc error formats.
    let mut unresolved: HashSet<String> = HashSet::new();
    for line in &diagnostics {
        if let Some(ident) = extract_identifier_from_clangd_msg(line) {
            unresolved.insert(ident.to_lowercase());
        }
    }

    let genuine: HashSet<String> = if run_as_primary { unresolved.clone() } else { forge_symbols.intersection(&unresolved).cloned().collect() };

    tracing::info!(
        target: "compiler_gate",
        forge = forge_symbols.len(),
        unresolved_by_compiler = unresolved.len(),
        genuine = genuine.len(),
        "C/C++ compiler gate: {} of {} FORGE warnings are genuine",
        genuine.len(),
        forge_symbols.len()
    );

    Some(genuine)
}

pub(crate) async fn gdscript_compiler_gate(
    code: &str,
    forge_warnings: &[String],
) -> Option<HashSet<String>> {
    let forge_symbols: HashSet<String> = extract_forge_tokens(forge_warnings);
    let run_as_primary = forge_symbols.is_empty();

    // Pre-flight TCP probe — Godot editor must be running on port 6005.
    // If unreachable, fall through to the headless check-only subprocess
    // arm (verify_godot_check_only) instead of skipping the gate.
    use std::net::TcpStream;
    use std::time::Duration;
    if TcpStream::connect_timeout(
        &"127.0.0.1:6005".parse().unwrap(),
        Duration::from_secs(2),
    )
    .is_err()
    {
        tracing::info!(
            target: "compiler_gate",
            "GDScript compiler gate: Godot editor not reachable on :6005, trying check-only subprocess"
        );
        return verify_godot_check_only(code, &forge_symbols, run_as_primary).await;
    }

    // Empty forge_tokens — we want ALL LSP-reported unresolved symbols.
    let empty_set = HashSet::new();
    let diagnostics = verify_godot_tcp(code, &empty_set).await;
    if diagnostics.is_empty() {
        // LSP accepted everything. Treat all FORGE warnings as FPs.
        tracing::info!(
            target: "compiler_gate",
            forge = forge_symbols.len(),
            "GDScript compiler gate: LSP accepted code, all FORGE warnings look like FPs"
        );
        return Some(HashSet::new());
    }

    // LSP diagnostics come as `"message":"..."` JSON pairs, prefixed with
    // "compiler: Godot LSP: ". Single-quoted extraction doesn't apply —
    // extract via extract_backtick_symbols which handles any quoted form,
    // plus split bare identifiers from the message text.
    let mut unresolved: HashSet<String> = HashSet::new();
    for line in &diagnostics {
        // Strip the "compiler: Godot LSP: " prefix to get the message body.
        let body = line.strip_prefix("compiler: Godot LSP: ").unwrap_or(line);
        // Pull any backtick-quoted symbols.
        for sym in crate::scanner::lsp_gate::extract_backtick_symbols(body) {
            unresolved.insert(sym.to_lowercase());
        }
        // Also pull bare identifiers from phrases like
        // "Function 'foo()' not found" — single-quote extraction reuses
        // clangd helper since it handles single-quoted identifiers.
        if let Some(ident) = extract_identifier_from_clangd_msg(body) {
            unresolved.insert(ident.to_lowercase());
        }
    }

    let genuine: HashSet<String> = if run_as_primary { unresolved.clone() } else { forge_symbols.intersection(&unresolved).cloned().collect() };

    tracing::info!(
        target: "compiler_gate",
        forge = forge_symbols.len(),
        unresolved_by_lsp = unresolved.len(),
        genuine = genuine.len(),
        "GDScript compiler gate: {} of {} FORGE warnings are genuine",
        genuine.len(),
        forge_symbols.len()
    );

    Some(genuine)
}

/// Locate the Godot binary: PATH lookup for `godot` / `godot4` (Windows
/// `godot.exe` is covered by the `godot` probe). Returns None when no
/// editor binary is installed — the gate then skips (conservative).
fn find_godot_binary() -> Option<PathBuf> {
    find_binary("godot").or_else(|| find_binary("godot4"))
}

/// Strip ANSI escape sequences (e.g. `\x1b[31;1m` color codes) from a
/// stderr line. Godot emits color codes even when stderr is piped, so
/// prefix matching (`SCRIPT ERROR:`) must run on the stripped form.
fn strip_ansi(line: &str) -> String {
    static ANSI_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = ANSI_RE.get_or_init(|| {
        regex::Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").expect("valid ansi regex")
    });
    re.replace_all(line, "").into_owned()
}

/// Headless GDScript verification via `godot --headless --check-only
/// --script <abs temp.gd>`. Tier-2 fallback for `gdscript_compiler_gate`
/// when no editor is listening on :6005 — parse-only, no project context
/// required, so it works on fenced GDScript fragments from agent responses.
///
/// Contract mirrors `rust_compiler_gate` (two modes):
///   - FP-suppression (FORGE non-empty): a clean parse → Some(empty) (all
///     FORGE warnings are FPs); errors → Some(FORGE ∩ compiler symbols).
///   - Primary (FORGE empty): error identifiers surface as new warnings.
///
/// stderr is the primary signal — godot's exit code is historically
/// unreliable (#33895, #54087, #89229):
///   - `SCRIPT ERROR: <msg>` lines are the target errors (String * int
///     operator misuse lands here).
///   - `at:` continuation lines and `WARNING:` lines are ignored; the
///     engine banner goes to stdout, also ignored.
///   - `ERROR: Failed to load script ... "Parse error"` is a trailing
///     confirmation of the SCRIPT ERROR lines above it — counted once.
///   - `SCRIPT ERROR: Compile Error: Identifier not found: <name>` is an
///     FP trap in primary mode: autoload singletons are not populated when
///     compiling via `--script` without project context (#78587, #80319),
///     so primary mode keeps Parse Error lines only (suppression mode's
///     FORGE intersection already filters the noise).
///
/// NEVER pass `--debug` — the interactive debugger wedges forever on
/// parse-error scripts (godot#117123).
async fn verify_godot_check_only(
    code: &str,
    forge_symbols: &HashSet<String>,
    run_as_primary: bool,
) -> Option<HashSet<String>> {
    let godot = find_godot_binary()?;
    let temp = write_temp_file(code, "gd")?;
    let script_path = temp.to_string_lossy().to_string();
    let result = run_with_timeout(
        &godot,
        &["--headless", "--check-only", "--script", &script_path],
        None,
        15,
    )
    .await;
    let _ = std::fs::remove_file(&temp);
    let (_, stderr) = result?;

    let mut error_lines: Vec<String> = Vec::new();
    let mut has_error_confirmation = false;
    for raw_line in stderr.lines() {
        let line = strip_ansi(raw_line);
        if line.starts_with("SCRIPT ERROR:") {
            if line.contains("Parse Error:") {
                error_lines.push(line);
            } else if run_as_primary {
                // Compile Error shapes (Identifier not found etc.) are FP
                // traps without project context — only surfaced when they
                // corroborate an existing FORGE warning (suppression mode).
            } else {
                error_lines.push(line);
            }
        } else if line.starts_with("ERROR: Failed to load script") {
            has_error_confirmation = true;
        }
        // `at:` continuations, WARNING:, banner — ignored.
    }

    // Primary-mode category filter. Excluded shapes:
    //   - TYPE-MISMATCH: fires on REAL functions with wrong arg types
    //     (`Invalid argument for "connect()" ...`) - API-version drift in
    //     otherwise-valid code, FP as a new warning. Mirrors the rust
    //     gate's E0308 exclusion.
    //   - SCOPE-RESOLUTION (`Could not find type/member`, `Identifier ...
    //     not declared`): GDScript compiles `class_name`/autoload/project
    //     types only WITH project context; the check-only subprocess has
    //     none, so every cross-file reference errors. FP trap per
    //     godotengine/godot#78587 / #80319.
    // Unknown-symbol shapes stay captured ONLY in suppression mode (FORGE
    // already flagged the symbol); semantic misuse (`Invalid operands`)
    // stays captured in both.
    const TYPE_MISMATCH_MARKERS: &[&str] = &[
        "Invalid argument for",
        "Cannot pass a value of type",
        "Cannot infer the type",
    ];
    const SCOPE_RESOLUTION_MARKERS: &[&str] =
        &["Could not find type", "Could not find member", "not declared in the current scope"];
    // Structural shapes mean the fragment itself is malformed (most often
    // extraction-filter indentation loss, not agent hallucination) - the
    // parse verdict is untrustworthy in BOTH modes.
    const STRUCTURAL_ERROR_MARKERS: &[&str] = &[
        "Expected indented block",
        "Unexpected indent",
        "Unexpected EOF",
        "expected \":\"",
    ];
    if error_lines
        .iter()
        .any(|l| STRUCTURAL_ERROR_MARKERS.iter().any(|m| l.contains(m)))
    {
        tracing::info!(
            target: "compiler_gate",
            forge = forge_symbols.len(),
            "GDScript check-only gate: structural error (fragment untrusted) - abstaining"
        );
        return None;
    }
    let parse_error_lines: Vec<&String> = if run_as_primary {
        error_lines
            .iter()
            .filter(|l| {
                !TYPE_MISMATCH_MARKERS.iter().any(|m| l.contains(m))
                    && !SCOPE_RESOLUTION_MARKERS.iter().any(|m| l.contains(m))
            })
            .collect()
    } else {
        error_lines.iter().collect()
    };

    if parse_error_lines.is_empty() && !has_error_confirmation {
        tracing::info!(
            target: "compiler_gate",
            forge = forge_symbols.len(),
            "GDScript check-only gate: script parses clean, all FORGE warnings look like FPs"
        );
        return Some(HashSet::new());
    }

    let mut unresolved: HashSet<String> = HashSet::new();
    for line in &parse_error_lines {
        // Could not find type "void2" / member "foo" — first double-quoted
        // token is the offending symbol (extract_first_quoted_symbol).
        if let Some(sym) = extract_first_quoted_symbol(line) {
            unresolved.insert(sym.to_lowercase());
        }
        // Identifier not found: <name> — bare identifier after the colon.
        if let Some(idx) = line.rfind("Identifier not found: ") {
            let name: String = line[idx + "Identifier not found: ".len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                unresolved.insert(name.to_lowercase());
            }
        }
    }

    // Semantic-misuse shapes (`Invalid operands "String" and "int"`) carry
    // no quoted symbol and no `Identifier not found` marker - the loops
    // above extract nothing. These errors are self-contained facts (operand
    // types, operator misuse), never project-context dependent, so surface
    // one synthesized readable token as the warning. Structural shapes were
    // already excluded above; anything else without a symbol abstains.
    const SEMANTIC_MISUSE_MARKERS: &[&str] = &[
        "Invalid operands",
        "Cannot call",
        "Cannot return",
        "Cannot assign",
    ];
    if unresolved.is_empty() {
        let semantic = parse_error_lines
            .iter()
            .find(|l| SEMANTIC_MISUSE_MARKERS.iter().any(|m| l.contains(m)));
        if let Some(first) = semantic {
            let msg = strip_ansi(first);
            let tail = msg.rsplit("Parse Error:").next().unwrap_or(msg.as_str()).trim();
            let token: String = tail.chars().take(60).collect::<String>().to_lowercase();
            if !token.is_empty() {
                unresolved.insert(token);
            }
        } else {
            // Errors exist but no symbol and no semantic shape: the verdict
            // is untrusted (unknown error class). Abstain rather than
            // report a clean parse - Some(empty) would license the emit
            // path to wipe every FORGE warning (suppression laundering).
            tracing::info!(
                target: "compiler_gate",
                "GDScript check-only gate: unparseable error class, no extractable signal - abstaining"
            );
            return None;
        }
    }

    let genuine: HashSet<String> = if run_as_primary {
        unresolved.clone()
    } else {
        forge_symbols
            .intersection(&unresolved)
            .cloned()
            .collect()
    };

    tracing::info!(
        target: "compiler_gate",
        mode = if run_as_primary { "primary" } else { "fp-suppression" },
        forge = forge_symbols.len(),
        parse_errors = parse_error_lines.len(),
        load_confirmation = has_error_confirmation,
        unresolved = unresolved.len(),
        genuine = genuine.len(),
        "GDScript check-only gate complete"
    );

    Some(genuine)
}

/// Java compiler gate — javac temp-file compile with cannot-find-symbol
/// capture. Mirrors rust_compiler_gate's two modes:
///   - PRIMARY (FORGE empty): all unresolved symbols as new warnings.
///   - FP-suppression: intersection with FORGE-flagged symbols.
///
/// Kind filtering (empirical, javac 17):
///   - Primary mode keeps `method` kind only. `class` / `package` /
///     `variable` unresolved errors fire for every external dependency the
///     single-file compile context lacks (RestTemplate, org.springframework.*
///     packages) — the same noise rust's no-Cargo.toml E0432/E0433 filter
///     removes. Cross-language method confusion (`xs.map()` on java.util.List)
///     is always `method` kind.
///   - Suppression mode keeps all kinds: FORGE already flagged the symbol,
///     the compiler confirming it unresolved (any kind) makes it genuine.
pub(crate) async fn java_compiler_gate(
    code: &str,
    forge_warnings: &[String],
) -> Option<HashSet<String>> {
    let forge_symbols: HashSet<String> = extract_forge_tokens(forge_warnings);
    let run_as_primary = forge_symbols.is_empty();

    let javac = find_binary("javac")?;

    let java_code = extract_java_code(code);
    if java_code.trim().is_empty() {
        return None;
    }
    // Bare statements/expressions (no class decl) parse-fail javac before
    // type-checking — wrap in a class + main stub like wrap_bare_rust_snippet.
    let java_code = wrap_bare_java_snippet(java_code);

    let work_dir = std::env::temp_dir()
        .join("anubis-java-gate")
        .join(format!("gate_{}", uuid_v4_simple()));
    std::fs::create_dir_all(&work_dir).ok()?;
    let in_path = work_dir.join("AnubisGateCheck.java");
    if std::fs::write(&in_path, java_code.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&work_dir);
        return None;
    }

    let in_str = in_path.to_string_lossy().to_string();
    let result = run_with_timeout(
        &javac,
        &["-d", work_dir.to_string_lossy().to_string().as_str(), "-nowarn", &in_str],
        Some(&work_dir),
        15,
    )
    .await;

    let _ = std::fs::remove_dir_all(&work_dir);

    let (_, stderr) = result?;

    let mut unresolved: HashSet<String> = HashSet::new();
    let mut current_symbols: Vec<String> = Vec::new();
    let mut arity_syms: HashSet<String> = HashSet::new();
    for line in stderr.lines() {
        // "error: no suitable method found for substring(int,int,int)" —
        // arity/wrong-overload hallucination on a REAL method. The bare
        // method name is deterministic evidence (compiler checked the
        // receiver's whole overload set).
        if let Some(rest) = line.split_once("no suitable method found for ").map(|(_, r)| r) {
            let name = rest
                .split(|c: char| c == '(' || c == '<')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() && name.len() < 100 {
                unresolved.insert(name.to_lowercase());
                arity_syms.insert(name.to_lowercase());
            }
        }
        // "error: method X in class Y is not applicable
        //  (actual and formal argument lists differ in length)" — same
        // evidence class, different javac phrasing.
        if line.contains("actual and formal argument lists differ in length") {
            if let Some(rest) = line.split_once("method ").map(|(_, r)| r) {
                let name = rest.split(' ').next().unwrap_or("").trim();
                if !name.is_empty() && name.len() < 100 {
                    unresolved.insert(name.to_lowercase());
                    arity_syms.insert(name.to_lowercase());
                }
            }
        }
        if line.contains("error: cannot find symbol") {
            // Flush previous group into the set.
            for sym in current_symbols.drain(..) {
                unresolved.insert(sym.to_lowercase());
            }
            continue;
        }
        // Detail lines: "  symbol:   method map((x)->x * 2)"
        //               "  symbol:   class RestTemplate"
        //               "  symbol:   variable xs"
        if let Some(rest) = line.trim_start().strip_prefix("symbol:") {
            let rest = rest.trim();
            // "method map((x)->x * 2)" / "class RestTemplate" — everything
            // after the kind token is the symbol (cut at '(' or '<').
            let tail = rest.split_once(' ').map(|(_, t)| t).unwrap_or("");
            let name = tail
                .split(|c: char| c == '(' || c == '<')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() && name.len() < 100 {
                current_symbols.push(name.to_string());
            }
            continue;
        }
        // "error: package org.springframework.web.client does not exist" —
        // suppression mode captures the trailing package segments so a
        // FORGE hallucinated-import warning (which quotes the import path)
        // intersects with the compiler's view.
        if let Some((_, rest)) = line.split_once("package ") {
            if rest.contains(" does not exist") {
                for seg in rest.split(" does not exist").next().unwrap_or("").split('.') {
                    let seg = seg.trim();
                    if seg.len() >= 3 && !seg.contains(' ') {
                        unresolved.insert(seg.to_lowercase());
                    }
                }
            }
        }
        // A non-indented line ends the current symbol group.
        if !line.starts_with("  ") {
            for sym in current_symbols.drain(..) {
                unresolved.insert(sym.to_lowercase());
            }
        }
    }
    // Flush trailing group.
    for sym in current_symbols.drain(..) {
        unresolved.insert(sym.to_lowercase());
    }

    // Primary mode: keep method-kind only (dep-noise filter). Re-walk with
    // kind tracking - the set above lost kind info, so redo cheaply.
    // Union ONLY the arity names (method-kind by construction) — not the
    // general-walk set (audit finding: class/package shapes would leak).
    if run_as_primary {
        let mut methods_only = extract_java_method_symbols(&stderr);
        for sym in &arity_syms {
            methods_only.insert(sym.clone());
        }
        tracing::info!(
            target: "compiler_gate",
            mode = "primary",
            unresolved_all = unresolved.len(),
            unresolved_methods = methods_only.len(),
            "Java compiler gate complete",
        );
        return Some(methods_only);
    }

    let genuine: HashSet<String> = forge_symbols.intersection(&unresolved).cloned().collect();
    tracing::info!(
        target: "compiler_gate",
        mode = "fp-suppression",
        forge = forge_symbols.len(),
        unresolved_by_javac = unresolved.len(),
        genuine = genuine.len(),
        "Java compiler gate complete",
    );
    Some(genuine)
}

/// Re-extract only method-kind cannot-find-symbol names from javac stderr.
fn extract_java_method_symbols(stderr: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut pending: Option<String> = None;
    for line in stderr.lines() {
        if line.contains("error: cannot find symbol") {
            if let Some(p) = pending.take() {
                out.insert(p.to_lowercase());
            }
            continue;
        }
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("symbol:") {
            let rest = rest.trim();
            if let Some((kind, tail)) = rest.split_once(' ') {
                if kind == "method" {
                    let name = tail
                        .split(|c: char| c == '(' || c == '<')
                        .next()
                        .unwrap_or("")
                        .trim();
                    if !name.is_empty() && name.len() < 100 {
                        pending = Some(name.to_string());
                    }
                }
            }
        } else if !t.starts_with("symbol:") && !line.starts_with("  ") {
            if let Some(p) = pending.take() {
                out.insert(p.to_lowercase());
            }
        }
    }
    if let Some(p) = pending.take() {
        out.insert(p.to_lowercase());
    }
    out
}

/// Extract java code from markdown (fences + bare java signatures).
fn extract_java_code(content: &str) -> String {
    let mut code = String::new();
    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !in_block {
            if trimmed.starts_with("```")
                && (trimmed.starts_with("```java") || trimmed == "```")
            {
                in_block = true;
            }
        } else if trimmed.starts_with("```") {
            in_block = false;
        } else {
            code.push_str(line);
            code.push('\n');
        }
    }
    if code.is_empty() {
        // Bare java (no fences) — take content as-is when it looks java-ish.
        let lower = content.to_lowercase();
        let java_ish = content.lines().any(|l| {
            let t = l.trim_start();
            t.starts_with("import ")
                || t.starts_with("public ")
                || t.starts_with("class ")
                || t.starts_with("package ")
        });
        if java_ish && !lower.contains("def ") && !lower.contains("fn ") {
            return content.to_string();
        }
    }
    code
}

/// Wrap bare java statements in a class+main stub so javac parses past the
/// wrapper into type-checking (mirror of wrap_bare_rust_snippet).
fn wrap_bare_java_snippet(code: String) -> String {
    let has_class = code.lines().any(|l| {
        let t = l.trim_start();
        t.contains("class ") && t.contains('{') || t.starts_with("public class")
    });
    if has_class {
        return code;
    }
    // Move any package/import lines outside the wrapper (javac requires
    // them first in file).
    let mut preamble = String::new();
    let mut body = String::new();
    for line in code.lines() {
        let t = line.trim_start();
        if t.starts_with("package ") || t.starts_with("import ") {
            preamble.push_str(line);
            preamble.push('\n');
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }
    format!("{preamble}public class AnubisGateCheck {{\n    public static void main(String[] args) {{\n{body}    }}\n}}\n")
}

#[cfg(test)]
mod java_gate_tests {
    use super::*;

    #[test]
    fn java_gate_parses_method_symbol() {
        let stderr = "Main.java:5: error: cannot find symbol\n        List<Integer> ys = xs.map(x -> x * 2);\n                             ^\n  symbol:   method map((x)->x * 2)\n  location: variable xs of type List<Integer>\n1 error\n";
        let out = extract_java_method_symbols(stderr);
        assert!(out.contains("map"), "got: {:?}", out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn java_gate_parses_class_symbol_kind() {
        let stderr = "Main2.java:4: error: cannot find symbol\n        RestTemplate rt = new RestTemplate();\n        ^\n  symbol:   class RestTemplate\n  location: class Main2\n1 error\n";
        let out = extract_java_method_symbols(stderr);
        assert!(!out.contains("resttemplate"), "class kind must be excluded from methods-only set, got: {:?}", out);
    }

    #[test]
    fn java_gate_wraps_bare_snippet() {
        let wrapped = wrap_bare_java_snippet("int x = 5;\nSystem.out.println(x);\n".to_string());
        assert!(wrapped.contains("public class AnubisGateCheck"));
        assert!(wrapped.contains("int x = 5;"));
    }

    #[test]
    fn java_gate_keeps_existing_class() {
        let code = "public class Main {\n    public static void main(String[] args) {}\n}\n".to_string();
        assert_eq!(wrap_bare_java_snippet(code.clone()), code);
    }

    #[test]
    fn java_gate_extract_code_from_fence() {
        let md = "```java\npublic class A { }\n```\n";
        assert!(extract_java_code(md).contains("public class A"));
    }
}
