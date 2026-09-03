//! TypeScript method hallucination detection via `tsc` compiler.
//!
//! Approach A from METHOD_DETECTION_PLAN.md: invoke the TypeScript compiler
//! (`tsc`) to detect TS2339 errors ("Property 'X' does not exist on type
//! 'Y'"). These are method hallucinations on typed receivers — the
//! highest-accuracy TS-specific detection mechanism available.
//!
//! Catches DELULU samples like:
//!   - `response.parseBody()` vs `response.json()` — `response` is `Response`
//!     (from `await fetch()`); `parseBody` not on Response.
//!
//! Implementation: spawns a Node.js subprocess that:
//!   1. Resolves the local `typescript` package via `require.resolve`.
//!   2. Writes source from stdin to a temp `.ts` file.
//!   3. Invokes the platform's native `tsc` binary (TS 7.x) or falls back
//!      to the JS `tsc.js` (TS 5.x) as a child process.
//!   4. Parses stderr for TS2339 diagnostics.
//!   5. Emits JSON `{diagnostics: [...]}` to stdout.
//!
//! Limitations:
//!   - Requires Node.js + typescript package resolvable from project_root
//!     (or globally via NODE_PATH). Returns empty (no warnings) if not.
//!   - Type resolution depends on package type declarations being installed
//!     in node_modules. Without @types/mongodb, `bulk.locate()` won't fire
//!     TS2339 because `bulk` resolves to `any`.
//!   - Captures TS2339 (method/property hallucination), TS2552 (typo of an
//!     in-scope name — "Did you mean 'X'?"), and TS2304 (genuinely undefined
//!     name). Deliberately skips TS2307 (Cannot find module) — that's a
//!     missing-dependency issue, not a hallucination.

use std::collections::HashSet;
use std::process::Stdio;
use std::time::Duration;

use once_cell::sync::Lazy;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Per-process availability cache. None = unchecked, Some(false) = not
/// available (don't retry every call), Some(true) = available.
static TS_AVAILABLE: Lazy<Mutex<Option<bool>>> = Lazy::new(|| Mutex::new(None));

/// Cached NODE_PATH that resolves typescript. Set when typescript is found
/// outside the default search path (e.g., global npm install). Propagated
/// to every subprocess so `require('typescript')` succeeds.
static NODE_PATH_FOR_TS: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

/// Result of a TS method check.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct TsDiagnostic {
    /// TypeScript diagnostic code (always 2339 for our filter).
    pub code: i32,
    /// Flattened message text (e.g., "Property 'parseBody' does not exist on type 'Response'.").
    pub message: String,
    /// 1-based line number.
    #[serde(default)]
    pub line: u32,
    /// 1-based column number.
    #[serde(default)]
    pub column: u32,
}

/// Resolve the global npm root via `npm root -g`. Cached.
///
/// On Windows, prefer `npm.cmd` (standard Node.js installer batch wrapper)
/// over bare `npm` which may resolve to a third-party shim (e.g. vite-plus)
/// that reports a different global root than where global packages are
/// actually installed.
async fn npm_global_root() -> Option<String> {
    static CACHE: Lazy<Mutex<Option<Option<String>>>> = Lazy::new(|| Mutex::new(None));
    let mut guard = CACHE.lock().await;
    if let Some(v) = &*guard {
        return v.clone();
    }
    let npm_bin = if cfg!(target_os = "windows") {
        // Try npm.cmd first (standard Node.js installer). Falls back to npm
        // if npm.cmd is not on PATH (rare).
        "npm.cmd"
    } else {
        "npm"
    };
    let result = crate::scanner::command_hidden_tokio(npm_bin)
        .arg("root")
        .arg("-g")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await;
    let value = match result {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        _ => None,
    };
    *guard = Some(value.clone());
    value
}

/// Configure env for a Command so it can find typescript.
///
/// Sets NODE_PATH to:
///   1. Existing NODE_PATH env var (if set).
///   2. NODE_PATH_FOR_TS cache (if we've discovered a global typescript).
///   3. Both, joined by path separator, if both present.
async fn configure_ts_env(cmd: &mut Command) {
    let existing = std::env::var("NODE_PATH").ok();
    let cached = NODE_PATH_FOR_TS.lock().await.clone();
    let combined: Vec<String> = [existing, cached].into_iter().flatten().collect();
    if !combined.is_empty() {
        let joined = std::env::join_paths(combined.iter().map(|s| std::path::Path::new(s)))
            .ok()
            .map(|p| p.to_string_lossy().to_string());
        if let Some(j) = joined {
            cmd.env("NODE_PATH", j);
        }
    }
}

/// Check whether the typescript package is resolvable from the project_root.
///
/// Tries `require('typescript/package.json')` from the project directory.
/// If unavailable in the default search path, falls back to:
///   1. Global npm root via `npm root -g`, joined with any existing
///      `NODE_PATH` env var so user-configured resolution paths survive.
///   2. The `NODE_PATH` env var alone (if `npm root -g` is unavailable).
///
/// This matters when `project_root` is a tempdir: Node's upward
/// `node_modules` walk finds nothing from a tempdir, so global / NODE_PATH
/// fallback is the only way to resolve a globally-installed typescript.
///
/// Caches the discovered NODE_PATH so subsequent subprocess calls succeed.
pub async fn typescript_available(project_root: &str) -> bool {
    let mut guard = TS_AVAILABLE.lock().await;
    if let Some(v) = *guard {
        return v;
    }

    // The check just tries to resolve the typescript package.json. Doesn't
    // depend on TS API surface (which changed dramatically between 5.x and 7.x).
    let script = r#"try {
    const pkg = require('typescript/package.json');
    process.stdout.write(JSON.stringify({ available: true, version: pkg.version }));
} catch (e) {
    process.stdout.write(JSON.stringify({ available: false, error: e.message }));
}
"#;

    let run_check = |node_path: Option<String>| async move {
        let mut cmd = crate::scanner::command_hidden_tokio("node");
        cmd.arg("-e")
            .arg(script)
            .current_dir(project_root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(np) = node_path {
            cmd.env("NODE_PATH", np);
        }
        let result = cmd.output().await;
        match result {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                #[derive(Deserialize)]
                struct Out {
                    available: bool,
                }
                serde_json::from_str::<Out>(stdout.trim())
                    .map(|o| o.available)
                    .unwrap_or(false)
            }
            _ => false,
        }
    };

    // Try 1: default env (inherits any NODE_PATH from the parent process).
    let mut available = run_check(None).await;

    // Try 2: NODE_PATH = global npm root + existing NODE_PATH (joined).
    // Joining (rather than overwriting) preserves user-configured resolution
    // paths — e.g. when NODE_PATH points at a project-local node_modules that
    // holds @types/* declarations tsc will need later. We test against the
    // combined value so a typescript reachable via EITHER path is found, but
    // cache only the newly-discovered global root: `configure_ts_env` re-reads
    // the env var at use time and joins it with the cache, so storing just the
    // new root keeps the cache minimal and avoids path duplication downstream.
    if !available {
        let existing_np = std::env::var("NODE_PATH").ok().filter(|s| !s.is_empty());
        if let Some(global_root) = npm_global_root().await {
            let combined = join_node_paths(
                std::iter::once(global_root.as_str())
                    .chain(existing_np.as_deref()),
            );
            available = run_check(Some(combined)).await;
            if available {
                let mut np_guard = NODE_PATH_FOR_TS.lock().await;
                *np_guard = Some(global_root);
            }
        } else if let Some(existing) = existing_np {
            // npm not available (e.g. minimal container) but user has NODE_PATH.
            // Try 1 already inherited it, but be defensive: some Command
            // configurations strip env, and an explicit set is cheap.
            available = run_check(Some(existing)).await;
        }
    }

    *guard = Some(available);
    available
}

/// Join multiple paths into a single NODE_PATH value using the platform's
/// path list separator (`;` on Windows, `:` elsewhere). Empty inputs are
/// skipped. Returns the joined string, or empty string if all inputs empty.
fn join_node_paths<'a, I>(paths: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let parts: Vec<&str> = paths.into_iter().filter(|s| !s.is_empty()).collect();
    parts.join(if cfg!(target_os = "windows") { ";" } else { ":" })
}

/// Reset availability cache. For tests that need to re-check.
pub async fn reset_availability_cache() {
    TS_AVAILABLE.lock().await.take();
    NODE_PATH_FOR_TS.lock().await.take();
}

/// Node.js wrapper script: reads source from stdin, writes to temp file,
/// resolves the platform's `tsc` binary, invokes it as a child process,
/// parses stderr for TS2339 lines, outputs JSON.
const TSC_WRAPPER_SCRIPT: &str = r#"
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

let tsPkg;
let tsRoot;
try {
    tsPkg = require('typescript/package.json');
    tsRoot = path.dirname(require.resolve('typescript/package.json'));
} catch (e) {
    process.stdout.write(JSON.stringify({ error: 'typescript-not-available', diagnostics: [] }));
    process.exit(0);
}

// Find the native tsc binary path. TS 7.x ships a native binary at
// node_modules/@typescript/typescript-<plat>-<arch>/lib/tsc[.exe].
// TS 5.x has lib/tsc.js (invoked via `node tsc.js`).
function findTscInvocation() {
    const platArchPkg = `@typescript/typescript-${process.platform}-${process.arch}`;
    const tryPaths = [
        path.join(tsRoot, 'node_modules', platArchPkg, 'lib', 'tsc'),
        path.join(tsRoot, '..', platArchPkg, 'lib', 'tsc'),
    ];
    for (const base of tryPaths) {
        const candidates = process.platform === 'win32'
            ? [base + '.exe', base]
            : [base];
        for (const c of candidates) {
            if (fs.existsSync(c)) {
                return { cmd: c, args: [] };
            }
        }
    }
    // Fallback: TS 5.x — invoke lib/tsc.js via node.
    const tscJs = path.join(tsRoot, 'lib', 'tsc.js');
    if (fs.existsSync(tscJs)) {
        return { cmd: process.execPath, args: [tscJs] };
    }
    return null;
}

const tsc = findTscInvocation();
if (!tsc) {
    process.stdout.write(JSON.stringify({ error: 'tsc-binary-not-found', diagnostics: [] }));
    process.exit(0);
}

// Source handoff: prefer explicit file path in argv (race-free). Fall back
// to reading fd 0 (stdin) only when no argument was passed — the stdin path
// races on Windows: the parent's async write_all + drop can close the pipe
// before node's readFileSync(0) executes, yielding an EMPTY source file and
// silently returning zero diagnostics (observed as intermittent TS_GATE
// diags=0 for code that provably errors).
//
// NOTE argv layout under `node -e <script> <file>`: process.argv =
// [execPath, <file>] — the -e script text is NOT in argv. So the file path
// is argv[1], not argv[2].
const source = process.argv.length > 2
    ? fs.readFileSync(process.argv[2], 'utf8')
    : (process.argv.length > 1 && fs.existsSync(process.argv[1])
        ? fs.readFileSync(process.argv[1], 'utf8')
        : fs.readFileSync(0, 'utf8'));
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anubis-ts-'));
const tmpFile = path.join(tmpDir, 'anubis_check.ts');
fs.writeFileSync(tmpFile, source);

try {
    // Note: --module esnext + --moduleResolution bundler works in both
    // TS 5.x and TS 7.x. Other combinations (commonjs+node, commonjs+bundler)
    // fail in one version or the other.
    const args = [
        ...tsc.args,
        '--noEmit',
        '--skipLibCheck',
        '--target', 'ES2020',
        '--module', 'esnext',
        '--moduleResolution', 'bundler',
        '--strict', 'false',
        '--noImplicitAny', 'false',
        '--strictNullChecks', 'false',
        '--noImplicitThis', 'false',
        '--allowJs',
        '--esModuleInterop',
        tmpFile,
    ];
    let capturedStderr = '';
    let capturedStdout = '';
    try {
        capturedStdout = execFileSync(tsc.cmd, args, {
            stdio: ['ignore', 'pipe', 'pipe'],
            encoding: 'utf8',
            maxBuffer: 10 * 1024 * 1024,
        });
    } catch (e) {
        // tsc exits non-zero when there are errors — that's expected.
        capturedStderr = (e.stderr || '') + '';
        capturedStdout = (e.stdout || '') + '';
    }

    // TS 7.x native binary writes diagnostics to stdout; TS 5.x writes to
    // stderr. Parse both for the error codes we care about.
    //
    // Codes captured:
    //   TS2339 — Property 'X' does not exist on type 'Y'. (method/prop hallucination)
    //   TS2552 — Cannot find name 'X'. Did you mean 'Y'? (typo of in-scope name)
    //   TS2304 — Cannot find name 'X'. (genuinely undefined identifier)
    //
    // Deliberately NOT captured:
    //   TS2307 — Cannot find module 'pkg'. This is a missing-dependency issue
    //            (npm install not run, @types/X absent) — not a hallucination.
    //            Including it would FP on every project without installed types.
    //
    // Format: "file.ts(L,C): error TS2339: Property 'X' does not exist on type 'Y'."
    // Normalize CRLF → LF so the `.` in the regex (which does not match `\r`
    // in JavaScript) can reach the message before the line-ending lookahead.
    const allOutput = (capturedStderr + '\n' + capturedStdout).replace(/\r\n/g, '\n');
    const diagnostics = [];
    const lineRe = /(?:^|\n)([^(]+)\((\d+),(\d+)\):\s*error\s+TS(2339|2552|2304|2554):\s*(.+?)(?=\n|$)/g;
    let m;
    while ((m = lineRe.exec(allOutput)) !== null) {
        diagnostics.push({
            code: parseInt(m[4], 10),
            message: m[5].trim(),
            line: parseInt(m[2], 10),
            column: parseInt(m[3], 10),
            fileName: m[1].trim(),
        });
    }
    process.stdout.write(JSON.stringify({ error: null, diagnostics }));
} finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
}
"#;

/// Verify TypeScript source for method hallucinations via TS2339 diagnostics.
///
/// Returns empty Vec if:
///   - typescript package not available
///   - source doesn't parse
///   - subprocess times out (10s — native tsc can be slow first run)
///   - no TS2339 diagnostics
pub async fn verify_ts_methods_via_compiler(
    source: &str,
    project_root: &str,
) -> Vec<TsDiagnostic> {
    let avail = typescript_available(project_root).await;
    if !avail {
        return Vec::new();
    }

    // Race-free source handoff: write to a temp file and pass its path as
    // argv. The old stdin-pipe path raced on Windows (parent drops the pipe
    // handle before node's readFileSync(0) runs → empty source → 0 diags).
    let src_dir = std::env::temp_dir().join(format!(
        "anubis-ts-src-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if std::fs::create_dir_all(&src_dir).is_err() {
        return Vec::new();
    }
    let src_file = src_dir.join("source.ts");
    if std::fs::write(&src_file, source.as_bytes()).is_err() {
        let _ = std::fs::remove_dir_all(&src_dir);
        return Vec::new();
    }

    let mut child = crate::scanner::command_hidden_tokio("node");
    child
        .arg("-e")
        .arg(TSC_WRAPPER_SCRIPT)
        .arg(&src_file)
        .current_dir(project_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_ts_env(&mut child).await;

    let mut child = match child.spawn() {
        Ok(c) => c,
        Err(_) => {
            let _ = std::fs::remove_dir_all(&src_dir);
            return Vec::new();
        }
    };

    let output = match tokio::time::timeout(Duration::from_secs(15), child.wait_with_output()).await {
        Ok(Ok(o)) if o.status.success() => o,
        _ => {
            let _ = std::fs::remove_dir_all(&src_dir);
            return Vec::new();
        }
    };
    let _ = std::fs::remove_dir_all(&src_dir);

    let stdout = String::from_utf8_lossy(&output.stdout);
    #[derive(Deserialize)]
    struct Out {
        #[serde(default)]
        diagnostics: Vec<TsDiagnostic>,
        #[serde(default)]
        error: Option<String>,
    }
    match serde_json::from_str::<Out>(stdout.trim()) {
        Ok(parsed) => {
            if let Some(err) = parsed.error {
            }
            parsed.diagnostics
        }
        Err(_) => Vec::new(),
    }
}

/// Format a TS2339 diagnostic as a forge warning string.
///
/// Format matches other forge warnings:
///   `hallucinated-method: TS2339 — Property 'X' does not exist on type 'Y'.`
pub fn format_warning(diag: &TsDiagnostic) -> String {
    format!("hallucinated-method: TS2339 — {}", diag.message)
}

/// Extract the hallucinated symbol from a TS diagnostic message.
///
/// TS2339: `Property 'X' does not exist on type 'Y'.` → [`X`, `Y`].
///   Both X (method) and Y (receiver type) are kept — FORGE may flag either.
/// TS2552: `Cannot find name 'X'. Did you mean 'Y'?` → [`X`] ONLY.
///   Y is the SUGGESTED correction, not the hallucination. Including Y
///   would let the golden completion (which uses Y) match the gate and
///   suppress the warning — the opposite of what we want.
/// TS2304: `Cannot find name 'X'.` → [`X`].
fn extract_diag_symbols(diag: &TsDiagnostic, code: &str) -> Vec<String> {
    let parts: Vec<&str> = diag.message.split('\'').collect();
    let mut quoted: Vec<String> = Vec::new();
    let mut i = 1;
    while i < parts.len() {
        if !parts[i].is_empty() {
            quoted.push(parts[i].to_string());
        }
        i += 2;
    }
    match diag.code {
        // TS2552: keep only the first quoted name (the typo). The second
        // quoted name is the suggested correction, which the golden
        // completion uses — including it would let the golden scan match
        // the gate and zero out the difference.
        2552 => quoted.into_iter().take(1).collect(),
        // TS2554: "Expected N-M arguments, but got K." — arity hallucination
        // on a REAL method. No quoted names in the message, so recover the
        // callee from the source line at the reported position.
        2554 => {
            // TS2554 carries no quoted names — recover the callee from the
            // offending source line. The gate caller threads the code in.
            let line_text = source_line(code, diag.line);
            extract_callee_at_position(&line_text, diag.column as usize).into_iter().collect()
        }
        // TS2339 and TS2304: keep all quoted names.
        _ => quoted,
    }
}

/// 1-based line fetch from source text (empty string when out of range).
fn source_line(code: &str, line_no: u32) -> String {
    if line_no == 0 {
        return String::new();
    }
    code.lines()
        .nth((line_no - 1) as usize)
        .unwrap_or("")
        .to_string()
}

/// Recover the callee name for a TS2554 arity diagnostic. tsc points the
/// column at the START of the callee identifier ("xs.red|uce()"), so walk
/// FORWARD over identifier chars; fall back to a backward walk if the
/// column lands on a non-identifier (paren-adjacent, other tsc shapes).
fn extract_callee_at_position(line_text: &str, col: usize) -> Option<String> {
    let bytes = line_text.as_bytes();
    if col == 0 || bytes.is_empty() {
        return None;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';

    let mut start = col - 1; // 0-based
    if start >= bytes.len() {
        return None;
    }

    // Forward walk: column at callee start.
    if is_ident(bytes[start]) {
        let mut end = start;
        while end < bytes.len() && is_ident(bytes[end]) {
            end += 1;
        }
        // Confirm a call shape follows (optional spaces + '('), otherwise
        // this is a random identifier, not the callee.
        let rest = &line_text[end..];
        let rest = rest.trim_start();
        if rest.starts_with('(') {
            let seg = &line_text[start..end];
            let tail = seg.rsplit('.').next().unwrap_or(seg);
            return Some(tail.to_string());
        }
        return None;
    }

    // Backward walk fallback: column at/after the callee (paren shape).
    if start > 0 {
        start -= 1;
    }
    if !is_ident(bytes[start]) {
        return None;
    }
    let mut begin = start;
    while begin > 0 && is_ident(bytes[begin - 1]) {
        begin -= 1;
    }
    let seg = &line_text[begin..=start];
    let tail = seg.rsplit('.').next().unwrap_or(seg).trim();
    if tail.len() >= 2 {
        Some(tail.to_string())
    } else {
        None
    }
}

/// TypeScript negative compiler FP gate (mirror of `csharp_compiler_gate`).
///
/// Runs the TypeScript compiler via `verify_ts_methods_via_compiler`
/// and returns `Some(set)` where the set = symbols flagged by BOTH FORGE
/// AND tsc. FORGE warnings whose symbols are NOT in the set are false
/// positives → suppress them in the wiring.
///
/// Returns `None` when typescript is unavailable or gate is skipped
/// (`DELULU_FORGE_ONLY=1`) → don't suppress (conservative).
///
/// Captures:
///   - TS2339 — Property 'X' does not exist on type 'Y' (method/prop).
///   - TS2552 — Cannot find name 'X'. Did you mean 'Y'? (typo of in-scope).
///   - TS2304 — Cannot find name 'X'. (genuinely undefined).
///
/// Symbol extraction handles two FORGE warning formats via the shared
/// `extract_warning_symbols` helper:
///   - Backtick-quoted: `hallucinated-method: `foo.bar` — ...`
///   - Non-backtick: `cached-hallucination: ApiErrorSchema.safeParse() —`
///     / `scope-hallucination: Router.get() — ...`
///
/// When `forge_warnings` is empty (PRIMARY mode), ALL unresolved tsc
/// symbols are returned as new hallucination warnings. This catches
/// TS hallucinations that FORGE's regex/AST pipeline misses entirely.
pub async fn ts_compiler_gate(
    code: &str,
    forge_warnings: &[String],
    project_root: &str,
) -> Option<HashSet<String>> {
    // Skip in FORGE_ONLY mode (offline benchmark tests).
    if std::env::var("DELULU_FORGE_ONLY").is_ok() {
        return None;
    }

    if !typescript_available(project_root).await {
        return None;
    }

    let forge_symbols: HashSet<String> = forge_warnings
        .iter()
        .flat_map(|w| crate::scanner::compiler_verifier::extract_warning_symbols(w))
        .collect();
    let run_as_primary = forge_symbols.is_empty();

    let diagnostics = verify_ts_methods_via_compiler(code, project_root).await;

    // Flakiness guard: the wrapper subprocess is invoked twice per scan
    // (forge Step 7 + this gate). If THIS invocation returned zero
    // diagnostics while forge Step 7 already emitted TS2339 catches
    // (warnings containing "TS2339"), the second run flaked (timeout /
    // cold tsc under load). Returning None skips suppression entirely —
    // never let one flaky wrapper run nuke confirmed Step-7 catches.
    let forge_has_ts2339 = forge_warnings
        .iter()
        .any(|w| w.contains("TS2339"));
    if diagnostics.is_empty() && forge_has_ts2339 && !run_as_primary {
        tracing::warn!(
            target: "compiler_gate",
            "TS gate wrapper flaked (0 diags) but forge Step 7 has TS2339 catches — skipping suppression"
        );
        return None;
    }

    // Extract lowercased symbols from each diagnostic. TS2339 yields the
    // property name (X) and receiver type (Y). TS2552/TS2304 yield only the
    // undefined name (the suggested correction is intentionally excluded —
    // see `extract_diag_symbols`).
    let mut unresolved: HashSet<String> = HashSet::new();
    for diag in &diagnostics {
        for sym in extract_diag_symbols(diag, code) {
            unresolved.insert(sym.to_lowercase());
        }
    }

    // Both modes return the full tsc-confirmed set (same rationale as the
    // Go gate): suppression semantics at the caller are unchanged, and the
    // caller surfaces compiler-confirmed symbols FORGE never flagged (e.g.
    // TS2554 arity errors) instead of silently burying them when an
    // unrelated FORGE warning flips the gate into suppression mode.
    let genuine: HashSet<String> = unresolved.clone();

    tracing::info!(
        target: "compiler_gate",
        forge = forge_symbols.len(),
        unresolved_by_tsc = unresolved.len(),
        genuine = genuine.len(),
        "TS compiler gate: {} of {} FORGE warnings are genuine",
        genuine.len(),
        forge_symbols.len()
    );

    Some(genuine)
}

/// Clear availability cache. Tests should call between runs that may change
/// NODE_PATH or install/remove typescript.
pub async fn clear_cache() {
    TS_AVAILABLE.lock().await.take();
    NODE_PATH_FOR_TS.lock().await.take();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: is typescript available in the test environment?
    async fn ts_here() -> bool {
        typescript_available(".").await
    }

    /// TS2339 detection: response.parseBody() fires (Response has no parseBody).
    /// This is the DELULU sample typescript-method-ee593f0c04c3 pattern.
    #[tokio::test]
    async fn catches_parsebody_on_response() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        let src = r#"
async function f() {
    const response = await fetch("http://example.com");
    const data = await response.parseBody();
    return data;
}
"#;
        let diags = verify_ts_methods_via_compiler(src, ".").await;
        assert!(
            diags.iter().any(|d| d.message.contains("parseBody") && d.message.contains("Response")),
            "expected parseBody TS2339; got: {:?}",
            diags
        );
    }

    /// TS2339 negative: response.json() does NOT fire (Response has json).
    /// This is the GOLDEN completion for the same DELULU sample.
    /// Critical: must not produce false positives on valid code.
    #[tokio::test]
    async fn passes_real_response_json() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        let src = r#"
async function f() {
    const response = await fetch("http://example.com");
    const data = await response.json();
    return data;
}
"#;
        let diags = verify_ts_methods_via_compiler(src, ".").await;
        assert!(
            !diags.iter().any(|d| d.code == 2339),
            "expected NO TS2339 on response.json; got: {:?}",
            diags
        );
    }

    /// TS2339 detection: hallucinated method on a class instance.
    /// Uses inline class so test doesn't depend on installed packages.
    #[tokio::test]
    async fn catches_hallucinated_method_on_typed_class() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        let src = r#"
class Foo {
    bar(): Foo { return this; }
    baz(): void {}
}
const f = new Foo();
f.bar().baz();    // valid
f.bar().wrong(); // hallucinated
"#;
        let diags = verify_ts_methods_via_compiler(src, ".").await;
        assert!(
            diags.iter().any(|d| d.message.contains("'wrong'") && d.message.contains("Foo")),
            "expected TS2339 for Foo.wrong; got: {:?}",
            diags
        );
    }

    /// TS2339 doesn't fire on `any`-typed receivers (limitation).
    /// `bulk.locate()` from DELULU sample — bulk is `any` without mongodb
    /// types installed → no TS2339. This is a documented limitation, not a
    /// bug. Test confirms we don't emit false positives in this case.
    #[tokio::test]
    async fn no_false_positive_on_any_typed_receiver() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        let src = r#"
function f(bulk: any) {
    bulk.locate({}).upsert().update({});
    bulk.find({}).upsert().update({});
}
"#;
        let diags = verify_ts_methods_via_compiler(src, ".").await;
        assert!(
            diags.iter().all(|d| d.code != 2339 || !d.message.contains("locate")),
            "should NOT fire on any.locate; got: {:?}",
            diags
        );
    }

    /// Empty source: no diagnostics, no crash.
    #[tokio::test]
    async fn empty_source_returns_empty() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        let diags = verify_ts_methods_via_compiler("", ".").await;
        assert!(diags.is_empty(), "got: {:?}", diags);
    }

    /// Syntax error: returns empty (no crash, no TS2339 false positives).
    #[tokio::test]
    async fn syntax_error_returns_empty() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        let diags = verify_ts_methods_via_compiler("function {{{{", ".").await;
        assert!(diags.is_empty(), "syntax errors should not produce TS2339; got: {:?}", diags);
    }

    /// Format warning produces forge-pipeline-compatible string.
    #[test]
    fn format_warning_includes_code_and_message() {
        let d = TsDiagnostic {
            code: 2339,
            message: "Property 'parseBody' does not exist on type 'Response'.".to_string(),
            line: 2,
            column: 30,
        };
        let s = format_warning(&d);
        assert!(s.starts_with("hallucinated-method: TS2339 — "));
        assert!(s.contains("parseBody"));
        assert!(s.contains("Response"));
    }

    /// typescript_available returns false on bogus project_root (no crash).
    /// Note: may return true if NODE_PATH is set globally — test is best-effort.
    #[tokio::test]
    async fn typescript_available_does_not_crash_on_missing_dir() {
        clear_cache().await;
        let tmp = std::env::temp_dir().join("anubis_ts_availability_test_xyz_12345");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = typescript_available(tmp.to_str().unwrap()).await;
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Regression: typescript_available must resolve TS from a tempdir via
    /// global npm root or NODE_PATH. Node's upward node_modules walk finds
    /// nothing from a tempdir; the function must fall back to global npm /
    /// NODE_PATH rather than report `false` unconditionally.
    ///
    /// Skips when typescript truly isn't available (CI without global TS).
    #[tokio::test]
    async fn typescript_available_resolves_from_tempdir() {
        clear_cache().await;
        let tmp = std::env::temp_dir().join("anubis_ts_availability_tempdir_probe_98765");
        let _ = std::fs::create_dir_all(&tmp);
        let probe = typescript_available(tmp.to_str().unwrap()).await;
        let _ = std::fs::remove_dir_all(&tmp);

        // Sanity probe: ensure TS is installed somewhere we can reach.
        let ts_installed = npm_global_root()
            .await
            .map(|root| std::path::Path::new(&root).join("typescript").join("package.json").exists())
            .unwrap_or(false)
            || std::env::var("NODE_PATH").map(|s| !s.is_empty()).unwrap_or(false);
        if !ts_installed {
            eprintln!("skipping: no global typescript and no NODE_PATH");
            return;
        }
        assert!(probe, "typescript_available should resolve TS from a tempdir via global npm / NODE_PATH");
    }

    /// TS2552 detection: typo of an in-scope name fires "Cannot find name
    /// 'X'. Did you mean 'Y'?" — the dominant DELULU v2 TS hallucination
    /// pattern (~280 of 300 samples). Pre-fix this gate returned 0% recall
    /// because the wrapper only captured TS2339.
    #[tokio::test]
    async fn catches_ts2552_typo_of_in_scope_name() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        // `console` is a lib global. `consloe` is a typo → TS2552 with
        // "Did you mean 'console'?" suggestion.
        let src = "consloe.log(\"hi\");\n";
        let diags = verify_ts_methods_via_compiler(src, ".").await;
        assert!(
            diags.iter().any(|d| d.code == 2552 && d.message.contains("consloe")),
            "expected TS2552 for `consloe`; got: {:?}",
            diags
        );
    }

    /// TS2304 detection: invented name with no close match → "Cannot find
    /// name 'X'." (no suggestion). Distinct from TS2552 which has a suggestion.
    #[tokio::test]
    async fn catches_ts2304_invented_name() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        // An obviously invented name with no close match in scope.
        let src = "xyzzyFakeInventedIdentifier123();\n";
        let diags = verify_ts_methods_via_compiler(src, ".").await;
        assert!(
            diags.iter().any(|d| (d.code == 2304 || d.code == 2552) && d.message.contains("xyzzyFakeInventedIdentifier123")),
            "expected TS2304/TS2552 for invented name; got: {:?}",
            diags
        );
    }

    /// extract_diag_symbols returns the typo only for TS2552 (NOT the
    /// "Did you mean" suggestion). Including the suggestion would let the
    /// golden completion match the gate and zero out the difference signal.
    #[test]
    fn extract_diag_symbols_ts2552_drops_suggestion() {
        let typo = TsDiagnostic {
            code: 2552,
            message: "Cannot find name 'isVlidApiRequest'. Did you mean 'isValidApiRequest'?".to_string(),
            line: 4,
            column: 1,
        };
        let syms = extract_diag_symbols(&typo, "");
        assert_eq!(syms, vec!["isVlidApiRequest".to_string()]);
    }

    /// extract_diag_symbols returns BOTH names for TS2339 — the property
    /// name AND the receiver type. FORGE may flag either side.
    #[test]
    fn extract_diag_symbols_ts2339_keeps_both() {
        let d = TsDiagnostic {
            code: 2339,
            message: "Property 'parseBody' does not exist on type 'Response'.".to_string(),
            line: 2,
            column: 30,
        };
        let syms = extract_diag_symbols(&d, "");
        assert_eq!(syms, vec!["parseBody".to_string(), "Response".to_string()]);
    }

    /// ts_compiler_gate PRIMARY mode: empty FORGE warnings + hallucinated
    /// code → returns Some(non-empty set). This is the configuration used
    /// in the production scanner wiring (compiler-detected: warnings).
    #[tokio::test]
    async fn ts_compiler_gate_primary_mode_detects_typo() {
        clear_cache().await;
        if !ts_here().await {
            eprintln!("skipping: typescript not available");
            return;
        }
        // DELULU_FORGE_ONLY short-circuits the gate. Test must clear it
        // to exercise the production path. Restore on exit so other tests
        // running in the same process aren't affected.
        let prior = std::env::var_os("DELULU_FORGE_ONLY");
        std::env::remove_var("DELULU_FORGE_ONLY");

        let code = "consloe.log(\"hi\");\n";
        let genuine = ts_compiler_gate(code, &[], ".").await;

        if let Some(v) = prior {
            std::env::set_var("DELULU_FORGE_ONLY", v);
        }

        assert!(
            genuine.is_some(),
            "expected Some(set) when typescript available, got None"
        );
        let genuine = genuine.unwrap();
        assert!(
            genuine.contains("consloe"),
            "expected `consloe` in genuine set; got: {:?}",
            genuine
        );
    }
}
